"""Phase 2 feature tests: API keys, anomaly detection, webhook notifier.

Includes attack/defense simulations:
- A revoked API key must be rejected.
- An API key must NOT grant access to read/admin endpoints (scope containment).
- A probing agent that keeps sending blocked payloads triggers an R7 alert.
- The webhook SSRF guard rejects private/loopback and non-HTTPS destinations.
"""

from __future__ import annotations

import pytest

from app.services.notify import validate_webhook_url


@pytest.mark.asyncio
async def test_api_key_lifecycle_and_ingest_auth(client, auth_headers):
    # Admin creates a key; plaintext returned exactly once.
    resp = await client.post(
        "/api/v1/apikeys", json={"name": "gateway-1"}, headers=auth_headers
    )
    assert resp.status_code == 201, resp.text
    created = resp.json()
    key = created["key"]
    assert key.startswith("mcpg_")
    assert created["prefix"] == key[:11]

    # Listing never exposes the plaintext.
    resp = await client.get("/api/v1/apikeys", headers=auth_headers)
    assert resp.status_code == 200
    assert all("key" not in k for k in resp.json())

    # The key authenticates the ingest surface (no bearer token).
    resp = await client.post(
        "/api/v1/inspect",
        json={"method": "tools/call", "tool_name": "read_file",
              "agent_id": "agent-key-test", "payload": {"path": "notes.txt"}},
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["blocked"] is False

    # Scope containment: the key must NOT read events or manage users.
    resp = await client.get("/api/v1/events", headers={"X-API-Key": key})
    assert resp.status_code == 401
    resp = await client.get("/api/v1/apikeys", headers={"X-API-Key": key})
    assert resp.status_code == 401

    # Revocation: key stops working immediately.
    key_id = created["id"]
    resp = await client.post(f"/api/v1/apikeys/{key_id}/revoke", headers=auth_headers)
    assert resp.status_code == 200 and resp.json()["revoked"] is True
    resp = await client.post(
        "/api/v1/inspect",
        json={"method": "tools/call", "tool_name": "read_file", "payload": {}},
        headers={"X-API-Key": key},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_api_key_admin_only(client, auth_headers):
    # Create a non-admin analyst.
    resp = await client.post(
        "/api/v1/auth/users",
        json={"email": "analyst2@test.local", "password": "AnalystPass123!",
              "role": "analyst"},
        headers=auth_headers,
    )
    assert resp.status_code in (201, 409)
    resp = await client.post(
        "/api/v1/auth/login",
        data={"username": "analyst2@test.local", "password": "AnalystPass123!"},
    )
    analyst_headers = {"Authorization": f"Bearer {resp.json()['access_token']}"}

    resp = await client.post(
        "/api/v1/apikeys", json={"name": "nope"}, headers=analyst_headers
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_invalid_api_key_rejected(client):
    resp = await client.post(
        "/api/v1/inspect",
        json={"method": "tools/call", "payload": {}},
        headers={"X-API-Key": "mcpg_totally-fake-key"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_probing_agent_raises_anomaly_alert(client, auth_headers):
    """Attack simulation: agent repeatedly sends destructive payloads that get
    blocked -> R7 'repeated blocked attempts' anomaly alert must fire."""
    agent = "probing-agent-r7"
    for i in range(3):
        resp = await client.post(
            "/api/v1/inspect",
            json={
                "method": "tools/call",
                "tool_name": "exec",
                "agent_id": agent,
                "payload": {"cmd": f"rm -rf /data/{i}"},
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["blocked"] is True  # R4 critical -> backstop block

    # The third blocked message crosses BLOCKED_THRESHOLD; expect an R7 alert.
    resp = await client.get("/api/v1/alerts", headers=auth_headers)
    r7 = [a for a in resp.json()
          if a["rule_id"] == "R7" and a["evidence"].get("agent_id") == agent]
    assert len(r7) == 1, "expected exactly one deduplicated R7 alert"
    assert r7[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_anomaly_alerts_deduplicate(client, auth_headers):
    """A continued burst must not create a second open R7 alert in-window."""
    agent = "probing-agent-dedupe"
    for i in range(5):
        await client.post(
            "/api/v1/inspect",
            json={"method": "tools/call", "tool_name": "exec", "agent_id": agent,
                  "payload": {"cmd": "drop table users"}},
            headers=auth_headers,
        )
    resp = await client.get("/api/v1/alerts", headers=auth_headers)
    r7 = [a for a in resp.json()
          if a["rule_id"] == "R7" and a["evidence"].get("agent_id") == agent]
    assert len(r7) == 1


def test_webhook_ssrf_guard():
    # Non-HTTPS rejected by default.
    ok, reason = validate_webhook_url("http://hooks.example.com/x")
    assert not ok and "https" in reason
    # Loopback/private rejected even over HTTPS.
    ok, reason = validate_webhook_url("https://127.0.0.1/hook")
    assert not ok and "SSRF" in reason
    ok, reason = validate_webhook_url("https://localhost/hook")
    assert not ok
    # Unresolvable hosts fail closed.
    ok, _ = validate_webhook_url("https://definitely-not-a-real-host.invalid/x")
    assert not ok


@pytest.mark.asyncio
async def test_notify_simulation_mode(caplog):
    """With no webhook configured, high-severity alerts are logged (simulated)."""
    import logging
    from datetime import datetime, timezone

    from app.models import Alert, Severity
    from app.services.notify import notify_alerts

    alert = Alert(
        rule_id="R4", title="test critical", description="d",
        severity=Severity.critical, evidence={},
    )
    alert.created_at = datetime.now(timezone.utc)
    with caplog.at_level(logging.WARNING, logger="mcpguard.notify"):
        sent = await notify_alerts([alert])
    assert sent == 1
    assert any("ALERT-SIMULATION" in r.message for r in caplog.records)
