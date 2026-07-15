"""Phase 5 tests: quarantine enforcement + policy versioning/rollback.

Attack/defense flow:
- A quarantined server's traffic is denied at /inspect even when the message is
  benign; releasing it (activate) restores traffic.
- Policy history is append-only; rollback restores old rules as a NEW version.
"""

from __future__ import annotations

import pytest


async def _register_server(client, headers, name: str) -> str:
    resp = await client.post(
        "/api/v1/servers",
        json={"name": name, "endpoint": f"stdio: {name}", "transport": "stdio",
              "source": "manual", "tools": []},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


@pytest.mark.asyncio
async def test_quarantined_server_traffic_denied(client, auth_headers):
    server_id = await _register_server(client, auth_headers, "q-server")

    benign = {"server_id": server_id, "method": "tools/call",
              "tool_name": "read_file", "agent_id": "agent-q",
              "payload": {"path": "notes.txt"}}

    # Benign traffic allowed while active.
    resp = await client.post("/api/v1/inspect", json=benign, headers=auth_headers)
    assert resp.json()["blocked"] is False

    # Quarantine the server -> same benign message is now denied.
    resp = await client.post(f"/api/v1/servers/{server_id}/quarantine",
                             headers=auth_headers)
    assert resp.status_code == 200 and resp.json()["status"] == "quarantined"

    resp = await client.post("/api/v1/inspect", json=benign, headers=auth_headers)
    body = resp.json()
    assert body["blocked"] is True
    assert any("quarantined" in r for r in body["reasons"])

    # Release from quarantine -> traffic restored.
    resp = await client.post(f"/api/v1/servers/{server_id}/activate",
                             headers=auth_headers)
    assert resp.status_code == 200 and resp.json()["status"] == "active"
    resp = await client.post("/api/v1/inspect", json=benign, headers=auth_headers)
    assert resp.json()["blocked"] is False


@pytest.mark.asyncio
async def test_activate_is_admin_only(client, auth_headers):
    server_id = await _register_server(client, auth_headers, "q-server-2")
    await client.post(
        "/api/v1/auth/users",
        json={"email": "analyst5@test.local", "password": "AnalystPass123!",
              "role": "analyst"},
        headers=auth_headers,
    )
    login = await client.post(
        "/api/v1/auth/login",
        data={"username": "analyst5@test.local", "password": "AnalystPass123!"},
    )
    analyst = {"Authorization": f"Bearer {login.json()['access_token']}"}
    resp = await client.post(f"/api/v1/servers/{server_id}/activate", headers=analyst)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_policy_versioning_and_rollback(client, auth_headers):
    # v1: create.
    resp = await client.post(
        "/api/v1/policies",
        json={"name": "versioned-policy", "description": "v1",
              "rules": {"default": "allow", "deny_tools": ["a"]}},
        headers=auth_headers,
    )
    assert resp.status_code == 201, resp.text
    pid = resp.json()["id"]

    # v2: update rules.
    resp = await client.put(
        f"/api/v1/policies/{pid}",
        json={"name": "versioned-policy", "description": "v2", "enabled": True,
              "rules": {"default": "allow", "deny_tools": ["a", "b"]}},
        headers=auth_headers,
    )
    assert resp.status_code == 200

    versions = (await client.get(f"/api/v1/policies/{pid}/versions",
                                 headers=auth_headers)).json()
    assert [v["version"] for v in versions] == [2, 1]
    assert versions[1]["change_note"] == "created"
    assert versions[0]["rules"]["deny_tools"] == ["a", "b"]

    # Rollback to v1 restores the old rules and appends v3.
    resp = await client.post(f"/api/v1/policies/{pid}/rollback/1",
                             headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["rules"]["deny_tools"] == ["a"]

    versions = (await client.get(f"/api/v1/policies/{pid}/versions",
                                 headers=auth_headers)).json()
    assert versions[0]["version"] == 3
    assert versions[0]["change_note"] == "rollback to v1"
    # History is append-only: v1 and v2 still present, untouched.
    assert {v["version"] for v in versions} == {1, 2, 3}


@pytest.mark.asyncio
async def test_rollback_unknown_version_404(client, auth_headers):
    resp = await client.post(
        "/api/v1/policies",
        json={"name": "rb-404", "rules": {"default": "allow"}},
        headers=auth_headers,
    )
    pid = resp.json()["id"]
    resp = await client.post(f"/api/v1/policies/{pid}/rollback/99",
                             headers=auth_headers)
    assert resp.status_code == 404
