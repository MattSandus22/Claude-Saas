"""Policy bundle export/import + Rego export (Phase 17) tests.

Unit tests cover the pure YAML (de)serialization, validation errors, and Rego
generation. Integration tests cover export -> import round trip, that import
version-snapshots and never deletes, admin-only import, and the Rego endpoint.
"""

from __future__ import annotations

import pytest
import yaml

from app.services.policybundle import (
    parse_bundle,
    policies_to_bundle,
    policy_to_rego,
)


def test_bundle_roundtrip():
    pols = [{"name": "P1", "description": "d1", "enabled": True,
             "rules": {"default": "allow", "deny_tools": ["rm"]}},
            {"name": "P2", "description": "", "enabled": False, "rules": {}}]
    text = policies_to_bundle(pols)
    parsed = parse_bundle(text)
    assert [p["name"] for p in parsed] == ["P1", "P2"]
    assert parsed[0]["rules"]["deny_tools"] == ["rm"]
    assert parsed[1]["enabled"] is False


def test_parse_bundle_rejects_bad_shapes():
    with pytest.raises(ValueError):
        parse_bundle("just a string")
    with pytest.raises(ValueError):
        parse_bundle(yaml.safe_dump({"policies": "not a list"}))
    with pytest.raises(ValueError):
        parse_bundle(yaml.safe_dump({"policies": [{"description": "no name"}]}))
    with pytest.raises(ValueError):
        parse_bundle(yaml.safe_dump({"bundle_version": 99, "policies": []}))
    # Duplicate names are rejected.
    with pytest.raises(ValueError):
        parse_bundle(yaml.safe_dump({"policies": [{"name": "X"}, {"name": "X"}]}))


def test_rego_generation_covers_rule_families():
    rego = policy_to_rego("Guard Rail", {
        "default": "allow",
        "deny_tools": ["exec"],
        "deny_methods": ["tools/call"],
        "deny_agents": ["bad"],
        "max_threat_score": 65,
        "require_agent_id": True,
        "allow_tools": ["read_file"],
    })
    assert "package mcpguard.guard_rail" in rego
    assert "default allow := true" in rego
    assert 'input.tool_name in {"exec"}' in rego
    assert 'input.method in {"tools/call"}' in rego
    assert "input.threat_score >= 65" in rego
    assert "not input.agent_id" in rego
    assert 'not input.tool_name in {"read_file"}' in rego  # allowlist deny
    assert "allowed if {" in rego


def test_rego_default_deny():
    rego = policy_to_rego("Strict", {"default": "deny"})
    assert "default allow := false" in rego


@pytest.mark.asyncio
async def test_export_import_roundtrip_via_api(client, auth_headers):
    # Create a distinctive policy, export, then import into a fresh-name variant.
    await client.post(
        "/api/v1/policies",
        json={"name": "export-me", "description": "orig",
              "rules": {"default": "allow", "deny_tools": ["danger"]}},
        headers=auth_headers,
    )
    resp = await client.get("/api/v1/policies/export", headers=auth_headers)
    assert resp.status_code == 200
    bundle = resp.text
    assert "export-me" in bundle

    # Edit the bundle: rename one policy and tweak another, then import.
    doc = yaml.safe_load(bundle)
    doc["policies"].append({
        "name": "imported-new", "description": "added via import",
        "enabled": True, "rules": {"default": "deny"},
    })
    resp = await client.post("/api/v1/policies/import",
                             json={"bundle": yaml.safe_dump(doc)}, headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert "imported-new" in body["created"]
    assert "export-me" in body["updated"]

    # The new policy exists and enforcement sees it.
    policies = (await client.get("/api/v1/policies", headers=auth_headers)).json()
    assert any(p["name"] == "imported-new" for p in policies)


@pytest.mark.asyncio
async def test_import_snapshots_versions(client, auth_headers):
    await client.post(
        "/api/v1/policies",
        json={"name": "ver-import", "rules": {"default": "allow"}},
        headers=auth_headers,
    )
    pol = next(p for p in (await client.get("/api/v1/policies", headers=auth_headers)).json()
               if p["name"] == "ver-import")
    doc = {"policies": [{"name": "ver-import", "description": "changed",
                         "enabled": True, "rules": {"default": "deny"}}]}
    await client.post("/api/v1/policies/import",
                      json={"bundle": yaml.safe_dump(doc)}, headers=auth_headers)
    versions = (await client.get(f"/api/v1/policies/{pol['id']}/versions",
                                 headers=auth_headers)).json()
    # v1 (created) + v2 (imported update).
    assert any(v["change_note"] == "imported (update)" for v in versions)


@pytest.mark.asyncio
async def test_import_rejects_unknown_rule_keys(client, auth_headers):
    doc = {"policies": [{"name": "bad-rules", "rules": {"bogus_key": 1}}]}
    resp = await client.post("/api/v1/policies/import",
                             json={"bundle": yaml.safe_dump(doc)}, headers=auth_headers)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_import_is_admin_only(client, auth_headers):
    await client.post(
        "/api/v1/auth/users",
        json={"email": "analyst17@test.local", "password": "AnalystPass123!",
              "role": "analyst"},
        headers=auth_headers,
    )
    login = await client.post(
        "/api/v1/auth/login",
        data={"username": "analyst17@test.local", "password": "AnalystPass123!"},
    )
    analyst = {"Authorization": f"Bearer {login.json()['access_token']}"}
    doc = {"policies": [{"name": "x", "rules": {}}]}
    resp = await client.post("/api/v1/policies/import",
                             json={"bundle": yaml.safe_dump(doc)}, headers=analyst)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_rego_endpoint(client, auth_headers):
    resp = await client.post(
        "/api/v1/policies",
        json={"name": "rego-policy", "rules": {"default": "allow", "deny_tools": ["exec"]}},
        headers=auth_headers,
    )
    pid = resp.json()["id"]
    resp = await client.get(f"/api/v1/policies/{pid}/rego", headers=auth_headers)
    assert resp.status_code == 200
    assert "package mcpguard.rego_policy" in resp.text
    assert 'input.tool_name in {"exec"}' in resp.text
