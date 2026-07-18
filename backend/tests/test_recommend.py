"""Incident response recommendation (Phase 11) tests.

Unit tests cover the pure recommender: which subject each rule family implicates
and how severity drives urgency. Integration tests cover the endpoints,
including the guard that a case can only apply actions the recommender suggested
for *that* case (no using an incident as a lever against an unrelated subject).
"""

from __future__ import annotations

import pytest

from app.models import Incident, Severity
from app.services.recommend import recommend_actions


def _incident(**kw) -> Incident:
    base = dict(group_key="k", title="t", server_id=None, agent_id=None,
                severity=Severity.high, rule_ids=[])
    base.update(kw)
    return Incident(**base)


def test_agent_behavior_rules_recommend_contain():
    inc = _incident(agent_id="a1", rule_ids=["R7", "R11"], severity=Severity.high)
    actions = recommend_actions(inc)
    assert [a.action for a in actions] == ["contain_agent"]
    assert actions[0].target == "a1"
    assert set(actions[0].triggering_rules) == {"R7", "R11"}


def test_drift_recommends_quarantine_server():
    inc = _incident(server_id="s1", rule_ids=["R9"], severity=Severity.high)
    actions = recommend_actions(inc)
    assert [a.action for a in actions] == ["quarantine_server"]
    assert "rug-pull" in actions[0].reason


def test_correlation_recommends_quarantine_server():
    inc = _incident(server_id="s1", rule_ids=["R13"], severity=Severity.critical)
    actions = recommend_actions(inc)
    assert actions[0].action == "quarantine_server"
    assert actions[0].urgency == "urgent"
    assert "campaign" in actions[0].reason


def test_both_subjects_recommended_and_ordered_by_urgency():
    # Critical case with both an agent rule and a server rule -> both actions.
    inc = _incident(agent_id="a1", server_id="s1", rule_ids=["R11", "R13"],
                    severity=Severity.critical)
    actions = recommend_actions(inc)
    kinds = {a.action for a in actions}
    assert kinds == {"contain_agent", "quarantine_server"}
    # urgent actions come first
    assert actions[0].urgency == "urgent"


def test_low_severity_content_only_no_recommendation():
    # A low-severity case from content rules with no subject-specific rule and
    # not high+ -> nothing to recommend.
    inc = _incident(agent_id=None, server_id=None, rule_ids=["R2"],
                    severity=Severity.low)
    assert recommend_actions(inc) == []


@pytest.mark.asyncio
async def test_recommended_actions_endpoint(client, auth_headers):
    # Register a server and drive a destructive message so an incident forms.
    resp = await client.post(
        "/api/v1/servers",
        json={"name": "rec-srv", "endpoint": "stdio: rec-srv", "transport": "stdio",
              "source": "manual", "tools": []},
        headers=auth_headers,
    )
    server_id = resp.json()["id"]
    await client.post(
        "/api/v1/inspect",
        json={"server_id": server_id, "method": "tools/call", "tool_name": "exec",
              "agent_id": "rec-agent", "payload": {"cmd": "rm -rf /"}},
        headers=auth_headers,
    )
    incidents = (await client.get("/api/v1/incidents", headers=auth_headers)).json()
    inc = next(i for i in incidents if i["agent_id"] == "rec-agent")

    recs = (await client.get(f"/api/v1/incidents/{inc['id']}/recommended-actions",
                             headers=auth_headers)).json()
    actions = {r["action"] for r in recs}
    # Critical destructive activity on a known server+agent -> both suggested.
    assert "contain_agent" in actions
    assert "quarantine_server" in actions


@pytest.mark.asyncio
async def test_apply_action_contains_agent_and_is_enforced(client, auth_headers):
    resp = await client.post(
        "/api/v1/servers",
        json={"name": "apply-srv", "endpoint": "stdio: apply-srv",
              "transport": "stdio", "source": "manual", "tools": []},
        headers=auth_headers,
    )
    server_id = resp.json()["id"]
    await client.post(
        "/api/v1/inspect",
        json={"server_id": server_id, "method": "tools/call", "tool_name": "exec",
              "agent_id": "apply-agent", "payload": {"cmd": "rm -rf /"}},
        headers=auth_headers,
    )
    inc = next(i for i in (await client.get("/api/v1/incidents", headers=auth_headers)).json()
               if i["agent_id"] == "apply-agent")

    # Apply containment from the case.
    resp = await client.post(f"/api/v1/incidents/{inc['id']}/apply-action",
                             json={"action": "contain_agent"}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["applied"] == "contain_agent"

    # The agent is now on the blocklist and a benign message is denied.
    blocked = (await client.get("/api/v1/agents/blocked", headers=auth_headers)).json()
    assert "apply-agent" in blocked["blocked_agents"]
    resp = await client.post(
        "/api/v1/inspect",
        json={"method": "tools/call", "tool_name": "read_file",
              "agent_id": "apply-agent", "payload": {"path": "x"}},
        headers=auth_headers,
    )
    assert resp.json()["blocked"] is True


@pytest.mark.asyncio
async def test_apply_unrecommended_action_rejected(client, auth_headers):
    # An incident with only an agent (no server) must reject quarantine_server.
    await client.post(
        "/api/v1/inspect",
        json={"method": "tools/call", "tool_name": "exec",
              "agent_id": "lever-agent", "payload": {"cmd": "rm -rf /"}},
        headers=auth_headers,
    )
    inc = next(i for i in (await client.get("/api/v1/incidents", headers=auth_headers)).json()
               if i["agent_id"] == "lever-agent")
    resp = await client.post(f"/api/v1/incidents/{inc['id']}/apply-action",
                             json={"action": "quarantine_server"}, headers=auth_headers)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_apply_action_is_admin_only(client, auth_headers):
    await client.post(
        "/api/v1/inspect",
        json={"method": "tools/call", "tool_name": "exec",
              "agent_id": "rbac-agent", "payload": {"cmd": "rm -rf /"}},
        headers=auth_headers,
    )
    inc = next(i for i in (await client.get("/api/v1/incidents", headers=auth_headers)).json()
               if i["agent_id"] == "rbac-agent")
    # Create an analyst.
    await client.post(
        "/api/v1/auth/users",
        json={"email": "analyst11@test.local", "password": "AnalystPass123!",
              "role": "analyst"},
        headers=auth_headers,
    )
    login = await client.post(
        "/api/v1/auth/login",
        data={"username": "analyst11@test.local", "password": "AnalystPass123!"},
    )
    analyst = {"Authorization": f"Bearer {login.json()['access_token']}"}
    resp = await client.post(f"/api/v1/incidents/{inc['id']}/apply-action",
                             json={"action": "contain_agent"}, headers=analyst)
    assert resp.status_code == 403
