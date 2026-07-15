"""Tool-sequence baseline (R11) tests — per-agent transition anomaly.

Unit tests cover the pure Markov-transition model. Integration tests seed an
agent's ordered tool history directly, then drive the detector:
- an agent that has always chained read→summarize suddenly does read→http_post
  (a sensitive sink) → one high-severity R11 alert;
- a rare-but-benign new transition → medium severity;
- an agent still in its learning window (too few transitions) → never flagged;
- a repeat of a transition the agent makes all the time → not flagged.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.db.session import AsyncSessionLocal
from app.detection.sequence import (
    build_transition_model,
    detect_sequence_anomaly,
    is_sensitive_sink,
    total_transitions,
    transition_probability,
)
from app.models import MCPEvent


def test_build_transition_model():
    model = build_transition_model(["a", "b", "a", "b", "a", "c"])
    assert model["a"] == {"b": 2, "c": 1}
    assert model["b"] == {"a": 2}
    assert total_transitions(model) == 5


def test_transition_probability():
    model = build_transition_model(["a", "b", "a", "b", "a", "c"])
    assert transition_probability(model, "a", "b") == pytest.approx(2 / 3)
    assert transition_probability(model, "a", "c") == pytest.approx(1 / 3)
    # Unseen source or edge -> 0.0.
    assert transition_probability(model, "a", "z") == 0.0
    assert transition_probability(model, "z", "a") == 0.0


def test_is_sensitive_sink():
    assert is_sensitive_sink("http_post")
    assert is_sensitive_sink("send_email")
    assert is_sensitive_sink("exec_shell")
    assert not is_sensitive_sink("read_file")
    assert not is_sensitive_sink(None)


async def _seed_sequence(agent_id: str, tools: list[str], *, now: datetime):
    """Insert one ordered tool history for an agent, strictly increasing in time.

    The final tool lands at now-1s so a subsequent live /inspect event (at ~now)
    orders after it. Seed the whole intended sequence in a single call — two
    calls would produce overlapping timestamps and an ambiguous last transition.
    """
    async with AsyncSessionLocal() as db:
        for i, tool in enumerate(tools):
            ts = now - timedelta(seconds=(len(tools) - i))
            db.add(MCPEvent(agent_id=agent_id, method="tools/call", tool_name=tool,
                            direction="request", payload={}, created_at=ts))
        await db.commit()


@pytest.mark.asyncio
async def test_exfil_sequence_raises_high_r11():
    agent = "seq-exfil-agent"
    now = datetime.now(timezone.utc)
    # Learned normal: always read_file -> summarize, then the anomalous
    # read_file -> http_post (sink) as the final transition. Seed as one sequence.
    seq = ["read_file", "summarize"] * 12 + ["read_file", "http_post"]
    await _seed_sequence(agent, seq, now=now)

    async with AsyncSessionLocal() as db:
        findings = await detect_sequence_anomaly(db, agent_id=agent, now=now)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "R11"
    assert f.severity == "high"  # destination is a sensitive sink
    assert f.evidence["from_tool"] == "read_file"
    assert f.evidence["to_tool"] == "http_post"
    assert f.evidence["sensitive_sink"] is True


@pytest.mark.asyncio
async def test_rare_benign_transition_medium():
    agent = "seq-benign-agent"
    now = datetime.now(timezone.utc)
    # Learned list_files -> read_file, then a new benign destination (not a sink).
    seq = ["list_files", "read_file"] * 12 + ["list_files", "count_lines"]
    await _seed_sequence(agent, seq, now=now)

    async with AsyncSessionLocal() as db:
        findings = await detect_sequence_anomaly(db, agent_id=agent, now=now)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].evidence["sensitive_sink"] is False


@pytest.mark.asyncio
async def test_learning_window_not_flagged():
    agent = "seq-new-agent"
    now = datetime.now(timezone.utc)
    # Only a handful of transitions (< MIN_TRANSITIONS=20): still learning.
    await _seed_sequence(agent, ["a", "b", "a", "http_post"], now=now)
    async with AsyncSessionLocal() as db:
        findings = await detect_sequence_anomaly(db, agent_id=agent, now=now)
    assert findings == []


@pytest.mark.asyncio
async def test_common_transition_not_flagged():
    agent = "seq-steady-agent"
    now = datetime.now(timezone.utc)
    # Always read_file -> http_post: even a sink is normal for THIS agent.
    await _seed_sequence(agent, ["read_file", "http_post"] * 16, now=now)
    async with AsyncSessionLocal() as db:
        findings = await detect_sequence_anomaly(db, agent_id=agent, now=now)
    assert findings == []


@pytest.mark.asyncio
async def test_sequence_anomaly_end_to_end_via_inspect(client, auth_headers):
    """The inspect pipeline raises an R11 alert when an agent breaks its pattern."""
    agent = "seq-e2e-agent"
    now = datetime.now(timezone.utc)
    # Seed a strong read_file->summarize history ending in read_file, so the
    # live inspect below forms the read_file -> exfil_send transition.
    await _seed_sequence(agent, ["read_file", "summarize"] * 12 + ["read_file"], now=now)

    resp = await client.post(
        "/api/v1/inspect",
        json={"method": "tools/call", "tool_name": "exfil_send",
              "agent_id": agent, "payload": {"data": "hello"}},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    alerts = (await client.get("/api/v1/alerts", headers=auth_headers)).json()
    r11 = [a for a in alerts if a["rule_id"] == "R11"
           and a["evidence"].get("agent_id") == agent]
    assert len(r11) == 1
    assert r11[0]["evidence"]["to_tool"] == "exfil_send"
