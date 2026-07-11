"""Unit tests for the policy engine and payload sanitizer."""

from __future__ import annotations

import pytest

from app.core.sanitize import PayloadTooComplex, sanitize
from app.services.policy import evaluate_policies


# ---- Policy engine ----
def test_no_policies_defaults_allow():
    d = evaluate_policies([], method="tools/call", tool_name="x", agent_id="a", threat_score=0)
    assert d.allowed is True


def test_deny_tool_overrides_allow():
    policies = [
        {"name": "p1", "rules": {"default": "allow"}},
        {"name": "p2", "rules": {"deny_tools": ["exec_shell"]}},
    ]
    d = evaluate_policies(
        policies, method="tools/call", tool_name="exec_shell", agent_id="a", threat_score=0
    )
    assert d.allowed is False
    assert any("exec_shell" in r for r in d.reasons)


def test_max_threat_score_blocks():
    policies = [{"name": "p", "rules": {"max_threat_score": 70}}]
    d = evaluate_policies(
        policies, method="tools/call", tool_name="x", agent_id="a", threat_score=85
    )
    assert d.allowed is False


def test_allowlist_blocks_unlisted_tool():
    policies = [{"name": "p", "rules": {"allow_tools": ["read_file"]}}]
    d_allowed = evaluate_policies(
        policies, method="tools/call", tool_name="read_file", agent_id="a", threat_score=0
    )
    d_blocked = evaluate_policies(
        policies, method="tools/call", tool_name="write_file", agent_id="a", threat_score=0
    )
    assert d_allowed.allowed is True
    assert d_blocked.allowed is False


def test_require_agent_id():
    policies = [{"name": "p", "rules": {"require_agent_id": True}}]
    d = evaluate_policies(
        policies, method="tools/call", tool_name="x", agent_id=None, threat_score=0
    )
    assert d.allowed is False


# ---- Sanitizer ----
def test_sanitize_strips_control_chars():
    out = sanitize({"k": "hello\x00\x07world"})
    assert out["k"] == "helloworld"


def test_sanitize_rejects_deep_nesting():
    payload = cur = {}
    for _ in range(50):
        cur["n"] = {}
        cur = cur["n"]
    with pytest.raises(PayloadTooComplex):
        sanitize(payload)


def test_sanitize_rejects_too_many_items():
    with pytest.raises(PayloadTooComplex):
        sanitize({"list": list(range(10_000))})


def test_sanitize_preserves_structure():
    payload = {"a": 1, "b": [1, 2, {"c": "ok"}], "d": True, "e": None}
    out = sanitize(payload)
    assert out == payload
