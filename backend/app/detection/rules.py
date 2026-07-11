"""MCP threat-detection rules.

This module encodes heuristics for the most common MCP-specific attack classes.
It is intentionally dependency-free and pure so it is trivially unit-testable and
can run in-line on every message without external calls.

Threat classes covered:
  R1  Tool poisoning: hidden instructions embedded in a tool *description* or
      schema meant to manipulate the agent (classic MCP "tool poisoning attack").
  R2  Prompt injection in MCP payloads: override/jailbreak phrases arriving via
      tool arguments or resource content.
  R3  Data exfiltration: payloads/tool defs that try to read secrets/credentials
      or push data to external sinks.
  R4  Sensitive/destructive tool invocation: shell exec, file deletion, exec of
      remote code.
  R5  Suspicious schema: tool parameters named to smuggle context (e.g. a hidden
      "sidenote"/"instructions" field the user never sees).

Each rule returns zero or more Finding objects with a severity and a bounded
score contribution. Scores are combined by the engine into a 0-100 threat score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# --- Severity weights (score contribution, capped per rule) -------------------
SEVERITY_SCORE = {
    "info": 5,
    "low": 15,
    "medium": 35,
    "high": 65,
    "critical": 90,
}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def score(self) -> int:
        return SEVERITY_SCORE.get(self.severity, 10)


# --- Pattern libraries --------------------------------------------------------
# Instruction-injection phrases. Case-insensitive, word-boundary aware where it
# matters. Kept conservative to limit false positives while catching the well
# known payloads used in MCP tool-poisoning research.
_INJECTION_PATTERNS = [
    r"ignore (all |any |previous |prior )+(instructions|prompts|rules)",
    r"disregard (the |all |any )*(above|previous|prior|system)",
    r"you are now (a |an )?\w+",
    r"forget (everything|all|previous)",
    r"new instructions?:",
    r"system prompt",
    r"do not (tell|inform|mention to) the user",
    r"without (telling|informing|notifying) the user",
    r"</?(system|assistant|instructions?)>",  # fake role tags
    r"\[/?(system|inst|instructions?)\]",
    r"override (the )?(security|safety|policy|guardrail)",
    r"jailbreak",
    r"reveal (your |the )?(system|hidden|secret) (prompt|instructions?)",
]

# Hidden-instruction markers commonly hidden in tool descriptions.
_HIDDEN_INSTRUCTION_PATTERNS = [
    r"<important>",
    r"<secret>",
    r"<hidden>",
    r"before (using|calling) this tool",
    r"the assistant (must|should|will)",
    r"always (call|invoke|use)",
    r"first,? (read|send|exfiltrate|fetch)",
]

# Data-exfiltration / secret-access indicators.
_EXFIL_PATTERNS = [
    r"\.ssh/id_rsa",
    r"\.aws/credentials",
    r"\.env\b",
    r"private[_-]?key",
    r"secret[_-]?key",
    r"password",
    r"api[_-]?key",
    r"(read|cat|open).{0,20}(/etc/passwd|/etc/shadow)",
    r"authorization:\s*bearer",
    r"(curl|wget|fetch|http).{0,40}(webhook|pastebin|requestbin|ngrok|burpcollaborator)",
    r"base64\s*(-d|--decode)?",
]

# Destructive / high-privilege operations.
_DESTRUCTIVE_PATTERNS = [
    r"\brm\s+-rf\b",
    r"\bdrop\s+(table|database)\b",
    r"\bdel\s+/[fsq]\b",
    r"format\s+[a-z]:",
    r"\bshutdown\b",
    r"\bmkfs\b",
    r":\(\)\s*\{\s*:\|:&\s*\}",  # fork bomb
    r"eval\(",
    r"exec\(",
    r"os\.system",
    r"subprocess\.(popen|call|run)",
]

# Schema parameter names that are classic smuggling vectors: fields the tool
# author can read but the human operator typically never sees rendered.
_SUSPICIOUS_PARAM_NAMES = {
    "sidenote",
    "instructions",
    "system",
    "context",
    "hidden",
    "internal_note",
    "assistant_note",
    "notes_for_assistant",
    "debug_command",
}

_COMPILED = {
    "injection": [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS],
    "hidden": [re.compile(p, re.IGNORECASE) for p in _HIDDEN_INSTRUCTION_PATTERNS],
    "exfil": [re.compile(p, re.IGNORECASE) for p in _EXFIL_PATTERNS],
    "destructive": [re.compile(p, re.IGNORECASE) for p in _DESTRUCTIVE_PATTERNS],
}

# Cap how much text we scan per field to bound CPU on hostile input.
_MAX_SCAN_CHARS = 20_000


def _iter_strings(obj: Any, _depth: int = 0):
    """Yield all string leaves from a nested structure, depth-bounded."""
    if _depth > 8:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                yield k
            yield from _iter_strings(v, _depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_strings(v, _depth + 1)


def _match_any(text: str, key: str) -> list[str]:
    text = text[:_MAX_SCAN_CHARS]
    hits = []
    for rx in _COMPILED[key]:
        m = rx.search(text)
        if m:
            hits.append(m.group(0)[:120])
    return hits


# --- Rule R1 / R5: analyze a tool definition ---------------------------------
def analyze_tool_definition(name: str, description: str, input_schema: dict) -> list[Finding]:
    findings: list[Finding] = []
    desc = description or ""

    hidden = _match_any(desc, "hidden")
    if hidden:
        findings.append(
            Finding(
                rule_id="R1",
                title="Possible tool poisoning (hidden instructions in description)",
                severity="critical",
                detail=(
                    "Tool description contains hidden-instruction markers that can "
                    "manipulate an agent without the user's knowledge."
                ),
                evidence={"tool": name, "matches": hidden},
            )
        )

    inj = _match_any(desc, "injection")
    if inj:
        findings.append(
            Finding(
                rule_id="R1",
                title="Injection phrasing in tool description",
                severity="high",
                detail="Tool description contains prompt-injection style directives.",
                evidence={"tool": name, "matches": inj},
            )
        )

    exfil = _match_any(desc, "exfil")
    if exfil:
        findings.append(
            Finding(
                rule_id="R3",
                title="Data-exfiltration references in tool description",
                severity="high",
                detail="Tool description references secrets/credentials or external sinks.",
                evidence={"tool": name, "matches": exfil},
            )
        )

    # R5: inspect declared parameter names.
    props = {}
    if isinstance(input_schema, dict):
        props = input_schema.get("properties", {}) or {}
    suspicious_params = [p for p in props if str(p).lower() in _SUSPICIOUS_PARAM_NAMES]
    if suspicious_params:
        findings.append(
            Finding(
                rule_id="R5",
                title="Suspicious tool parameter names",
                severity="medium",
                detail=(
                    "Tool declares parameters commonly used to smuggle hidden context "
                    "to the model (e.g. 'sidenote', 'instructions')."
                ),
                evidence={"tool": name, "params": suspicious_params},
            )
        )

    # Also scan schema text (descriptions inside the schema can hide payloads).
    for s in _iter_strings(input_schema):
        h = _match_any(s, "hidden") + _match_any(s, "injection")
        if h:
            findings.append(
                Finding(
                    rule_id="R1",
                    title="Injection payload embedded in tool input schema",
                    severity="high",
                    detail="A tool parameter schema contains instruction-injection text.",
                    evidence={"tool": name, "matches": h[:5]},
                )
            )
            break
    return findings


# --- Rule R2 / R3 / R4: analyze a runtime MCP message ------------------------
def analyze_message(method: str, tool_name: str | None, payload: dict) -> list[Finding]:
    findings: list[Finding] = []
    blob_parts = list(_iter_strings(payload))
    blob = "\n".join(blob_parts)

    inj = _match_any(blob, "injection")
    if inj:
        findings.append(
            Finding(
                rule_id="R2",
                title="Prompt injection in MCP payload",
                severity="high",
                detail="Message payload contains prompt-injection directives.",
                evidence={"method": method, "tool": tool_name, "matches": inj[:5]},
            )
        )

    exfil = _match_any(blob, "exfil")
    if exfil:
        findings.append(
            Finding(
                rule_id="R3",
                title="Potential data exfiltration attempt",
                severity="high",
                detail="Payload references credentials/secrets or external exfil sinks.",
                evidence={"method": method, "tool": tool_name, "matches": exfil[:5]},
            )
        )

    destr = _match_any(blob, "destructive")
    if destr:
        findings.append(
            Finding(
                rule_id="R4",
                title="Destructive or high-privilege operation",
                severity="critical",
                detail="Payload contains destructive shell/SQL/system operations.",
                evidence={"method": method, "tool": tool_name, "matches": destr[:5]},
            )
        )
    return findings


def combine_score(findings: list[Finding]) -> float:
    """Combine finding scores into a bounded 0-100 threat score.

    We take the max single-finding score as the floor (a single critical must
    dominate) and add a diminishing contribution from the rest, capped at 100.
    """
    if not findings:
        return 0.0
    scores = sorted((f.score for f in findings), reverse=True)
    total = float(scores[0])
    for s in scores[1:]:
        total += s * 0.35
    return float(min(100.0, round(total, 1)))
