"""Tool-definition drift detection ("rug pull" defense) — rule R9.

The classic MCP rug-pull: a server advertises a benign tool, the operator
approves it, and *later* the server silently swaps the description or schema
for a poisoned one. Clients re-fetch tool definitions on every session, so the
swap reaches agents immediately — but nothing in the MCP protocol surfaces the
change to a human.

Defense: fingerprint every approved tool definition (SHA-256 over name +
description + input schema). Whenever a server re-registers its tools, compare
fingerprints; any changed definition raises a high-severity R9 alert with the
before/after evidence, and brand-new tools appearing post-approval raise a
lower-severity notice.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


def fingerprint_tool(name: str, description: str, input_schema: dict[str, Any]) -> str:
    """Stable content hash of a tool definition."""
    canonical = json.dumps(
        {"name": name, "description": description or "", "schema": input_schema or {}},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class DriftFinding:
    rule_id: str
    title: str
    severity: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)


def diff_tool_sets(
    old: dict[str, str],  # tool name -> fingerprint (approved baseline)
    new: dict[str, str],  # tool name -> fingerprint (just reported)
    *,
    server_name: str,
) -> list[DriftFinding]:
    """Compare baseline vs newly-reported tool fingerprints."""
    findings: list[DriftFinding] = []

    changed = [n for n in old.keys() & new.keys() if old[n] != new[n]]
    added = sorted(new.keys() - old.keys())
    removed = sorted(old.keys() - new.keys())

    for name in sorted(changed):
        findings.append(
            DriftFinding(
                rule_id="R9",
                title="Tool definition drift (possible rug pull)",
                severity="high",
                detail=(
                    f"Tool '{name}' on server '{server_name}' changed its definition "
                    "after initial registration. Silent definition changes are the "
                    "primary delivery mechanism for tool-poisoning attacks."
                ),
                evidence={
                    "tool": name,
                    "server": server_name,
                    "old_fingerprint": old[name],
                    "new_fingerprint": new[name],
                },
            )
        )

    if added:
        findings.append(
            DriftFinding(
                rule_id="R9",
                title="New tools appeared after registration",
                severity="medium",
                detail=(
                    f"Server '{server_name}' now advertises {len(added)} tool(s) that "
                    "were not present at registration: " + ", ".join(added[:10])
                ),
                evidence={"server": server_name, "added_tools": added[:50]},
            )
        )

    if removed:
        findings.append(
            DriftFinding(
                rule_id="R9",
                title="Tools removed from server",
                severity="info",
                detail=(
                    f"Server '{server_name}' no longer advertises: "
                    + ", ".join(removed[:10])
                ),
                evidence={"server": server_name, "removed_tools": removed[:50]},
            )
        )

    return findings
