"""Policy bundle export/import + OPA/Rego export.

Treats the policy set as version-controllable code: export every policy to a
single YAML *bundle* you can commit to Git, and import a bundle back to
reconcile an environment to a known state. Import is idempotent — a policy
matched by name is updated (and version-snapshotted), a new one is created,
existing policies not in the bundle are left untouched (a bundle adds/updates,
it never silently deletes).

Also exports a single policy as OPA **Rego** so the same allow/deny intent can
run in an external policy engine (an OPA sidecar, Gatekeeper, etc.).

The YAML (de)serialization and Rego generation are pure helpers, unit-tested in
isolation; the DB reconcile is a thin wrapper.
"""

from __future__ import annotations

from typing import Any

import yaml

BUNDLE_VERSION = 1


def policies_to_bundle(policies: list[dict[str, Any]]) -> str:
    """Serialize policies (name/description/enabled/rules dicts) to a YAML bundle."""
    doc = {
        "bundle_version": BUNDLE_VERSION,
        "policies": [
            {
                "name": p["name"],
                "description": p.get("description", ""),
                "enabled": bool(p.get("enabled", True)),
                "rules": p.get("rules", {}) or {},
            }
            for p in policies
        ],
    }
    # sort_keys=False to keep a stable, human-authored field order in Git diffs.
    return yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)


def parse_bundle(text: str) -> list[dict[str, Any]]:
    """Parse + validate a YAML bundle. Returns a list of policy dicts.

    Raises ValueError with a clear message on any structural problem so the API
    can return 422 rather than persisting a malformed policy.
    """
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError("bundle must be a mapping with a 'policies' list")
    ver = doc.get("bundle_version")
    if ver not in (None, BUNDLE_VERSION):
        raise ValueError(f"unsupported bundle_version {ver!r} (expected {BUNDLE_VERSION})")
    raw = doc.get("policies")
    if not isinstance(raw, list):
        raise ValueError("bundle 'policies' must be a list")

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for i, p in enumerate(raw):
        if not isinstance(p, dict):
            raise ValueError(f"policy #{i} must be a mapping")
        name = p.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"policy #{i} is missing a non-empty 'name'")
        if name in seen:
            raise ValueError(f"duplicate policy name in bundle: {name!r}")
        seen.add(name)
        rules = p.get("rules", {})
        if rules is None:
            rules = {}
        if not isinstance(rules, dict):
            raise ValueError(f"policy {name!r} 'rules' must be a mapping")
        out.append({
            "name": name.strip()[:255],
            "description": str(p.get("description", ""))[:5000],
            "enabled": bool(p.get("enabled", True)),
            "rules": rules,
        })
    return out


def _rego_str_list(values: Any) -> str:
    items = [str(v) for v in values] if isinstance(values, list) else []
    return "{" + ", ".join(f'"{v}"' for v in items) + "}"


def policy_to_rego(name: str, rules: dict[str, Any]) -> str:
    """Render a policy's allow/deny intent as an OPA Rego module.

    Mirrors services/policy.py semantics: deny_tools/deny_methods/deny_agents,
    max_threat_score, require_agent_id, an optional allow_tools allowlist, and a
    default allow/deny. `input` is expected to carry method, tool_name, agent_id,
    and threat_score — the same fields MCPGuard evaluates.
    """
    # Package name: a safe slug of the policy name.
    slug = "".join(c if c.isalnum() else "_" for c in name.lower()).strip("_") or "policy"
    default = str(rules.get("default", "allow")).lower()
    lines: list[str] = [
        f"package mcpguard.{slug}",
        "",
        "import future.keywords.in",
        "",
        f"default allow := {'true' if default == 'allow' else 'false'}",
        "",
    ]

    deny_conditions: list[list[str]] = []
    if rules.get("deny_methods"):
        deny_conditions.append([f"input.method in {_rego_str_list(rules['deny_methods'])}"])
    if rules.get("deny_tools"):
        deny_conditions.append([f"input.tool_name in {_rego_str_list(rules['deny_tools'])}"])
    if rules.get("deny_agents"):
        deny_conditions.append([f"input.agent_id in {_rego_str_list(rules['deny_agents'])}"])
    if isinstance(rules.get("max_threat_score"), (int, float)):
        deny_conditions.append([f"input.threat_score >= {rules['max_threat_score']}"])
    if rules.get("require_agent_id"):
        deny_conditions.append(['not input.agent_id'])

    for cond in deny_conditions:
        lines.append("deny if {")
        for c in cond:
            lines.append(f"    {c}")
        lines.append("}")
        lines.append("")

    allow_tools = rules.get("allow_tools")
    if isinstance(allow_tools, list) and allow_tools:
        # Allowlist: a tool call not in the set is denied.
        lines.append("deny if {")
        lines.append("    input.tool_name")
        lines.append(f"    not input.tool_name in {_rego_str_list(allow_tools)}")
        lines.append("}")
        lines.append("")

    # Final decision: allowed unless any deny fired.
    lines.append("allowed if {")
    lines.append("    allow")
    lines.append("    not deny")
    lines.append("}")
    return "\n".join(lines) + "\n"
