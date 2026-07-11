"""Input sanitization for untrusted MCP payloads.

Security decision: MCP messages come from potentially hostile sources. Before we
store or scan them we enforce structural limits (depth, size, key count) to
prevent resource-exhaustion (billion-laughs style) and we neutralize control
characters. We do NOT execute or interpret any payload content — it is treated
strictly as data.
"""

from __future__ import annotations

from typing import Any

MAX_DEPTH = 12
MAX_STRING = 50_000
MAX_KEYS = 2_000
MAX_ITEMS = 5_000


class PayloadTooComplex(ValueError):
    pass


_CONTROL_TRANSLATE = {c: None for c in range(0x00, 0x20) if c not in (0x09, 0x0A, 0x0D)}


def _clean_str(s: str) -> str:
    # Drop non-tab/newline control chars; bound length.
    return s.translate(_CONTROL_TRANSLATE)[:MAX_STRING]


def sanitize(value: Any, _depth: int = 0, _counter: dict | None = None) -> Any:
    """Return a sanitized copy of `value` or raise PayloadTooComplex.

    Enforces depth, total key/item counts, and string length. Strips control
    characters from strings. Non-JSON scalar types are coerced to str.
    """
    if _counter is None:
        _counter = {"keys": 0, "items": 0}
    if _depth > MAX_DEPTH:
        raise PayloadTooComplex("payload nesting too deep")

    if isinstance(value, str):
        return _clean_str(value)
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            _counter["keys"] += 1
            if _counter["keys"] > MAX_KEYS:
                raise PayloadTooComplex("too many keys")
            out[_clean_str(str(k))[:256]] = sanitize(v, _depth + 1, _counter)
        return out
    if isinstance(value, (list, tuple)):
        out_list = []
        for item in value:
            _counter["items"] += 1
            if _counter["items"] > MAX_ITEMS:
                raise PayloadTooComplex("too many items")
            out_list.append(sanitize(item, _depth + 1, _counter))
        return out_list
    # Unknown/unsupported type -> stringify defensively.
    return _clean_str(str(value))
