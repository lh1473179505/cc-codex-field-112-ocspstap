from __future__ import annotations
from typing import Any

def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "ocspstap", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}

def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """STUB: real implementation must satisfy docs/admit-rules.md."""
    return {
        "decision": "deny",
        "reason_codes": ["not_implemented"],
        "kind": "ocspstap",
        "notes": ["stub admit; implement per docs"],
    }
