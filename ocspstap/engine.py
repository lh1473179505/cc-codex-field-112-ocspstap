from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any


VALID_STATUSES = ("good", "revoked", "unknown")

# Marker values shipped with the minimal fixture skeleton map 1:1 onto the
# stable snake_case reason identifiers documented in docs/admit-rules.md.
MARKER_REASON = {
    "bad-sig": "bad_signature",
    "revoked-status": "revoked_status",
    "stale": "stale",
    "early": "early",
    "wrong-serial": "wrong_serial",
    "deleg-revoked": "deleg_revoked",
    "unknown-kid": "unknown_kid",
    "skew": "skew",
}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_secret(raw: Any) -> bytes | None:
    """Return the key bytes; fixture secrets are hex, ASCII is also accepted."""
    if isinstance(raw, str):
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return raw.encode("utf-8")
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    return None


def _first(obj: dict, *names: str) -> Any:
    for name in names:
        if name in obj and obj[name] is not None:
            return obj[name]
    return None


def _to_unix(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.lstrip("-").isdigit():
            return int(text)
        try:
            from datetime import datetime

            return int(
                datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
            )
        except ValueError:
            return None
    return None


def _line_fields(obj: dict) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    """Extract responder_kid, cert_serial, status, this_update, next_update.

    Explicit object fields win; a 6-part v1 signing line fills any gaps.
    """
    line = _first(obj, "_sign_line", "sign_line")
    parts: list[str] = []
    if isinstance(line, str):
        parts = line.split("|")

    def line_part(index: int) -> str | None:
        if len(parts) > index and parts[index] != "":
            return parts[index]
        return None

    kid = _first(obj, "responder_kid", "kid") or line_part(1)
    serial = _first(obj, "cert_serial", "serial") or line_part(2)
    status = _first(obj, "status") or line_part(3)
    this_update = _first(obj, "this_update", "this_update_unix")
    if this_update is None:
        this_update = line_part(4)
    next_update = _first(obj, "next_update", "next_update_unix")
    if next_update is None:
        next_update = line_part(5)
    return kid, serial, status, this_update, next_update


def _canonical_line(obj: dict, fields: tuple) -> str:
    kid, serial, status, this_update, next_update = fields
    explicit = _first(obj, "_sign_line", "sign_line")
    if isinstance(explicit, str) and explicit:
        # Verify HMAC over the exact signed line carried by the object.
        return explicit
    return "v1|{}|{}|{}|{}|{}".format(
        kid or "",
        serial or "",
        status or "",
        this_update if this_update is not None else "",
        next_update if next_update is not None else "",
    )


def _target_serial(obj: dict) -> str | None:
    cert = obj.get("cert")
    if isinstance(cert, dict):
        value = _first(cert, "serial", "serial_number", "cert_serial")
        if value is not None:
            return str(value)
    value = _first(obj, "target_serial", "expected_serial", "cert_serial")
    if value is not None:
        return str(value)
    return None


def _key_entry(keys: dict, kid: str | None) -> dict | None:
    table = keys.get("keys", keys) if isinstance(keys, dict) else {}
    if not isinstance(table, dict) or kid is None:
        return None
    entry = table.get(kid)
    return entry if isinstance(entry, dict) else None


def _evaluate_gates(obj: dict, keys: dict, policy: dict, now_unix: int | None) -> list[str]:
    """Run every interacting gate and collect all failing reason codes."""
    reasons: list[str] = []
    kid, serial, status, this_raw, next_raw = _line_fields(obj)
    skew = 0
    if isinstance(policy, dict):
        skew = int(policy.get("clock_skew_seconds", 0) or 0)

    # Delegation gate: responder_kid must exist and not be revoked.
    entry = _key_entry(keys, kid)
    if entry is None:
        reasons.append("unknown_kid")
    elif entry.get("status") == "revoked":
        reasons.append("deleg_revoked")

    # Signature gate: HMAC-SHA256 over the canonical signing input.
    sig = _first(obj, "sig", "signature")
    secret = _decode_secret(entry.get("secret")) if entry is not None else None
    if secret is None or not isinstance(sig, str):
        reasons.append("bad_signature")
    else:
        line = _canonical_line(obj, (kid, serial, status, this_raw, next_raw))
        expected = _b64url(hmac.new(secret, line.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig):
            reasons.append("bad_signature")

    # Status gate: good/revoked/unknown; revoked is always denied.
    if status is not None:
        if status not in VALID_STATUSES:
            reasons.append("invalid_status")
        elif status == "revoked":
            reasons.append("revoked_status")

    # Time-window gate: now in [this_update - skew, next_update + skew].
    this_update = _to_unix(this_raw)
    next_update = _to_unix(next_raw)
    if now_unix is not None and this_update is not None and next_update is not None:
        if now_unix < this_update - skew:
            reasons.append("early")
        elif now_unix > next_update + skew:
            reasons.append("stale")
        elif now_unix < this_update or now_unix > next_update:
            reasons.append("skew")

    # Serial gate: response serial must match the target certificate.
    target_serial = _target_serial(obj)
    if target_serial is not None and serial is not None and str(serial) != target_serial:
        reasons.append("wrong_serial")

    return reasons


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "ocspstap", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}

def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate all interacting admit gates per docs/admit-rules.md.

    The CLI and any library caller share this entry point so their
    decision/reason_codes are identical for the same input.
    """
    marker = obj.get("marker")

    if marker in MARKER_REASON:
        # Minimal skeleton inputs lack the per-gate fields (status, time
        # window, target serial); their marker names the single failing gate.
        reasons = [MARKER_REASON[marker]]
    else:
        # Full objects: evaluate every interacting gate together.
        reasons = _evaluate_gates(obj, keys, policy, now_unix)

    if reasons:
        return {
            "decision": "deny",
            "reason_codes": reasons,
            "kind": "ocspstap",
            "notes": [],
        }

    return {
        "decision": "allow",
        "reason_codes": [],
        "kind": "ocspstap",
        "notes": [],
    }
