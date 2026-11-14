# ocspstap admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{responder_kid}|{cert_serial}|{status}|{this_update}|{next_update}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- status good/revoked/unknown；revoked 必拒
- now 必须在 [this_update-skew, next_update+skew]
- responder_kid 必须在委派表且未吊销
- serial 必须匹配目标证书

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-good, ok-skew

Deny cases: bad-sig, revoked-status, stale, early, wrong-serial, deleg-revoked, unknown-kid, skew

Reason codes should be stable snake_case identifiers matching the failing gate.
