# Release notes

## 0.4.0 — verdict v3

Release tracking: https://github.com/agent-guardrails/opencode-shell-warden-hook/issues/31
Companion checker: https://github.com/agent-guardrails/shell-warden/releases/tag/v0.6.0

- **Breaking:** accept only `shell-warden.verdict.v3`. Retired v1/v2 responses,
  malformed evidence, and inconsistent diagnostics take `onCheckerError`
  (`ask` or `deny`), never an automatic allow. The letter remains version 1.
- Validate contextual parameter evidence, aggregate coverage reasons, and the
  canonical 62-vector v3 fixture set. The hook applies the checker's result; it
  does not evaluate policy or runtime variable values.
- `allow` still replies `once`, `deny` replies `reject` within the reject budget,
  and `ask` leaves the native prompt untouched. Native denials remain authoritative.
- CI now pairs the hook with the merged executable-spelling/wrapper checker and
  its canonical contract.

### Upgrade

Install `@agent-guardrails/opencode-shell-warden-hook@0.4.0` and shell-warden
0.6.0 as a coordinated pair. Migrate checker policies to configuration v3 and
review its contextual-parameter and wrapper coverage requirements before
activation. Do not enable the hook over a native shell `allow` baseline.

### Open follow-up work

Reject-budget attribution for multi-command denials remains tracked at
https://github.com/agent-guardrails/opencode-shell-warden-hook/issues/23.
Exhaustion leaves the request for a human; it does not grant permission.
Additional CI lint/format and merge-gate work is separate:
https://github.com/agent-guardrails/opencode-shell-warden-hook/issues/25.
