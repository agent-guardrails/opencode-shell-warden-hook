# opencode-shell-warden-hook

OpenCode V2 hook plugin: forwards shell permission decisions to the shell-warden
checker over the one-shot letter protocol ([ADR-0016](https://github.com/agent-guardrails/docs/blob/main/adr/0016-two-tier-enforcement.md) —
no server, no long-lived process; the checker is spawned fresh on every check).

## Install

```sh
npm install @agent-guardrails/opencode-shell-warden-hook
```

`opencode.jsonc` (options per `docs/spec/shell-warden/04-shim-config.md` v2.0):

```jsonc
{
  "plugins": [
    {
      "package": "@agent-guardrails/opencode-shell-warden-hook",
      "options": {
        "checker": {
          "command": ["/opt/homebrew/bin/shell-warden", "--config", "/Users/me/.config/shell-warden/config.jsonc"]
        },
        "budgets": { "checkTimeoutMs": 2000, "killGraceMs": 250 },
        "onCheckerError": "ask",
        "actions": ["shell"]
      }
    }
  ]
}
```

## How it works

```
OpenCode server ── permission.asked ── shim ── spawn shell-warden (letter in → verdict out)
                                     ◀── allow | ask | deny ── (one JSON verdict, then EOF)
```

- `allow` → the request is confirmed (`once`); `deny` → rejected with the checker's
  prescriptive message; `ask` → the request is left untouched for the native prompt.
- The checker is a pure function of (letter, config): one spawn per check, empty
  child environment, no cache, no network, no state (02-letter-verdict §2.1).
- The shim never loosens a decision and never synthesizes `allow`: checker defects
  (exit ≠ 0, timeout, malformed output, schema drift) degrade to `onCheckerError`
  (`ask` or `deny`).
- Hook-owned state: allow-only cache (`cache.ttlMs`) and the reject budget per rule
  per session (`rejectBudget`) — exhaustion hands the ask to the human.

## Active response contract

The hook accepts only `shell-warden.verdict.v3`; the letter remains version 1.
Upgrade it together with the configuration-v3 checker. Retired v1/v2 responses and
mixed installations fail through `onCheckerError`, with no fallback validator.
The checker owns parameter permissions and three-valued policy evaluation; the
hook only validates and applies its result. Unknown restrictive predicates remain
ask, not an automatic allow or a fabricated deny vote.

Contract: https://github.com/agent-guardrails/docs/blob/main/spec/shell-warden/12-contextual-parameters.md

Tests: `npm test` and `npm run typecheck`. Set `SHELL_WARDEN_TEST_BINARY` to an
absolute path to the paired v3 binary to additionally run the real-checker
`permission.asked` round trip. Its controlled permission-event harness verifies
reply/silence without executing shell letters; it is not a deployment smoke test.

All options, defaults and clamps: `04-shim-config.md` in the spec repo. Unknown keys
are ignored with a warning; only a broken `checker.command` / `sha256` /
`onCheckerError: "allow"` disables the plugin at load — the fail-closed posture
for misconfiguration.
