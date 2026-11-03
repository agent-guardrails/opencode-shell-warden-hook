# opencode-shell-warden-hook

Thin **OpenCode V2** plugin (the "hook" part of the shell-warden system): it receives permission
evaluation events from OpenCode and asks the **shell-warden engine** for a verdict over
NDJSON JSON-RPC on stdio.

The shim contains **no policy logic** — only transport, supervision, budgets, verdict application
and fail-closed degradation. Spec: `agent-guardrails/opencode-adrs` → `docs/policyd-plugin-design/`
(`03-shim.md`, `04-shim-config.md`, `02-protocol.md`).

## How it works

```
OpenCode server ── permission.hook("evaluate") ── shim ── policy/check ──▶ shell-warden engine
                        ◀── tighten-only verdict ───────────── verdict: allow | ask | deny
```

- `allow` / `deny` are applied to the hook event; `ask` falls through to OpenCode's native prompt.
- The shim never loosens a decision and never synthesizes `allow`: any engine anomaly
  (crash, timeout, malformed frame, bad protocol version) degrades to `onEngineError` (`ask` or `deny`).
- Engine runs as a persistent child process spawned **without inherited environment**, from an
  **absolute** argv, with an exact `protocolVersion` handshake.

## Install

```sh
npm install @agent-guardrails/opencode-shell-warden-hook   # or reference a local checkout
```

`opencode.jsonc`:

```jsonc
{
  "plugins": [
    {
      "package": "@agent-guardrails/opencode-shell-warden-hook",
      "options": {
        "engine": { "command": ["/usr/local/bin/shell-warden", "serve"] },
        "onEngineError": "ask",
        "actions": ["shell"]
      }
    }
  ]
}
```

All options, defaults and clamps: `04-shim-config.md` in the spec repo. Unknown keys are ignored
with a warning; invalid `engine.command` (relative path, failed `{env:…}` substitution) disables
the plugin at load — that is the fail-closed posture for misconfiguration.

## Development

```sh
npm install
npm test        # node --test (35 contract/unit tests, mock engine included)
npm run typecheck
```

Layout:

| Module | Responsibility |
|---|---|
| `src/protocol.ts` | NDJSON framing, byte caps, frame parser, id pool |
| `src/supervisor.ts` | engine lifecycle: spawn → handshake → ready, violations → restart → unhealthy, dispose |
| `src/cache.ts` | allow-only TTL LRU verdict cache |
| `src/apply.ts` | request building, cache keys, tighten-only verdict mapping |
| `src/config.ts` | options validation (fatal vs warn+clamp) |
| `src/index.ts` | `Plugin.define` + hook registrations |

Tests run on Node ≥ 22.6 using native TypeScript type-stripping (no build step).
The engine side (segmentation, rules, verdicts) is a separate project: `agent-guardrails/shell-warden`.

## Status

M0/M1 (shim): implemented — protocol codec, supervisor, cache, apply, config, hook wiring.
Not yet: `policy/observe` hardening, sha256 pinning is implemented at spawn only (no MDM story), engine itself.
