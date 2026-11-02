# opencode-shell-warden-hook — agent instructions

This repository implements the **hook side** of the shell-warden system. The contract lives in
`agent-guardrails/docs`: `spec/shell-warden/` (normative) and `schemas/` (wire + engine config).
Read them before changing protocol, budgets, config semantics or security behavior.

## Workflow

Per the org rules ([agent-guardrails/.github/AGENTS.md](https://github.com/agent-guardrails/.github/blob/main/AGENTS.md)):
- every non-trivial change starts with a GitHub issue in this repo, linked to the
  ["Agent Guardrails Roadmap"](https://github.com/orgs/agent-guardrails/projects/1) project;
- reference the issue in commits and PRs (`Closes #123`) and move the issue to Done on merge;
- **all changes land via pull requests** — never push directly to the default branch.

## Sync duties (part of Definition of Done)

- **Changed anything the spec describes** (wire protocol, budgets/clamps, config validation,
  security invariants, cache/verdict application) → update
  `agent-guardrails/docs/spec/shell-warden/` and `schemas/` **in the same change**; mention
  `docs:` in the commit message.
- **Made an architectural choice** (options were weighed, e.g. transport, lifecycle policy,
  trust boundary) → new ADR in `agent-guardrails/docs/adr/` (next number, MADR structure).
- **Milestone boundary** (M0…M4 per `spec/shell-warden/11-roadmap.md`) → update the matching item
  in the org project "Agent Guardrails Roadmap".

## Constraints

- Fail-closed everywhere: never synthesize `allow`; `onEngineError ∈ {ask, deny}` (spec invariant I3).
- The shim stays thin: no policy logic; LOC budget ~400 (spec 11-roadmap, risks).
- Fail-closed matching: an `allow` verdict never originates from unverified input (I10).
- Tests: `npm test` (node --test) and `npm run typecheck` must pass before push. Contract tests and
  `test/helpers/mock-engine.mjs` are the protocol's guard — change them together with `protocol.ts`.
- Node runs TypeScript via type-stripping: no parameter properties, no enums, no namespaces.
