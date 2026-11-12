// Verdict v2 hook conformance — consumes all and only the shared-manifest
// `hook-consumer` vectors (HANDOFF-verdict-v2 §Hook 4, 10 §10.8), plus the
// hook-specific anomaly requirements: flat v1 rejection, absent/unknown/
// non-string protocol, malformed v2 without any v1 fallback, and the 64 KiB
// pre-parse cap.
//
// Fixture provenance: byte-identical copy of docs schemas/fixtures/
// shell-warden.verdict.v2 at docs@a5480bd (contract PR #34, ADR-0023).

import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { parseV2Envelope, V2_PROTOCOL } from "../src/verdict-v2.ts"
import type { Letter } from "../src/types.ts"
import { MAX_VERDICT_BYTES } from "../src/types.ts"

const FIXTURES = new URL("./verdict-v2/", import.meta.url)

interface Vector {
  path: string
  roles: string[]
  phase: string
  expectedInvocationId: string
  positionalIndexes: number[]
  expectedError: Record<string, unknown> | null
}

function manifest(): Vector[] {
  const raw = JSON.parse(readFileSync(new URL("manifest.json", FIXTURES), "utf8"))
  assert.ok(Array.isArray(raw.fixtures), "fixture manifest must contain a fixtures array")
  return raw.fixtures
}

function letterFor(vector: Vector): Letter {
  return {
    version: 1,
    invocation: { id: vector.expectedInvocationId, sessionID: "ses_conformance" },
    action: "shell",
    commands: vector.positionalIndexes.map((index) => ({ index, raw: "git status", cwd: "/repo" })),
  }
}

test("every hook-consumer vector is consumed with its pinned phase outcome", () => {
  const vectors = manifest()
  // all consumer-rejection vectors are hook-consumer only: none may be skipped
  const consumerRejections = vectors.filter((v) => v.phase === "consumer-rejection")
  assert.ok(consumerRejections.length >= 1, "the flat v1 rejection vector must exist")
  let consumed = 0
  for (const vector of vectors) {
    if (!vector.roles.includes("hook-consumer")) continue
    consumed += 1
    const text = readFileSync(new URL(vector.path, FIXTURES), "utf8")
    const outcome = parseV2Envelope(letterFor(vector), text)
    if (vector.phase === "valid") {
      assert.equal(outcome.ok, true, `${vector.path} must validate: ${JSON.stringify(outcome)}`)
      if (outcome.ok) assert.equal(outcome.value.invocationId, vector.expectedInvocationId)
    } else {
      assert.equal(outcome.ok, false, `${vector.path} (${vector.phase}) must fail closed`)
    }
  }
  assert.equal(consumed, vectors.length, "every manifest vector has the hook-consumer role")
})

test("checker-producer-only phases are not skipped by the role filter", () => {
  const vectors = manifest()
  // schema-phase and semantic-phase vectors carry hook-consumer too (roles
  // are multi-role) — this guards against dropping them from the hook run
  assert.ok(vectors.some((v) => v.phase === "schema" && v.roles.includes("hook-consumer")))
  assert.ok(vectors.some((v) => v.phase === "semantic" && v.roles.includes("hook-consumer")))
})

// ── Hook-specific anomaly requirements ──────────────────────────────────────

const baseLetter: Letter = {
  version: 1,
  invocation: { id: "msg:call", sessionID: "ses_1" },
  action: "shell",
  commands: [{ index: 0, raw: "git status", cwd: "/repo" }],
}

const v2Command = {
  index: 0,
  verdict: "allow",
  ruleId: "hook/allow",
  classification: "static",
  match: "argv",
  facts: {
    evidence: "complete",
    reasons: ["complete"],
    selectedProfiles: ["base"],
    matched: ["hook/allow"],
    qualified: ["hook/allow"],
    rejected: [],
    votes: ["allow:hook/allow"],
  },
}

const v2Body = (over: Record<string, unknown> = {}): string =>
  JSON.stringify({
    protocol: V2_PROTOCOL,
    result: {
      invocationId: "msg:call",
      verdict: "allow",
      commands: [v2Command],
      ...over,
    },
  })

test("flat v1 response (even exact-valid) is rejected without fallback", () => {
  const flatV1 = JSON.stringify({
    invocationId: "msg:call",
    verdict: "allow",
    commands: [{ index: 0, verdict: "allow", ruleId: "hook/allow", classification: "static", match: "argv" }],
  })
  const outcome = parseV2Envelope(baseLetter, flatV1)
  assert.equal(outcome.ok, false)
  assert.match(outcome.ok ? "" : outcome.reason, /protocol/)
})

test("absent protocol is an anomaly", () => {
  const body = JSON.stringify({ result: JSON.parse(v2Body()).result })
  assert.equal(parseV2Envelope(baseLetter, body).ok, false)
})

test("unknown protocol is an anomaly", () => {
  const body = v2Body().replace(V2_PROTOCOL, "shell-warden.verdict.v3")
  assert.equal(parseV2Envelope(baseLetter, body).ok, false)
})

test("non-string protocol is an anomaly", () => {
  const body = v2Body().replace(`"protocol":"${V2_PROTOCOL}"`, '"protocol":42')
  assert.equal(parseV2Envelope(baseLetter, body).ok, false)
})

test("malformed v2 never falls back to a v1 read", () => {
  // a v2 envelope whose nested result was dropped cannot be re-read as flat v1
  const body = JSON.stringify({ protocol: V2_PROTOCOL })
  const outcome = parseV2Envelope(baseLetter, body)
  assert.equal(outcome.ok, false)
  assert.match(outcome.ok ? "" : outcome.reason, /result/)
})

test("oversize output fails the 64 KiB cap before JSON parsing", () => {
  const filler = "x".repeat(MAX_VERDICT_BYTES)
  const oversize = JSON.stringify({
    protocol: V2_PROTOCOL,
    result: { invocationId: "msg:call", verdict: "ask", commands: [{ index: 0, verdict: "ask", classification: "invalid", match: "raw" }], message: filler },
  })
  assert.ok(Buffer.byteLength(oversize, "utf8") > MAX_VERDICT_BYTES)
  const outcome = parseV2Envelope(baseLetter, oversize)
  assert.equal(outcome.ok, false)
  assert.match(outcome.ok ? "" : outcome.reason, /64 KiB/)
})

test("valid v2 envelope returns the nested result to the application path", () => {
  const outcome = parseV2Envelope(baseLetter, v2Body())
  assert.equal(outcome.ok, true)
  if (outcome.ok) {
    assert.equal(outcome.value.verdict, "allow")
    assert.equal(outcome.value.commands[0]?.ruleId, "hook/allow")
  }
})
