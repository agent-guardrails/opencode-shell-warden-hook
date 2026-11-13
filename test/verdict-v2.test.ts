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

// ── Letter positional index validation (02 §2.8) ────────────────────────────
// The expected letter context carries contiguous positional indexes 0..N-1
// equal to their array positions; a malformed letter must fail closed before
// any result-command comparison (no checker output may rescue it).

const letterWithIndexes = (...indexes: number[]): Letter => ({
  version: 1,
  invocation: { id: "msg:call", sessionID: "ses_1" },
  action: "shell",
  commands: indexes.map((index) => ({ index, raw: "git status", cwd: "/repo" })),
})

const twoCommandBody = (): string =>
  JSON.stringify({
    protocol: V2_PROTOCOL,
    result: {
      invocationId: "msg:call",
      verdict: "allow",
      commands: [
        { index: 0, verdict: "allow", classification: "static", match: "argv" },
        { index: 1, verdict: "allow", classification: "static", match: "argv" },
      ],
    },
  })

test("contiguous letter indexes validate against the matching result", () => {
  assert.equal(parseV2Envelope(letterWithIndexes(0, 1), twoCommandBody()).ok, true)
})

test("duplicate letter command index fails closed", () => {
  const outcome = parseV2Envelope(letterWithIndexes(0, 0), twoCommandBody())
  assert.equal(outcome.ok, false)
  assert.match(outcome.ok ? "" : outcome.reason, /letter\.commands\[1\]\.index/)
})

test("skipped letter command index fails closed", () => {
  const outcome = parseV2Envelope(letterWithIndexes(0, 2), twoCommandBody())
  assert.equal(outcome.ok, false)
  assert.match(outcome.ok ? "" : outcome.reason, /letter\.commands\[1\]\.index/)
})

test("negative letter command index fails closed", () => {
  const outcome = parseV2Envelope(letterWithIndexes(-1), twoCommandBody())
  assert.equal(outcome.ok, false)
  assert.match(outcome.ok ? "" : outcome.reason, /letter\.commands\[0\]\.index/)
})

test("out-of-position letter command index fails closed", () => {
  const outcome = parseV2Envelope(letterWithIndexes(1, 0), twoCommandBody())
  assert.equal(outcome.ok, false)
  assert.match(outcome.ok ? "" : outcome.reason, /letter\.commands\[0\]\.index/)
})

// ── String bounds count Unicode code points, not UTF-16 units ───────────────
// The v2 schema measures maxLength/minLength in code points; String.length and
// regex quantifiers count UTF-16 code units, so supplementary characters (one
// emoji = 2 units) would push schema-valid verdicts into onCheckerError.

const EMOJI = "\u{1F600}"

const ruleEnvelope = (ruleId: string): string =>
  JSON.stringify({
    protocol: V2_PROTOCOL,
    result: {
      invocationId: "msg:call",
      verdict: "allow",
      commands: [{
        index: 0,
        verdict: "allow",
        ruleId,
        classification: "static",
        match: "argv",
        facts: {
          evidence: "complete",
          reasons: ["complete"],
          selectedProfiles: ["base"],
          matched: [ruleId],
          qualified: [ruleId],
          rejected: [],
          votes: [`allow:${ruleId}`],
        },
      }],
    },
  })

test("message bounds count code points — 300 emoji (600 UTF-16 units) is valid", () => {
  // the reported false-negative: under UTF-16 counting 300 emoji read as 600
  // chars and a schema-valid verdict degraded through onCheckerError
  const outcome = parseV2Envelope(baseLetter, v2Body({ message: EMOJI.repeat(300) }))
  assert.equal(outcome.ok, true)
  if (outcome.ok) assert.equal(outcome.value.message, EMOJI.repeat(300))
})

test("message at the 512 code-point boundary — 512 emoji valid, 513 invalid", () => {
  assert.equal(parseV2Envelope(baseLetter, v2Body({ message: EMOJI.repeat(512) })).ok, true)
  const over = parseV2Envelope(baseLetter, v2Body({ message: EMOJI.repeat(513) }))
  assert.equal(over.ok, false)
  assert.match(over.ok ? "" : over.reason, /message/)
})

test("ruleId and its vote entry count code points — 128 emoji valid, 129 invalid", () => {
  // `allow:` + 128 emoji is 129 UTF-16 units: the old {1,128} quantifier and
  // the identifier length check both rejected it although the schema allows it
  assert.equal(parseV2Envelope(baseLetter, ruleEnvelope(EMOJI.repeat(128))).ok, true)
  const over = parseV2Envelope(baseLetter, ruleEnvelope(EMOJI.repeat(129)))
  assert.equal(over.ok, false)
})

test("invocationId counts code points — 256 emoji valid, 257 invalid", () => {
  const id256 = EMOJI.repeat(256)
  const letter: Letter = { ...baseLetter, invocation: { id: id256, sessionID: "ses_1" } }
  const atBound = JSON.stringify({
    protocol: V2_PROTOCOL,
    result: { invocationId: id256, verdict: "allow", commands: [v2Command] },
  })
  assert.equal(parseV2Envelope(letter, atBound).ok, true)
  const letterOver: Letter = { ...baseLetter, invocation: { id: EMOJI.repeat(257), sessionID: "ses_1" } }
  const over = parseV2Envelope(letterOver, JSON.stringify({
    protocol: V2_PROTOCOL,
    result: { invocationId: EMOJI.repeat(257), verdict: "allow", commands: [v2Command] },
  }))
  assert.equal(over.ok, false)
  // the schema bound fires before the echo check — overlong ids fail closed
  assert.match(over.ok ? "" : over.reason, /^verdict\.result\.invocationId invalid$/)
})
