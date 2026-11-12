import { test } from "node:test"
import assert from "node:assert/strict"
import { CheckerInvoker, RejectBudgets, verifyPin, type CheckerOptions } from "../src/checker.ts"
import type { Letter } from "../src/types.ts"
import { MAX_VERDICT_BYTES } from "../src/types.ts"
import { writeFileSync } from "node:fs"

const NODE = process.execPath
const MOCK = new URL("./helpers/mock-checker.mjs", import.meta.url).pathname

const letter: Letter = {
  version: 1,
  invocation: { id: "msg:call", sessionID: "ses_1" },
  action: "shell",
  commands: [{ index: 0, raw: "git status", cwd: "" }],
}

const V2_PROTOCOL = "shell-warden.verdict.v2"

const command = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  index: 0,
  verdict: "allow",
  ruleId: "git/allow-status",
  classification: "static",
  match: "argv",
  facts: {
    evidence: "complete",
    reasons: ["complete"],
    selectedProfiles: ["git"],
    matched: ["git/allow-status"],
    qualified: ["git/allow-status"],
    rejected: [],
    votes: ["allow:git/allow-status"],
  },
  ...over,
})

const verdictBody = (over: Record<string, unknown> = {}, commandOver: Record<string, unknown> = {}): string =>
  JSON.stringify({
    protocol: V2_PROTOCOL,
    result: { invocationId: "msg:call", verdict: "allow", commands: [command(commandOver)], ...over },
  })

const makeOpts = (over: Partial<CheckerOptions> = {}): CheckerOptions => ({
  command: [NODE, MOCK, "--behavior", JSON.stringify({})],
  sha256: null,
  checkTimeoutMs: 2_000,
  killGraceMs: 100,
  maxConcurrentSpawns: 8,
  log: () => {},
  ...over,
})

test("valid v2 envelope passes through", async () => {
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: verdictBody() })] }))
  const out = await invoker.check(letter)
  assert.equal(out.ok, true)
  if (out.ok) {
    assert.equal(out.verdict.verdict, "allow")
    assert.equal(out.verdict.commands[0]?.ruleId, "git/allow-status")
  }
})

test("deny with prescriptive message passes", async () => {
  const body = verdictBody(
    { verdict: "deny", message: "history rewrite" },
    { verdict: "deny", facts: undefined },
  )
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
  const out = await invoker.check(letter)
  assert.equal(out.ok, true)
  if (out.ok) assert.equal(out.verdict.message, "history rewrite")
})

test("ask verdict passes (hook escalates by silence)", async () => {
  const body = verdictBody(
    { verdict: "ask" },
    { verdict: "ask", ruleId: undefined, classification: "invalid", match: "raw", facts: undefined },
  )
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
  const out = await invoker.check(letter)
  assert.equal(out.ok, true)
  if (out.ok) assert.equal(out.verdict.verdict, "ask")
})

test("non-zero exit degrades; stdout ignored", async () => {
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: verdictBody(), exit: 3 })] }))
  const out = await invoker.check(letter)
  assert.deepEqual(out, { ok: false, reason: "checker exit 3" })
})

test("non-json output degrades", async () => {
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: "banana" })] }))
  const out = await invoker.check(letter)
  assert.equal(out.ok, false)
})

test("trailing bytes after the one verdict degrades", async () => {
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: verdictBody() + "…" })] }))
  assert.equal((await invoker.check(letter)).ok, false)
})

test("invocationId mismatch degrades (fail-closed, I10)", async () => {
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: verdictBody({ invocationId: "other:1" }) })] }))
  assert.equal((await invoker.check(letter)).ok, false)
})

test("aggregate deny without message degrades", async () => {
  const body = verdictBody({ verdict: "deny" }, { verdict: "deny" })
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
  assert.equal((await invoker.check(letter)).ok, false)
})

test("flat v1 response degrades — no v1 read, no fallback (ADR-0023)", async () => {
  const flatV1 = JSON.stringify({
    invocationId: "msg:call",
    verdict: "allow",
    commands: [{ index: 0, verdict: "allow", ruleId: "git/allow-status", classification: "static", match: "argv" }],
  })
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: flatV1 })] }))
  const out = await invoker.check(letter)
  assert.equal(out.ok, false)
  if (!out.ok) assert.match(out.reason, /protocol/)
})

test("unknown and non-string protocol degrade", async () => {
  for (const protocol of ["shell-warden.verdict.v3", 42]) {
    const body = JSON.stringify({ protocol, result: JSON.parse(verdictBody()).result })
    const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
    assert.equal((await invoker.check(letter)).ok, false, `protocol ${String(protocol)}`)
  }
})

test("malformed v2 degrades without falling back to v1", async () => {
  // valid flat v1 nested inside a v2 envelope is still an anomaly
  const body = JSON.stringify({ protocol: V2_PROTOCOL, invocationId: "msg:call", verdict: "allow" })
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
  const out = await invoker.check(letter)
  assert.equal(out.ok, false)
})

test("impossible v2 tuples degrade (invalid allow, opaque allow, raw allow)", async () => {
  const cases = [
    verdictBody({}, { classification: "invalid", match: "raw" }),
    verdictBody({}, { classification: "opaque", match: "raw" }),
    verdictBody({}, { classification: "static", match: "raw" }),
    verdictBody({ verdict: "deny" }, { verdict: "deny", ruleId: undefined, facts: undefined }),
    verdictBody({ verdict: "allow" }, { classification: "static", match: "argv", facts: { evidence: "complete", reasons: [], selectedProfiles: [], matched: ["r"], qualified: ["r"], rejected: [], votes: [] } }),
  ]
  for (const body of cases) {
    const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
    const out = await invoker.check(letter)
    assert.equal(out.ok, false, `must degrade: ${body.slice(0, 80)}…`)
  }
})

test("oversize output degrades at the pre-parse 64 KiB cap", async () => {
  const filler = "x".repeat(MAX_VERDICT_BYTES)
  const body = JSON.stringify({
    protocol: V2_PROTOCOL,
    result: {
      invocationId: "msg:call",
      verdict: "ask",
      commands: [{ index: 0, verdict: "ask", classification: "invalid", match: "raw" }],
      message: filler,
    },
  })
  assert.ok(Buffer.byteLength(body, "utf8") > MAX_VERDICT_BYTES)
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
  const out = await invoker.check(letter)
  assert.equal(out.ok, false)
})

test("commands count mismatch degrades", async () => {
  const body = JSON.stringify({
    protocol: V2_PROTOCOL,
    result: {
      invocationId: "msg:call",
      verdict: "allow",
      commands: [command(), { index: 5, verdict: "allow", classification: "static", match: "argv" }],
    },
  })
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
  assert.equal((await invoker.check(letter)).ok, false)
})

test("aggregate mismatch degrades (deny > ask > allow enforced)", async () => {
  // command verdicts allow + ask must aggregate to ask, not allow
  const body = JSON.stringify({
    protocol: V2_PROTOCOL,
    result: {
      invocationId: "msg:call",
      verdict: "allow",
      commands: [
        command(),
        { index: 1, verdict: "ask", classification: "invalid", match: "raw" },
      ],
    },
  })
  const invoker = new CheckerInvoker(makeOpts({
    command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })],
  }))
  const wideLetter: Letter = {
    ...letter,
    commands: [
      { index: 0, raw: "git status", cwd: "" },
      { index: 1, raw: "git status --wat", cwd: "" },
    ],
  }
  assert.equal((await invoker.check(wideLetter)).ok, false)
})

test("timeout degrades (SIGTERM densify is the checker's problem)", async () => {
  const invoker = new CheckerInvoker(makeOpts({
    command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: verdictBody(), sleepMs: 1_000 })],
    checkTimeoutMs: 150, killGraceMs: 50,
  }))
  const out = await invoker.check(letter)
  assert.equal(out.ok, false)
  assert.match(out.ok === false ? out.reason : "", /exit/)
})

test("empty stdout degrades", async () => {
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: "" })] }))
  const out = await invoker.check(letter)
  assert.deepEqual(out, { ok: false, reason: "checker produced no verdict" })
})

test("spawn budget exhausted degrades locally", async () => {
  const opts = makeOpts({
    command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: verdictBody(), sleepMs: 700 })],
    maxConcurrentSpawns: 1,
  })
  const invoker = new CheckerInvoker(opts)
  const [a, b] = await Promise.all([invoker.check(letter), invoker.check(letter)])
  const reasons = [a, b].map((x) => (x.ok ? "ok" : x.reason))
  assert.equal(reasons.filter((r) => r.includes("spawn budget")).length, 1)
})

test("sha256 pin mismatch refuses every spawn", async () => {
  writeFileSync("/tmp/sw-pin-probe", "x")
  const opts = makeOpts({ command: ["/tmp/sw-pin-probe"], sha256: "a".repeat(64) })
  verifyPin(opts)
  const invoker = new CheckerInvoker(opts)
  const out = await invoker.check(letter)
  assert.match(out.ok === false ? out.reason : "", /pin/)
})

test("reject budget spends then exhausts per rule+session", () => {
  const rb = new RejectBudgets(2, 60_000)
  assert.equal(rb.trySpend("s1", "r1"), true)
  assert.equal(rb.trySpend("s1", "r1"), true)
  assert.equal(rb.trySpend("s1", "r1"), false)
  assert.equal(rb.trySpend("s2", "r1"), true) // another session independent
  assert.equal(rb.trySpend("s1", "r9"), true)
})
