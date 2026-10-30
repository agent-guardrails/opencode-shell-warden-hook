import { test } from "node:test"
import assert from "node:assert/strict"
import { fileURLToPath } from "node:url"
import { EngineSupervisor, type SupervisorOptions } from "../src/supervisor.ts"
import type { CheckParams } from "../src/types.ts"

const MOCK = fileURLToPath(new URL("./helpers/mock-engine.mjs", import.meta.url))
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

const budgets = {
  handshakeTimeoutMs: 1_000,
  checkTimeoutMs: 400,
  killGraceMs: 50,
  maxFrameBytes: 65_536,
  maxInFlight: 4,
  maxViolations: 3,
  maxViolationsWindowMs: 60_000,
  maxBackoffMs: 300,
  windowMs: 800,
  resetAfterMs: 60_000,
}

const makeSup = (scenario: string, over: Partial<SupervisorOptions["budgets"]> = {}): EngineSupervisor =>
  new EngineSupervisor(
    {
      command: [process.execPath, MOCK, scenario],
      protocolVersion: 1,
      sha256: null,
      cwd: null,
      clientVersion: "0.1.0-test",
      budgets: { ...budgets, ...over },
    },
    Date.now,
  )

const req = (raw: string): CheckParams => ({
  invocation: { id: `t:${raw}`, sessionID: "ses_t", hook: "permission.evaluate" },
  action: "shell",
  commands: [{ index: 0, raw, cwd: "/repo" }],
})

test("happy path: handshake then allow and deny verdicts", async () => {
  const sup = makeSup("ok")
  try {
    const ok = await sup.check(req("echo hi"))
    assert.equal(ok.ok, true)
    if (ok.ok) {
      assert.equal(ok.result.verdict, "allow")
      assert.equal(ok.result.invocationId, "t:echo hi")
    }
    const deny = await sup.check(req("rm -rf /tmp/x"))
    assert.equal(deny.ok, true)
    if (deny.ok) {
      assert.equal(deny.result.verdict, "deny")
      assert.equal(deny.result.message, "denied by mock")
    }
  } finally {
    sup.dispose()
  }
})

test("protocol version mismatch degrades and eventually marks unhealthy", async () => {
  const sup = makeSup("bad-version", { windowMs: 800 })
  try {
    let last = await sup.check(req("echo hi"))
    assert.equal(last.ok, false)
    const deadline = Date.now() + 8_000
    while (!(last.ok === false && last.reason === "unhealthy") && Date.now() < deadline) {
      await sleep(40)
      last = await sup.check(req("echo hi"))
    }
    assert.equal(last.ok, false)
    if (!last.ok) assert.equal(last.reason, "unhealthy")
  } finally {
    sup.dispose()
  }
})

test("check timeout degrades and kills the engine", async () => {
  const sup = makeSup("slow-check", { checkTimeoutMs: 150 })
  try {
    const r = await sup.check(req("echo hi"))
    assert.equal(r.ok, false)
    if (!r.ok) assert.equal(r.reason, "timeout")
    assert.equal(sup.currentState, "restarting")
  } finally {
    sup.dispose()
  }
})

test("engine crash on check rejects the invocation", async () => {
  const sup = makeSup("crash-on-check")
  try {
    const r = await sup.check(req("echo hi"))
    assert.equal(r.ok, false)
    if (!r.ok) assert.ok(["engine-restarting", "engine-exited", "timeout"].includes(r.reason))
  } finally {
    sup.dispose()
  }
})

test("garbage output is a protocol violation", async () => {
  const sup = makeSup("garbage", { checkTimeoutMs: 300 })
  try {
    const r = await sup.check(req("echo hi"))
    assert.equal(r.ok, false)
  } finally {
    sup.dispose()
  }
})

test("fatal engine error triggers long unhealthy cooldown", async () => {
  const sup = makeSup("fatal")
  try {
    const first = await sup.check(req("echo hi"))
    assert.equal(first.ok, false)
    if (!first.ok) assert.equal(first.reason, "engine-error")
    const second = await sup.check(req("echo hi"))
    assert.equal(second.ok, false)
    if (!second.ok) assert.equal(second.reason, "unhealthy")
  } finally {
    sup.dispose()
  }
})

test("dispose rejects in-flight checks", async () => {
  const sup = makeSup("slow-check", { checkTimeoutMs: 5_000 })
  try {
    const pending = sup.check(req("echo hi"))
    await sleep(50)
    sup.dispose()
    const r = await pending
    assert.equal(r.ok, false)
    if (!r.ok) assert.equal(r.reason, "disposed")
  } finally {
    sup.dispose()
  }
})
