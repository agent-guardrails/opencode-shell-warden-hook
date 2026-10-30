import { test } from "node:test"
import assert from "node:assert/strict"
import { validateOptions } from "../src/config.ts"

const ABS = "/usr/local/bin/shell-warden"

test("missing engine.command is fatal", () => {
  const r = validateOptions({})
  assert.equal(r.ok, false)
  if (!r.ok) assert.match(r.reason, /engine\.command/)
})

test("relative engine.command[0] is fatal (invariant I2)", () => {
  const r = validateOptions({ engine: { command: ["warden", "serve"] } })
  assert.equal(r.ok, false)
  if (!r.ok) assert.match(r.reason, /absolute path/)
})

test("defaults apply for a valid absolute command", () => {
  const r = validateOptions({ engine: { command: [ABS, "serve"] } })
  assert.equal(r.ok, true)
  if (!r.ok) return
  assert.deepEqual(r.config.engine.command, [ABS, "serve"])
  assert.equal(r.config.budgets.checkTimeoutMs, 5000)
  assert.equal(r.config.onEngineError, "ask")
  assert.deepEqual(r.config.actions, ["shell"])
  assert.equal(r.config.actionsAll, false)
  assert.equal(r.config.cache.enabled, true)
  assert.equal(r.config.observeShell, false)
})

test("onEngineError allow is fatal (invariant I3)", () => {
  const r = validateOptions({ engine: { command: [ABS] }, onEngineError: "allow" })
  assert.equal(r.ok, false)
  if (!r.ok) assert.match(r.reason, /never valid/)
})

test("budgets clamp with warnings", () => {
  const warns: string[] = []
  const r = validateOptions({ engine: { command: [ABS] }, budgets: { checkTimeoutMs: 999_999 } }, (m) => warns.push(m))
  assert.equal(r.ok, true)
  if (!r.ok) return
  assert.equal(r.config.budgets.checkTimeoutMs, 30_000)
  assert.ok(warns.some((w) => w.includes("checkTimeoutMs")))
})

test("unknown keys are ignored with warning", () => {
  const warns: string[] = []
  const r = validateOptions({ engine: { command: [ABS] }, wat: 1 }, (m) => warns.push(m))
  assert.equal(r.ok, true)
  assert.ok(warns.some((w) => w.includes('"wat"')))
})

test("{env:NAME} substitution resolves and fails closed", () => {
  process.env.WARDEN_TEST_BIN = ABS
  const ok = validateOptions({ engine: { command: ["{env:WARDEN_TEST_BIN}"] } })
  assert.equal(ok.ok, true)
  if (ok.ok) assert.deepEqual(ok.config.engine.command, [ABS])
  delete process.env.WARDEN_TEST_BIN
  const bad = validateOptions({ engine: { command: ["{env:WARDEN_TEST_BIN}"] } })
  assert.equal(bad.ok, false)
})

test("actions filtering and wildcard", () => {
  const r = validateOptions({ engine: { command: [ABS] }, actions: ["shell", "nope", "*"] })
  assert.equal(r.ok, true)
  if (!r.ok) return
  assert.equal(r.config.actionsAll, true)
  assert.deepEqual(r.config.actions, ["*"])
  const r2 = validateOptions({ engine: { command: [ABS] }, actions: ["nope"] })
  assert.equal(r2.ok, true)
  if (r2.ok) assert.deepEqual(r2.config.actions, ["shell"])
})

test("enabled=false disables the plugin", () => {
  const r = validateOptions({ enabled: false, engine: { command: [ABS] } })
  assert.equal(r.ok, false)
  if (!r.ok) assert.match(r.reason, /disabled/)
})

test("sha256 must be 64 hex chars or null", () => {
  const bad = validateOptions({ engine: { command: [ABS], sha256: "zz" } })
  assert.equal(bad.ok, false)
  const good = validateOptions({ engine: { command: [ABS], sha256: "a".repeat(64) } })
  assert.equal(good.ok, true)
  if (good.ok) assert.equal(good.config.engine.sha256, "a".repeat(64))
})
