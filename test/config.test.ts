import { test } from "node:test"
import assert from "node:assert/strict"
import { validateOptions } from "../src/config.ts"

test("defaults: minimal valid options", () => {
  const r = validateOptions({ checker: { command: ["/usr/local/bin/shell-warden"] } })
  assert.equal(r.ok, true)
  if (!r.ok) return
  assert.equal(r.config.enabled, true)
  assert.deepEqual(r.config.checker, { command: ["/usr/local/bin/shell-warden"], sha256: null })
  assert.equal(r.config.budgets.checkTimeoutMs, 2_000)
  assert.equal(r.config.budgets.killGraceMs, 250)
  assert.equal(r.config.budgets.maxRequestCommands, 32)
  assert.equal(r.config.budgets.maxConcurrentSpawns, 8)
  assert.equal(r.config.onCheckerError, "ask")
  assert.deepEqual(r.config.actions, ["shell"])
  assert.equal(r.config.actionsAll, false)
  assert.deepEqual(r.config.cache, { enabled: true, maxEntries: 1_024, ttlMs: 0 })
  assert.deepEqual(r.config.rejectBudget, { maxRejections: 3, windowMs: 1_800_000 })
  assert.deepEqual(r.config.asConfig, { observeShell: false })
  assert.equal(r.config.logLevel, "warn")
})

test("checker.command must be a non-empty string array (fatal)", () => {
  assert.equal(validateOptions({ checker: { command: "x" } }).ok, false)
  assert.equal(validateOptions({ checker: { command: [] } }).ok, false)
  assert.equal(validateOptions({ checker: { command: [1, 2] } }).ok, false)
})

test("checker.command[0] must be absolute (fatal)", () => {
  const r = validateOptions({ checker: { command: ["shell-warden"] } })
  assert.equal(r.ok, false)
  if (!r.ok) assert.match(r.reason, /absolute/)
})

test("{env:NAME} substitution resolves; unresolved is fatal (I2)", () => {
  const r = validateOptions({ checker: { command: ["{env:HOME}", "check"] } })
  assert.equal(r.ok, true)
  if (r.ok) assert.equal(r.config.checker.command[0], process.env.HOME)
  const bad = validateOptions({ checker: { command: ["{env:SW_NO_SUCH_VAR_ZZ}", "check"] } })
  assert.equal(bad.ok, false)
})

test("sha256 must be null or 64 hex chars (fatal)", () => {
  assert.equal(validateOptions({ checker: { command: ["/x"], sha256: "abc" } }).ok, false)
  const r = validateOptions({ checker: { command: ["/x"], sha256: "a".repeat(64) } })
  assert.equal(r.ok, true)
})

test("onCheckerError 'allow' is rejected (I3)", () => {
  const r = validateOptions({ checker: { command: ["/x"] }, onCheckerError: "allow" })
  assert.equal(r.ok, false)
  if (!r.ok) assert.match(r.reason, /never 'allow'/)
  assert.equal(validateOptions({ checker: { command: ["/x"] }, onCheckerError: "deny" }).ok, true)
})

test("budgets are clamped with warnings", () => {
  const r = validateOptions({ checker: { command: ["/x"] }, budgets: { checkTimeoutMs: 5, maxRequestCommands: 999, killGraceMs: "no" } })
  assert.equal(r.ok, true)
  if (!r.ok) return
  assert.equal(r.config.budgets.checkTimeoutMs, 100)
  assert.equal(r.config.budgets.maxRequestCommands, 128)
  assert.equal(r.config.budgets.killGraceMs, 250)
  assert.ok(r.warns.some((w: string) => w.includes("checkTimeoutMs")))
})

test("unknown keys are ignored with a warning (§4.3)", () => {
  const r = validateOptions({ legacy: true, checker: { command: ["/x"], protocolVersion: 3 } })
  assert.equal(r.ok, true)
  if (!r.ok) return
  assert.ok(r.warns.some((w: string) => w.includes('"legacy"')))
  assert.ok(r.warns.some((w: string) => w.includes('"protocolVersion"')))
})

test("actions '*': actionsAll with '*' filtered out", () => {
  const r = validateOptions({ checker: { command: ["/x"] }, actions: ["*", "shell"] })
  const r2 = validateOptions({ checker: { command: ["/x"] }, actions: "*" })
  if (!r.ok || !r2.ok) return assert.fail("expected ok")
  assert.equal(r.config.actionsAll, true)
  assert.deepEqual(r.config.actions, ["shell"])
  assert.equal(r2.config.actionsAll, true)
  assert.deepEqual(r2.config.actions, ["shell"])
})

test("debug.dir must be absolute", () => {
  const r = validateOptions({ checker: { command: ["/x"] }, debug: { enabled: true, dir: "relative/dir" } })
  assert.equal(r.ok, true)
  if (r.ok) assert.equal(r.config.debug.dir, null)
  assert.ok(r.warns.some((w: string) => w.includes("debug.dir")))
})

test("enabled:false disables the plugin", () => {
  const r = validateOptions({ checker: { command: ["/x"] }, enabled: false })
  assert.equal(r.ok, true)
  if (r.ok) assert.equal(r.config.enabled, false)
})
