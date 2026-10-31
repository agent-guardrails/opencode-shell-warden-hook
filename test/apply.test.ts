import { test } from "node:test"
import assert from "node:assert/strict"
import { buildCheckRequest, cacheKey, InvocationRegistry, invocationIdOf, applyToEvent } from "../src/apply.ts"
import type { PermissionEvaluation } from "../src/types.ts"

const ev = (over: Partial<PermissionEvaluation> = {}): PermissionEvaluation => ({
  sessionID: "ses_1",
  action: "shell",
  resources: ["git status", "npm test"],
  effect: "ask",
  source: { type: "tool", messageID: "msg_1", id: "call_1" },
  ...over,
})

test("invocationIdOf uses source ids when present", () => {
  assert.equal(invocationIdOf(ev()), "msg_1:call_1")
  assert.match(invocationIdOf(ev({ source: undefined })), /^anon:/)
})

test("cacheKey is stable and sensitive to inputs", () => {
  const k1 = cacheKey("shell", ["git status"], "/repo", "build")
  const k2 = cacheKey("shell", ["git status"], "/repo", "build")
  assert.equal(k1, k2)
  assert.notEqual(k1, cacheKey("shell", ["git status"], "/repo", "plan"))
  assert.notEqual(k1, cacheKey("shell", ["git push"], "/repo", "build"))
})

test("buildCheckRequest maps the evaluate event", () => {
  const req = buildCheckRequest({ ev: ev(), invocationId: "msg_1:call_1", cwd: "/repo" })
  assert.equal(req.invocation.id, "msg_1:call_1")
  assert.equal(req.invocation.sessionID, "ses_1")
  assert.equal(req.invocation.hook, "permission.evaluate")
  assert.equal(req.action, "shell")
  assert.deepEqual(req.commands, [
    { index: 0, raw: "git status", cwd: "/repo" },
    { index: 1, raw: "npm test", cwd: "/repo" },
  ])
})

test("applyToEvent never loosens (invariant I5)", () => {
  const e = ev({ effect: "deny" })
  assert.equal(applyToEvent(e, "allow", "nope"), false)
  assert.equal(e.effect, "deny")
  assert.equal(e.message, undefined)
})

test("applyToEvent: engine verdict replaces the accumulated effect (v1.1)", () => {
  // The engine is the policy authority: it may automate an ask into an allow.
  const e = ev({ effect: "ask" })
  assert.equal(applyToEvent(e, "allow", "engine allows"), true)
  assert.equal(e.effect, "allow")
  assert.equal(e.message, "engine allows")
  // …and tighten back up if the engine asks/denies later
  assert.equal(applyToEvent(e, "deny", "engine denies"), true)
  assert.equal(e.effect, "deny")
})

test("applyToEvent: never loosens an existing deny (v1.1 guard)", () => {
  const e = ev({ effect: "deny" })
  assert.equal(applyToEvent(e, "allow", "nope"), false)
  assert.equal(applyToEvent(e, "ask", "nope"), false)
  assert.equal(e.effect, "deny")
  // same verdict → no change
  assert.equal(applyToEvent(e, "deny", "refined reason"), true)
  assert.equal(e.effect, "deny")
  assert.equal(e.message, "refined reason")
})

test("InvocationRegistry remembers and evicts oldest", () => {
  const r = new InvocationRegistry(2)
  r.remember("i1", "k1")
  r.remember("i2", "k2")
  r.remember("i3", "k3")
  assert.equal(r.keyFor("i1"), undefined)
  assert.equal(r.keyFor("i2"), "k2")
  assert.equal(r.keyFor("i3"), "k3")
})
