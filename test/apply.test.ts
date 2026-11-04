import { test } from "node:test"
import assert from "node:assert/strict"
import { buildLetter, cacheKey, invocationIdOf, replyDecision, type AskData } from "../src/apply.ts"

const data = (over: Partial<AskData> = {}): AskData => ({
  id: "per_1",
  sessionID: "ses_1",
  action: "shell",
  resources: ["git status", "npm test"],
  source: { type: "tool", messageID: "msg_1", id: "call_1" },
  ...over,
})

test("invocationIdOf uses the request source ids", () => {
  assert.equal(invocationIdOf(data().source, "ses_1", "shell"), "msg_1:call_1")
  assert.match(invocationIdOf(undefined, "ses_1", "shell"), /^anon:/)
})

test("buildLetter matches 02-letter-verdict §2.2 with no v1.x extras", () => {
  const l = buildLetter({ data: data(), invocationId: "msg_1:call_1", projectDir: "/work/repo" })
  assert.deepEqual(l, {
    version: 1,
    invocation: { id: "msg_1:call_1", sessionID: "ses_1", projectDir: "/work/repo" },
    action: "shell",
    commands: [
      { index: 0, raw: "git status", cwd: "/work/repo" },
      { index: 1, raw: "npm test", cwd: "/work/repo" },
    ],
  })
  // v1.x protocol fields must NOT leak into the letter
  assert.equal(Object.keys(l.invocation).includes("hook"), false)
  assert.equal(Object.keys(l.invocation).includes("startedAt"), false)
})

test("buildLetter rejects an empty projectDir — the engine invalidates letters with empty commands[].cwd", () => {
  assert.throws(
    () => buildLetter({ data: data(), invocationId: "msg_1:call_1", projectDir: "" }),
    /projectDir is required/,
  )
})

test("buildLetter without source uses the anon invocation id", () => {
  const l = buildLetter({ data: data({ source: undefined }), invocationId: "anon:ses_1:shell", projectDir: "/work/repo" })
  assert.equal(l.invocation.id, "anon:ses_1:shell")
  assert.equal(l.commands[0]?.cwd, "/work/repo")
})

test("cacheKey is stable and sensitive to inputs", () => {
  const k1 = cacheKey("shell", ["git status"], "/repo", "build")
  assert.equal(k1, cacheKey("shell", ["git status"], "/repo", "build"))
  assert.notEqual(k1, cacheKey("shell", ["git push"], "/repo", "build"))
})

test("replyDecision: allow→once, deny→reject, ask→null", () => {
  assert.equal(replyDecision("allow"), "once")
  assert.equal(replyDecision("deny"), "reject")
  assert.equal(replyDecision("ask"), null)
})
