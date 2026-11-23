// Integration surface: permission.asked -> real Rust checker -> v3 validation
// -> actual hook reply/silence. The harness never executes the shell letters.
import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { isAbsolute, join } from "node:path"
import plugin from "../src/index.ts"

const binary = process.env.SHELL_WARDEN_TEST_BINARY

test("parameter permissions complete a real-checker hook round trip", {
  skip: binary === undefined ? "set SHELL_WARDEN_TEST_BINARY to the paired v3 checker" : false,
  timeout: 20_000,
}, async () => {
  assert.ok(binary && isAbsolute(binary))
  const temporary = mkdtempSync(join(process.cwd(), ".parameter-round-trip-"))
  let teardown: (() => void) | undefined
  try {
    const allow = {
      id: "allow", action: "allow", expansions: { arguments: ["HOME"] },
      match: {
        arguments: { prefix: [], remainder: { each: { any: true } } },
        options: { none: true }, environment: { none: true },
        paths: { all: [{ coordinate: { argument: { index: 0, remainder: true } }, any: true }] },
        facts: { none: true }, nestedParts: { none: true },
      },
    }
    const profile = (name: string, restrictive: boolean) => ({
      id: name, executables: [name], options: {}, analyzer: "generic-v1",
      pathSources: [{ argument: { index: 0, remainder: true } }],
      // This peer fails parameter coverage, but must not veto a qualified allow.
      rules: [{ ...allow, id: "no-grant", expansions: { arguments: [] } }, allow, ...(restrictive ? [{
        id: "secret", action: "deny", message: "Restricted path.",
        match: { paths: { any: [{ coordinate: { argument: { index: 0, remainder: true } }, within: "/secret" }] } },
      }] : [])],
    })
    const configPath = join(temporary, "policy.json")
    writeFileSync(configPath, JSON.stringify({
      version: 3, defaults: { action: "ask", redirectPolicy: "none" },
      redirectPolicies: { none: { redirects: { none: true }, paths: { none: true } } },
      profiles: [profile("ls", false), profile("cat", true)],
    }))
    const commands = [
      'ls -- "$HOME"', 'ls "$HOME"', 'cat -- "$HOME"', "cat -- /public", "cat -- /secret",
    ]
    const replies: Array<{ requestID: string; decision: string; message?: string }> = []
    let markCompleted!: () => void
    const completed = new Promise<void>((resolve) => { markCompleted = resolve })
    const ctx = {
      options: {
        checker: { command: [binary, "--config", configPath], sha256: null },
        onCheckerError: "deny", cache: { enabled: false }, asConfig: { observeShell: false },
        logLevel: "error",
      },
      location: { directory: "/repo" },
      event: {
        subscribe: () => (async function* () {
          for (const [i, raw] of commands.entries()) {
            yield {
              type: "permission.asked", location: { directory: "/repo" },
              data: {
                id: `request-${i}`, sessionID: "round-trip", action: "shell", resources: [raw],
                source: { type: "tool", messageID: "round-trip", id: `call-${i}` },
              },
            }
          }
          markCompleted()
        })(),
      },
      permission: { reply: async (reply: { requestID: string; decision: string }) => { replies.push(reply) } },
    }
    const definition = plugin as unknown as { setup(ctx: unknown): Promise<(() => void) | undefined> }
    teardown = await definition.setup(ctx)
    assert.equal(typeof teardown, "function", "hook setup must succeed")
    await completed
    assert.deepEqual(replies.map(({ requestID, decision }) => ({ requestID, decision })), [
      { requestID: "request-0", decision: "once" },
      { requestID: "request-3", decision: "once" },
      { requestID: "request-4", decision: "reject" },
    ])
    assert.equal(replies[2]?.message, "Restricted path.")
  } finally {
    teardown?.()
    rmSync(temporary, { recursive: true, force: true })
  }
})
