// Test-only checker stub — behaves per docs/spec/shell-warden/10-testing.md.
// Usage: node mock-checker.mjs --behavior '<json>'
//   { stdout?: string, exit?: number, sleepMs?: number }
// Reads one letter line from stdin (ignores its content), emits stdout, exits.

const argIndex = process.argv.indexOf("--behavior")
const def = argIndex === -1 ? {} : JSON.parse(process.argv[argIndex + 1] ?? "{}")
let buf = ""
process.stdin.setEncoding("utf8")
process.stdin.on("data", (c) => { buf += c })
process.stdin.on("end", () => {
  const run = () => {
    process.stdout.write(def.stdout ?? buf)
    process.exit(def.exit ?? 0)
  }
  if (def.sleepMs) setTimeout(run, def.sleepMs)
  else run()
})
