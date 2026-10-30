// Verdict cache — docs/policyd-plugin-design/03-shim.md §3.4
// Allow-only, TTL from the engine, size-bounded LRU. Denies are never cached.

export interface CacheEntry {
  verdict: "allow"
  message?: string
  expiresAt: number
}

export class VerdictCache {
  private readonly maxEntries: number
  private readonly clock: () => number
  private map = new Map<string, CacheEntry>()

  constructor(maxEntries: number, clock: () => number = Date.now) {
    this.maxEntries = maxEntries
    this.clock = clock
  }

  get(key: string): CacheEntry | null {
    const e = this.map.get(key)
    if (e === undefined) return null
    if (e.expiresAt <= this.clock()) {
      this.map.delete(key)
      return null
    }
    // LRU touch
    this.map.delete(key)
    this.map.set(key, e)
    return e
  }

  put(key: string, ttlMs: number, message?: string): void {
    if (ttlMs <= 0) return
    while (this.map.size >= this.maxEntries) {
      const oldest = this.map.keys().next()
      if (oldest.done === true) break
      this.map.delete(oldest.value)
    }
    this.map.set(key, { verdict: "allow", message, expiresAt: this.clock() + ttlMs })
  }

  invalidate(): void {
    this.map.clear()
  }
}
