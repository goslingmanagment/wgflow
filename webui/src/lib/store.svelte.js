export const ui = $state({ since: '15m', group: 'person' })

export function setSince(s) {
  ui.since = s
}

// --- Logger health verdict -------------------------------------------------
// One honest signal, shared by every status chip. It must never look healthier
// than the logger actually is, so it folds in two independent freshness checks:
//   - the web SSE stream (are we still receiving events at all?)         -> down
//   - the capture's stats.json heartbeat (is the logger still writing?)  -> stale
// A dead capture behind a live web server reads as "stale" (silence NOT
// confirmed), never as quiet — see the honesty rules in docs/uiux-roadmap.md §6.

const SSE_DEAD_MS = 6_000 // ~3 missed 2s stream ticks => web stream is down
const CAPTURE_STALE_MS = 90_000 // 3x the 30s stats write cadence => logger stalled

export const health = $state({
  status: 'down', // 'live' | 'stale' | 'down'
  mbit: null, // current throughput, only when live
  detail: 'ожидание данных…', // human reason, shown on hover and copied into verdicts
  stats: null, // last RuntimeStats payload
})

let lastEventAt = 0

export function onStats(payload) {
  health.stats = payload
  lastEventAt = Date.now()
  refreshHealth()
}

export function onStreamError() {
  // Don't blank the data here; let the freshness math below decide the verdict
  // so a brief blip doesn't flap the pill.
  refreshHealth()
}

const secs = (ms) => Math.max(0, Math.round(ms / 1000))

export function refreshHealth() {
  const now = Date.now()
  const s = health.stats
  if (!s || !lastEventAt) {
    health.status = 'down'
    health.mbit = null
    health.detail = 'нет связи с веб-потоком'
    return
  }
  const sseAge = now - lastEventAt
  if (sseAge > SSE_DEAD_MS) {
    health.status = 'down'
    health.mbit = null
    health.detail = `веб-поток прерван ${secs(sseAge)}с назад — данные не обновляются`
    return
  }
  const updAge = now - new Date(s.updated_at).getTime()
  const flushAge = now - new Date(s.last_flush_at).getTime()
  if (updAge > CAPTURE_STALE_MS) {
    health.status = 'stale'
    health.mbit = null
    health.detail = `тишина не подтверждена — логгер не обновлялся ${secs(updAge)}с (флаш ${secs(flushAge)}с назад)`
    return
  }
  health.status = 'live'
  health.mbit = (Number(s.bit_rate_per_second) || 0) / 1e6
  health.detail = `логгер исправен · обновлён ${secs(updAge)}с назад · флаш ${secs(flushAge)}с назад`
}
