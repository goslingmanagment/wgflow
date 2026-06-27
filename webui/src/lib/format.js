export async function getJSON(url) {
  const r = await fetch(url)
  if (!r.ok) throw new Error('HTTP ' + r.status)
  return r.json()
}

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
export function fmtBytes(v) {
  let f = Number(v) || 0
  let i = 0
  while (f >= 1024 && i < UNITS.length - 1) {
    f /= 1024
    i++
  }
  return (i === 0 ? f.toFixed(0) : f.toFixed(f < 10 ? 2 : 1)) + ' ' + UNITS[i]
}

export function fmtShort(v) {
  let f = Number(v) || 0
  const u = ['', 'K', 'M', 'G', 'T']
  let i = 0
  while (f >= 1000 && i < u.length - 1) {
    f /= 1000
    i++
  }
  return (i === 0 ? f.toFixed(0) : f.toFixed(1)) + u[i]
}

// average Mbit/s over a window of `seconds`
export function fmtRate(bytes, seconds) {
  if (!seconds) return '0'
  const mbit = (Number(bytes) * 8) / seconds / 1e6
  return mbit >= 100 ? mbit.toFixed(0) : mbit.toFixed(1)
}

export function sinceSeconds(s) {
  const m = /^(\d+)([smhd])$/.exec(s || '15m')
  if (!m) return 900
  const n = +m[1]
  return n * { s: 1, m: 60, h: 3600, d: 86400 }[m[2]]
}

export function ago(ts) {
  const d = (Date.now() - new Date(ts).getTime()) / 1000
  if (d < 0) return 'now'
  if (d < 5) return 'now'
  if (d < 60) return Math.floor(d) + 's'
  if (d < 3600) return Math.floor(d / 60) + 'm'
  if (d < 86400) return Math.floor(d / 3600) + 'h'
  return Math.floor(d / 86400) + 'd'
}

export function uptime(startedAt) {
  let d = (Date.now() - new Date(startedAt).getTime()) / 1000
  if (!(d > 0)) return '—'
  const days = Math.floor(d / 86400)
  const h = Math.floor((d % 86400) / 3600)
  if (days > 0) return days + 'd ' + h + 'h'
  const m = Math.floor((d % 3600) / 60)
  return h + 'h ' + m + 'm'
}

// Moscow wall-clock formatters. The owner reads every window "at HH:MM МСК",
// so all absolute times render in Europe/Moscow regardless of the viewer's TZ.
// Moscow is UTC+3 year-round (no DST since 2014), but we resolve it through the
// tz database via Intl rather than hardcoding +3.
const _mskHM = new Intl.DateTimeFormat('ru-RU', { timeZone: 'Europe/Moscow', hour: '2-digit', minute: '2-digit' })
const _mskHMS = new Intl.DateTimeFormat('ru-RU', { timeZone: 'Europe/Moscow', hour: '2-digit', minute: '2-digit', second: '2-digit' })
const _mskHour = new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/Moscow', hour: 'numeric', hour12: false })

// Accept a Date, unix-seconds number (the series/chart convention), or ISO string.
function toDate(ts) {
  if (ts instanceof Date) return ts
  if (typeof ts === 'number') return new Date(ts * 1000)
  return new Date(ts)
}
export function hhmmMSK(ts) {
  return _mskHM.format(toDate(ts))
}
export function hhmmssMSK(ts) {
  return _mskHMS.format(toDate(ts))
}
// MSK hour 0–23 (handles the Intl "24" midnight quirk).
export function hourMSK(d = new Date()) {
  return Number(_mskHour.format(d)) % 24
}

export function dnsRcodeName(code) {
  const names = {
    0: 'NOERROR',
    1: 'FORMERR',
    2: 'SERVFAIL',
    3: 'NXDOMAIN',
    4: 'NOTIMP',
    5: 'REFUSED',
    6: 'YXDOMAIN',
    7: 'YXRRSET',
    8: 'NXRRSET',
    9: 'NOTAUTH',
    10: 'NOTZONE',
  }
  return names[Number(code)] || 'RCODE ' + code
}

export const CAT_COLORS = {
  google: '#4493f8',
  meta: '#7f77dd',
  // apple: silver/slate-blue, distinct from both `other` grey and `google` blue
  // (was #9aa7b4, a near-twin of `other`).
  apple: '#9fb8d4',
  telegram: '#1baf7a',
  // yandex: crimson, off the coral brand hue (#e06a3f) it used to collide with.
  yandex: '#e5263b',
  twitch: '#9146ff',
  cloudflare: '#f38020',
  aws: '#ff9900',
  discord: '#5865f2',
  games: '#e3b341',
  p2p: '#3fb950',
  dns: '#d29922',
  wildberries: '#d4537e',
  fansly: '#f85149',
  other: '#6b7785',
}
export function catColor(c) {
  return CAT_COLORS[c] || '#6b7785'
}

// Verdict status -> dot color. active = the coral active/brand hue; likely-bg =
// warn amber (deliberately not danger-red); silent = muted grey.
export const VERDICT_COLORS = {
  active: 'var(--color-coral)',
  'likely-background': 'var(--color-warn)',
  silent: 'var(--color-muted)',
}
export function verdictColor(status) {
  return VERDICT_COLORS[status] || 'var(--color-muted)'
}

export const WINDOWS = [
  { value: '5m', label: '5m' },
  { value: '15m', label: '15m' },
  { value: '30m', label: '30m' },
  { value: '1h', label: '1h' },
  { value: '3h', label: '3h' },
  { value: '6h', label: '6h' },
  { value: '12h', label: '12h' },
  { value: '24h', label: '24h' },
]
