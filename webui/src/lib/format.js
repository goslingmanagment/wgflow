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
  apple: '#9aa7b4',
  telegram: '#1baf7a',
  yandex: '#eb6834',
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
