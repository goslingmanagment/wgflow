// Server switcher. The panel lists its own logger plus the --remote servers it
// proxies (/api/servers); API calls for a remote go to /s/<name>/api/…. An old
// backend without /api/servers simply stays single-server.

const SERVER_KEY = 'wgflow.server'

function storage() {
  try {
    return typeof localStorage === 'undefined' ? null : localStorage
  } catch {
    return null
  }
}

function readSaved() {
  try {
    return storage()?.getItem(SERVER_KEY) || ''
  } catch {
    return ''
  }
}

export const servers = $state({ list: [], current: '', local: '' })

export async function loadServers() {
  let list = []
  try {
    const r = await fetch('/api/servers', { signal: AbortSignal.timeout?.(10_000) })
    if (r.ok) list = (await r.json()).servers || []
  } catch {}
  servers.list = list
  servers.local = list.find((s) => s.local)?.name || ''
  const saved = readSaved()
  // A panel-only host has no local logger: start on the first remote.
  servers.current = list.some((s) => s.name === saved) ? saved : servers.local || list[0]?.name || ''
}

export function setServer(name) {
  if (!servers.list.some((s) => s.name === name) || servers.current === name) return
  servers.current = name
  try {
    storage()?.setItem(SERVER_KEY, name)
  } catch {}
}

function serverPath(name, path) {
  if (!name || name === servers.local) return path
  return '/s/' + encodeURIComponent(name) + path
}

// onServer pins an /api/ path to one server regardless of the selection
// ('@name/api/…'). It stays a plain string so equal requests still compare
// equal (resource coalescing), and apiURL resolves it at fetch time.
export function onServer(name, path) {
  return '@' + encodeURIComponent(name) + path
}

// clientHref links a device's detail page. With several servers the link pins
// the server (#/clients/<name>/<server>): the same device name can exist on
// two servers, and back/forward, a new tab or a bookmark must reopen this one
// even after the header selection moved. App applies the pinned server.
export function clientHref(name, server = servers.current) {
  const base = '#/clients/' + encodeURIComponent(name)
  return server && servers.list.length > 1 ? base + '/' + encodeURIComponent(server) : base
}

// apiURL routes an /api/ path to the selected server (or to the server an
// onServer path names).
export function apiURL(path) {
  if (path.startsWith('@')) {
    const i = path.indexOf('/')
    return serverPath(decodeURIComponent(path.slice(1, i)), path.slice(i))
  }
  if (!path.startsWith('/api/') || path.startsWith('/api/servers')) return path
  return serverPath(servers.current, path)
}
