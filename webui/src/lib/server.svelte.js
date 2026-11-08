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

// apiURL routes an /api/ path to the selected server.
export function apiURL(path) {
  const cur = servers.current
  if (!cur || cur === servers.local || !path.startsWith('/api/') || path.startsWith('/api/servers')) return path
  return '/s/' + encodeURIComponent(cur) + path
}
