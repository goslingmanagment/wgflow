// Person-level verdict aggregation, shared by the Clients route and the Срез
// drawer (they used to carry diverging copies of this).

// A person inherits the "most alive" verdict among their devices. `unknown`
// (the rollup DB was unavailable, so no verdict could be computed) deliberately
// outranks `silent`: unproven silence must never be presented as proven quiet.
export const VERDICT_ORDER = { active: 4, 'likely-background': 3, unknown: 2, silent: 1 }

export function aggVerdict(devices) {
  let best = null
  for (const d of devices) {
    if (!best || (VERDICT_ORDER[d.verdict?.status] || 0) > (VERDICT_ORDER[best.status] || 0)) best = d.verdict
  }
  return best
}

// Fallback person for a device the server didn't resolve one for: the name
// prefix before the first dash ("dima-phone" -> "dima").
export function personOf(name) {
  const i = (name || '').indexOf('-')
  return i > 0 ? name.slice(0, i) : name
}
