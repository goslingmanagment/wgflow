export const ui = $state({ since: '15m' })

export function setSince(s) {
  ui.since = s
}
