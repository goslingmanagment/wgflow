// debounced(() => someState, ms) -> { value }: `value` trails the source by
// `ms` of quiet. Used by the search boxes so every keystroke doesn't fire an
// /api request (the shared runner already prevents stale responses winning;
// this is purely about not issuing the requests at all).
export function debounced(get, ms = 300) {
  let value = $state(get())
  $effect(() => {
    const v = get()
    if (v === value) return
    const t = setTimeout(() => (value = v), ms)
    return () => clearTimeout(t)
  })
  return {
    get value() {
      return value
    },
  }
}
