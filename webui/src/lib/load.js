export function createLatestRunner() {
  let seq = 0

  return async function runLatest(work, onValue, onError) {
    const id = ++seq
    try {
      const value = await work()
      if (id !== seq) return false
      onValue(value)
      return true
    } catch (e) {
      if (id !== seq) return false
      onError(e)
      return true
    }
  }
}

export function errorMessage(e) {
  return e?.message || String(e)
}
