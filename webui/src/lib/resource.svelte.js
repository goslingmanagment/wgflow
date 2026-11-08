import { getJSON } from './format.js'

export function errorMessage(e) {
  return e?.message || String(e)
}

// createResource owns the load-on-tick lifecycle every route used to hand-roll.
// It fixes three related problems at once:
//   - a repeated poll for the same URL coalesces with the request already in
//     flight, while a real URL change aborts the obsolete request immediately;
//     this keeps polling from amplifying a slow backend without delaying filter
//     or time-window changes;
//   - a failed refresh after successful data marks the page `stale` instead of
//     blanking it — one bad refresh must never erase a screenful of good data;
//   - `err` therefore only means "no data at all" (the true can't-load case).
export function createResource() {
  let data = $state(null)
  let err = $state(null) // message of the last failed load (null after a success)
  let errStatus = $state(null) // HTTP status of the last failure, when known
  let stale = $state(false) // data is present but the latest refresh failed
  let loading = $state(false)
  let lastUpdatedAt = $state(null) // ms timestamp of the last successful load

  let ctrl = null
  let seq = 0
  let lastUrls = null
  let activeUrls = null
  let inFlight = null

  const copyUrls = (urls) => (Array.isArray(urls) ? [...urls] : urls)
  const sameUrls = (a, b) => {
    if (!Array.isArray(a) || !Array.isArray(b)) return a === b
    return a.length === b.length && a.every((url, i) => url === b[i])
  }

  // Abort whatever is in flight when the owning component unmounts.
  $effect(() => () => ctrl?.abort())

  // urls: a single URL string, or an array fetched in parallel (data becomes an
  // array in the same order). Resolves true when this call's result was applied.
  function run(urls) {
    // A refresh tick while this exact request is still running should wait for
    // that work, not abort it and start the same expensive scan again. A changed
    // URL (window/filter/route input) is different: its old response is obsolete.
    if (inFlight && sameUrls(activeUrls, urls)) return inFlight

    ctrl?.abort()
    const c = (ctrl = new AbortController())
    const requestUrls = copyUrls(urls)
    activeUrls = requestUrls
    const id = ++seq
    loading = true
    const request = (async () => {
      try {
        const value = Array.isArray(requestUrls)
          ? await Promise.all(requestUrls.map((u) => getJSON(u, c.signal)))
          : await getJSON(requestUrls, c.signal)
        if (id !== seq) return false
        data = value
        err = null
        errStatus = null
        stale = false
        lastUpdatedAt = Date.now()
        return true
      } catch (e) {
        // Promise.all rejects on the first failed member. Abort the shared
        // controller so its still-running siblings cannot outlive this resource
        // request and overlap the next refresh/window selection.
        c.abort()
        if (id !== seq) return false
        // Superseded/unmount aborts are not errors; timeouts arrive as TimeoutError.
        if (e?.name === 'AbortError') return false
        err = errorMessage(e)
        errStatus = e?.status ?? null
        stale = data != null
        return false
      } finally {
        if (id === seq) {
          loading = false
          ctrl = null
          activeUrls = null
          inFlight = null
        }
      }
    })()
    inFlight = request
    return request
  }

  function load(urls) {
    lastUrls = copyUrls(urls)
    return run(urls)
  }

  function reload() {
    return lastUrls != null ? run(lastUrls) : Promise.resolve(false)
  }

  // Blank everything (e.g. the Срез window changed and the old text must not
  // linger under the new label). The next load starts from the clean state.
  function reset() {
    seq++ // orphan any in-flight request
    ctrl?.abort()
    ctrl = null
    activeUrls = null
    inFlight = null
    data = null
    err = null
    errStatus = null
    stale = false
    loading = false
    lastUpdatedAt = null
  }

  return {
    get data() {
      return data
    },
    get err() {
      return err
    },
    get errStatus() {
      return errStatus
    },
    get stale() {
      return stale
    },
    get loading() {
      return loading
    },
    get lastUpdatedAt() {
      return lastUpdatedAt
    },
    load,
    reload,
    reset,
  }
}
