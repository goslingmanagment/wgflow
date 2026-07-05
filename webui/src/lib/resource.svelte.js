import { getJSON } from './format.js'

export function errorMessage(e) {
  return e?.message || String(e)
}

// createResource owns the load-on-tick lifecycle every route used to hand-roll.
// It fixes three related problems at once:
//   - a previous in-flight request is *aborted*, not just ignored, so a hung
//     backend can't pile up requests (the server is plain HTTP/1.1, Safari caps
//     us at 6 connections and one is permanently held by the SSE stream);
//   - a failed refresh after successful data marks the page `stale` instead of
//     blanking it — one bad 5s tick must never erase a screenful of good data;
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

  // Abort whatever is in flight when the owning component unmounts.
  $effect(() => () => ctrl?.abort())

  // urls: a single URL string, or an array fetched in parallel (data becomes an
  // array in the same order). Resolves true when this call's result was applied.
  async function run(urls) {
    ctrl?.abort()
    const c = (ctrl = new AbortController())
    const id = ++seq
    loading = true
    try {
      const value = Array.isArray(urls) ? await Promise.all(urls.map((u) => getJSON(u, c.signal))) : await getJSON(urls, c.signal)
      if (id !== seq) return false
      data = value
      err = null
      errStatus = null
      stale = false
      lastUpdatedAt = Date.now()
      return true
    } catch (e) {
      if (id !== seq) return false
      // Superseded/unmount aborts are not errors; timeouts arrive as TimeoutError.
      if (e?.name === 'AbortError') return false
      err = errorMessage(e)
      errStatus = e?.status ?? null
      stale = data != null
      return false
    } finally {
      if (id === seq) loading = false
    }
  }

  function load(urls) {
    lastUrls = urls
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
