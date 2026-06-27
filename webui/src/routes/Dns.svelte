<script>
  import { refresh, ui } from '../lib/store.svelte.js'
  import { dnsRcodeName, getJSON, hhmmssMSK } from '../lib/format.js'
  import Win from '../lib/Win.svelte'

  let data = $state(null)
  let err = $state(null)
  let qtype = $state('all')
  let errorsOnly = $state(false)
  let q = $state('')

  $effect(() => {
    const s = ui.since,
      tick = refresh.tick,
      t = qtype,
      e = errorsOnly,
      qq = q
    load(s, t, e, qq)
  })
  async function load(s, t, e, qq) {
    try {
      const u = new URLSearchParams({ since: s, limit: '120' })
      if (t !== 'all') u.set('qtype', t)
      if (e) u.set('errors', '1')
      if (qq) u.set('q', qq)
      data = await getJSON('/api/dns?' + u.toString())
      err = null
    } catch (e2) {
      err = e2.message
    }
  }
  const QT = ['all', 'A', 'AAAA', 'CNAME', 'HTTPS']
</script>

<div class="head"><h1 class="serif">DNS</h1><Win /></div>
<div class="filters">
  <select bind:value={qtype}>{#each QT as t}<option value={t}>{t === 'all' ? 'All types' : t}</option>{/each}</select>
  <button class="tgl" class:on={errorsOnly} onclick={() => (errorsOnly = !errorsOnly)}>errors only</button>
  <input placeholder="search query" bind:value={q} />
</div>

{#if err}<p class="err">Couldn't load DNS. ({err})</p>{:else if !data}<p class="dim">Loading…</p>{:else}
  <div class="bar">last {ui.since} · {data.records.length} shown · <span class="warn">{data.errors} DNS errors</span></div>
  <div class="card">
    <table>
      <thead><tr><th>Time МСК</th><th>Client</th><th>Query</th><th>Type</th><th>Code</th><th>Answer</th></tr></thead>
      <tbody>
        {#each data.records as r}
          <tr>
            <td class="mono dim">{hhmmssMSK(r.ts)}</td>
            <td>{r.client}</td>
            <td class="q">{r.query}</td>
            <td><span class="qt mono">{r.qtype}</span></td>
            <td class="mono" class:nx={r.rcode !== 0}>{dnsRcodeName(r.rcode)}</td>
            <td class="mono dim">{r.answers && r.answers[0] ? r.answers[0].value : '—'}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if data.records.length === 0}<p class="dim pad">No queries match.</p>{/if}
  </div>
{/if}

<style>
  .head { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
  h1 { font-size: 22px; font-weight: 500; margin: 0; }
  .filters { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
  select, input { background: var(--color-s1); border: 1px solid var(--color-border); border-radius: 7px; padding: 7px 10px; color: var(--color-text); }
  input { width: 170px; }
  .tgl { background: var(--color-s1); border: 1px solid var(--color-border); border-radius: 7px; padding: 7px 12px; color: var(--color-dim); cursor: pointer; font-size: 12px; }
  .tgl.on { background: color-mix(in srgb, var(--color-warn) 16%, transparent); color: var(--color-warn); border-color: transparent; }
  .bar { color: var(--color-muted); font-size: 12px; margin-bottom: 8px; }
  .warn { color: var(--color-warn); }
  .card { background: var(--color-s1); border: 1px solid var(--color-border); border-radius: 12px; overflow: hidden; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; table-layout: fixed; }
  th { text-align: left; color: var(--color-muted); font-weight: 400; font-size: 11px; padding: 9px 8px; border-bottom: 1px solid var(--color-border); }
  td { padding: 8px; border-bottom: 1px solid var(--color-border); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  tr:last-child td { border-bottom: 0; }
  .q { color: var(--color-text); }
  .qt { font-size: 10px; color: var(--color-dim); background: var(--color-s3); border-radius: 4px; padding: 1px 6px; }
  .nx { color: var(--color-warn); font-weight: 500; }
  .dim { color: var(--color-muted); }
  .err { color: var(--color-danger); }
  .pad { padding: 16px; }
  th:nth-child(1), td:nth-child(1) { width: 12%; }
  th:nth-child(2), td:nth-child(2) { width: 17%; }
  th:nth-child(4), td:nth-child(4) { width: 9%; }
  th:nth-child(5), td:nth-child(5) { width: 13%; }
  th:nth-child(6), td:nth-child(6) { width: 18%; }
</style>
