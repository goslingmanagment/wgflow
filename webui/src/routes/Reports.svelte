<script>
  import { trackRefreshTick } from '../lib/store.svelte.js'
  import { getJSON, fmtBytes } from '../lib/format.js'
  import { createLatestRunner, errorMessage } from '../lib/load.js'
  import Icon from '../lib/Icon.svelte'

  const WINS = [
    ['1h', '1h'],
    ['6h', '6h'],
    ['24h', '24h'],
    ['168h', '7d'],
    ['720h', '30d'],
  ]
  let since = $state('24h')
  let data = $state(null)
  let err = $state(null)
  const runLatest = createLatestRunner()

  $effect(() => {
    trackRefreshTick()
    const s = since
    load(s)
  })
  async function load(s) {
    await runLatest(
      () => getJSON('/api/report?since=' + s),
      (next) => {
        data = next
        err = null
      },
      (e) => {
        err = errorMessage(e)
      },
    )
  }
  const cTotal = $derived((data?.by_client || []).reduce((a, r) => a + r.total, 0) || 1)
  const kTotal = $derived((data?.by_category || []).reduce((a, r) => a + r.total, 0) || 1)

  function exportCSV() {
    if (!data) return
    const lines = [['section', 'name', 'down_bytes', 'up_bytes', 'total_bytes']]
    data.by_client.forEach((r) => lines.push(['client', r.name, r.down, r.up, r.total]))
    data.by_category.forEach((r) => lines.push(['category', r.name, r.down, r.up, r.total]))
    const blob = new Blob([lines.map((l) => l.join(',')).join('\n')], { type: 'text/csv' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'wgflow-report-' + since + '.csv'
    a.click()
    URL.revokeObjectURL(a.href)
  }
</script>

<div class="head">
  <h1 class="serif">Report</h1>
  <div class="right">
    <div class="seg">{#each WINS as [v, l]}<button class:on={since === v} onclick={() => (since = v)}>{l}</button>{/each}</div>
    <button class="exp" onclick={exportCSV}><Icon name="download" size={14} /> CSV</button>
  </div>
</div>

{#if err}<p class="err">Couldn't load report. ({err})</p>{:else if !data}<p class="dim">Loading…</p>{:else}
  <div class="summ">Window <b>{WINS.find((w) => w[0] === since)?.[1]}</b> · rollup rows <b class="mono">{data.rollup_rows.toLocaleString()}</b></div>
  <div class="two">
    <div class="card">
      <h3 class="serif">By client</h3>
      <div class="tscroll">
        <table>
          <thead><tr><th>Client</th><th class="r">Down</th><th class="r">Up</th><th class="r">Total</th><th class="r">Share</th></tr></thead>
          <tbody>{#each data.by_client as r}<tr><td>{r.name}</td><td class="r mono">{fmtBytes(r.down)}</td><td class="r mono">{fmtBytes(r.up)}</td><td class="r mono">{fmtBytes(r.total)}</td><td class="r mono dim">{((r.total / cTotal) * 100).toFixed(0)}%</td></tr>{/each}</tbody>
        </table>
      </div>
    </div>
    <div class="card">
      <h3 class="serif">By category</h3>
      <div class="tscroll">
        <table>
          <thead><tr><th>Category</th><th class="r">Down</th><th class="r">Up</th><th class="r">Total</th><th class="r">Share</th></tr></thead>
          <tbody>{#each data.by_category as r}<tr><td>{r.name}</td><td class="r mono">{fmtBytes(r.down)}</td><td class="r mono">{fmtBytes(r.up)}</td><td class="r mono">{fmtBytes(r.total)}</td><td class="r mono dim">{((r.total / kTotal) * 100).toFixed(0)}%</td></tr>{/each}</tbody>
        </table>
      </div>
    </div>
  </div>
{/if}

<style>
  .head { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }
  h1 { font-size: 22px; font-weight: 500; margin: 0; }
  .right { display: flex; align-items: center; gap: 10px; }
  .seg { display: inline-flex; border: 1px solid var(--color-border); border-radius: 7px; overflow: hidden; }
  .seg button { background: transparent; border: 0; color: var(--color-dim); padding: 6px 11px; cursor: pointer; font-family: var(--font-mono); font-size: 12px; }
  .seg button.on { background: var(--color-accent-dim); color: var(--color-accent); }
  .exp { display: inline-flex; align-items: center; gap: 6px; background: var(--color-s1); border: 1px solid var(--color-border2); border-radius: 7px; padding: 6px 11px; color: var(--color-text); cursor: pointer; font-size: 12px; }
  .exp:hover { background: var(--color-s2); }
  .summ { color: var(--color-dim); font-size: 13px; margin-bottom: 12px; }
  .summ b { color: var(--color-text); font-weight: 500; }
  .two { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  @media (max-width: 760px) { .two { grid-template-columns: 1fr; } }
  .card { background: var(--color-s1); border: 1px solid var(--color-border); border-radius: 12px; padding: 14px 16px; min-width: 0; }
  h3 { font-size: 16px; font-weight: 500; margin: 0 0 10px; }
  .tscroll { overflow-x: auto; -webkit-overflow-scrolling: touch; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th { text-align: left; color: var(--color-muted); font-weight: 400; font-size: 11px; padding: 6px 6px 6px 0; border-bottom: 1px solid var(--color-border); }
  td { padding: 7px 6px 7px 0; border-bottom: 1px solid var(--color-border); white-space: nowrap; }
  tr:last-child td { border-bottom: 0; }
  .r { text-align: right; }
  .dim { color: var(--color-muted); }
  .err { color: var(--color-danger); }
  @media (max-width: 640px) { table { min-width: 420px; } }
</style>
