<script>
  import { refresh, ui } from '../lib/store.svelte.js'
  import { getJSON, fmtBytes, catColor } from '../lib/format.js'
  import Win from '../lib/Win.svelte'

  let data = $state(null)
  let err = $state(null)
  let cat = $state('all')
  let proto = $state('all')
  let q = $state('')

  $effect(() => {
    const s = ui.since,
      tick = refresh.tick,
      c = cat,
      p = proto,
      qq = q
    load(s, c, p, qq)
  })
  async function load(s, c, p, qq) {
    try {
      const u = new URLSearchParams({ since: s, limit: '60' })
      if (c !== 'all') u.set('category', c)
      if (p !== 'all') u.set('proto', p)
      if (qq) u.set('q', qq)
      data = await getJSON('/api/traffic?' + u.toString())
      err = null
    } catch (e) {
      err = e.message
    }
  }
  const CATS = ['all', 'google', 'meta', 'apple', 'telegram', 'yandex', 'twitch', 'cloudflare', 'aws', 'discord', 'games', 'p2p', 'dns', 'other']
</script>

<div class="head"><h1 class="serif">Traffic</h1><Win /></div>
<div class="filters">
  <select bind:value={cat}>{#each CATS as c}<option value={c}>{c === 'all' ? 'All categories' : c}</option>{/each}</select>
  <div class="seg">{#each ['all', 'tcp', 'udp'] as p}<button class:on={proto === p} onclick={() => (proto = p)}>{p}</button>{/each}</div>
  <input placeholder="search target" bind:value={q} />
</div>

{#if err}<p class="err">Couldn't load traffic. ({err})</p>{:else if !data}<p class="dim">Loading…</p>{:else}
  <div class="bar">last {ui.since} · {data.rows.length} of {data.total} flows · sorted by total</div>
  <div class="card">
    <table>
      <thead><tr><th>Client</th><th>Category</th><th>Target</th><th>Proto</th><th class="r">Down</th><th class="r">Up</th><th class="r">Total</th></tr></thead>
      <tbody>
        {#each data.rows as f}
          <tr>
            <td><a href="#/clients/{encodeURIComponent(f.client)}">{f.client}</a></td>
            <td><span class="cd" style="background:{catColor(f.category)}"></span>{f.category}</td>
            <td class="tgt">{f.target}</td>
            <td class="mono dim">{f.proto}:{f.port}</td>
            <td class="r mono">{fmtBytes(f.down)}</td>
            <td class="r mono">{fmtBytes(f.up)}</td>
            <td class="r mono">{fmtBytes(f.total)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if data.rows.length === 0}<p class="dim pad">No flows match these filters.</p>{/if}
  </div>
{/if}

<style>
  .head { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
  h1 { font-size: 22px; font-weight: 500; margin: 0; }
  .filters { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
  select, input { background: var(--color-s1); border: 1px solid var(--color-border); border-radius: 7px; padding: 7px 10px; color: var(--color-text); }
  input { width: 160px; }
  .seg { display: inline-flex; border: 1px solid var(--color-border); border-radius: 7px; overflow: hidden; }
  .seg button { background: transparent; border: 0; color: var(--color-dim); padding: 7px 12px; cursor: pointer; font-family: var(--font-mono); font-size: 12px; }
  .seg button.on { background: var(--color-accent-dim); color: var(--color-accent); }
  .bar { color: var(--color-muted); font-size: 12px; margin-bottom: 8px; }
  .card { background: var(--color-s1); border: 1px solid var(--color-border); border-radius: 12px; overflow: hidden; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; table-layout: fixed; }
  th { text-align: left; color: var(--color-muted); font-weight: 400; font-size: 11px; padding: 9px 8px; border-bottom: 1px solid var(--color-border); }
  td { padding: 9px 8px; border-bottom: 1px solid var(--color-border); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  tr:last-child td { border-bottom: 0; }
  td a:hover { color: var(--color-coral); }
  .r { text-align: right; }
  .tgt { color: var(--color-text); }
  .dim { color: var(--color-muted); }
  .cd { display: inline-block; width: 8px; height: 8px; border-radius: 2px; margin-right: 6px; }
  .err { color: var(--color-danger); }
  .pad { padding: 16px; }
  th:nth-child(1), td:nth-child(1) { width: 16%; }
  th:nth-child(2), td:nth-child(2) { width: 14%; }
  th:nth-child(4), td:nth-child(4) { width: 12%; }
  th:nth-child(5), td:nth-child(5), th:nth-child(6), td:nth-child(6), th:nth-child(7), td:nth-child(7) { width: 11%; }
</style>
