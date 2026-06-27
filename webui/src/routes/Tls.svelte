<script>
  import { trackRefreshTick, ui } from '../lib/store.svelte.js'
  import { getJSON, catColor, ago } from '../lib/format.js'
  import { createLatestRunner, errorMessage } from '../lib/load.js'
  import Win from '../lib/Win.svelte'

  let data = $state(null)
  let err = $state(null)
  let q = $state('')
  const runLatest = createLatestRunner()

  $effect(() => {
    trackRefreshTick()
    const s = ui.since,
      qq = q
    load(s, qq)
  })
  async function load(s, qq) {
    try {
      const u = new URLSearchParams({ since: s })
      if (qq) u.set('q', qq)
      await runLatest(
        () => getJSON('/api/tls?' + u.toString()),
        (next) => {
          data = next
          err = null
        },
        (e) => {
          err = errorMessage(e)
        },
      )
    } catch (e) {
      err = errorMessage(e)
    }
  }
  const sites = $derived(data?.sites || [])
  const maxHits = $derived(Math.max(1, ...sites.map((s) => s.hits)))
</script>

<div class="head"><h1 class="serif">Sites <small>TLS SNI</small></h1><span class="pgwin"><Win /></span></div>
<div class="filters"><input placeholder="search site" bind:value={q} /><span class="cnt">last {ui.since} · {sites.length} sites</span></div>

{#if err}<p class="err">Couldn't load sites. ({err})</p>{:else if !data}<p class="dim">Loading…</p>{:else}
  <div class="card">
    {#each sites as s}
      <div class="site">
        <div class="dm"><span class="cd" style="background:{catColor(s.category)}"></span><span class="t">{s.site}</span></div>
        <div class="hits"><span class="bar"><span style="width:{((s.hits / maxHits) * 100).toFixed(0)}%"></span></span><span class="n mono">{s.hits}</span></div>
        <div class="cl">{#each s.clients.slice(0, 2) as c}<a class="tag" href="#/clients/{encodeURIComponent(c)}">{c}</a>{/each}{#if s.clients.length > 2}<span class="more">+{s.clients.length - 2}</span>{/if}</div>
        <div class="last mono">{ago(s.last)}</div>
      </div>
    {/each}
    {#if sites.length === 0}<p class="dim pad">No sites in this window.</p>{/if}
  </div>

  {#if data.recent?.length}
    <div class="card recent">
      <div class="h">Recent · chronological</div>
      {#each data.recent.slice(0, 8) as r}
        <div class="rec"><span class="c mono">{r.client}</span><span class="a">→ {r.server_name}</span><span class="tm mono">{ago(r.ts)}</span></div>
      {/each}
    </div>
  {/if}
{/if}

<style>
  .head { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
  h1 { font-size: 22px; font-weight: 500; margin: 0; }
  h1 small { font-size: 12px; color: var(--color-muted); font-weight: 400; margin-left: 6px; }
  .filters { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }
  input { background: var(--color-s1); border: 1px solid var(--color-border); border-radius: 7px; padding: 7px 10px; color: var(--color-text); width: 180px; }
  .cnt { color: var(--color-muted); font-size: 12px; }
  .card { background: var(--color-s1); border: 1px solid var(--color-border); border-radius: 12px; padding: 4px 16px; margin-bottom: 14px; }
  .site { display: grid; grid-template-columns: 1fr 130px 150px 44px; gap: 12px; align-items: center; padding: 10px 0; border-bottom: 1px solid var(--color-border); }
  .site:last-child { border-bottom: 0; }
  .dm { display: flex; align-items: center; gap: 8px; min-width: 0; }
  .cd { width: 8px; height: 8px; border-radius: 2px; flex: 0 0 8px; }
  .t { font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .hits { display: flex; align-items: center; gap: 8px; }
  .hits .bar { flex: 1; height: 6px; border-radius: 4px; background: var(--color-s3); overflow: hidden; }
  .hits .bar span { display: block; height: 100%; background: var(--color-coral); border-radius: 4px; }
  .hits .n { width: 32px; text-align: right; font-size: 12px; color: var(--color-dim); }
  .cl { display: flex; gap: 4px; flex-wrap: wrap; align-items: center; }
  .tag { font-size: 10.5px; color: var(--color-dim); background: var(--color-s3); border-radius: 5px; padding: 2px 7px; }
  .tag:hover { color: var(--color-coral); }
  .more { font-size: 10.5px; color: var(--color-muted); }
  .last { text-align: right; font-size: 11px; color: var(--color-muted); }
  .recent .h { font-size: 11px; color: var(--color-muted); padding: 8px 0; }
  .rec { display: flex; align-items: center; gap: 8px; font-size: 12.5px; padding: 4px 0; }
  .rec .c { color: var(--color-dim); font-size: 11px; }
  .rec .a { color: var(--color-coral); }
  .rec .tm { margin-left: auto; color: var(--color-muted); font-size: 11px; }
  .dim { color: var(--color-muted); }
  .err { color: var(--color-danger); }
  .pad { padding: 16px; }
  @media (max-width: 640px) {
    .pgwin { display: none; } /* the sticky header already carries the window picker */
    .site {
      grid-template-columns: 1fr auto;
      grid-template-areas:
        'dm dm'
        'hits last'
        'cl cl';
      gap: 7px 12px;
      padding: 12px 0;
    }
    .dm { grid-area: dm; }
    .hits { grid-area: hits; }
    .cl { grid-area: cl; }
    .last { grid-area: last; text-align: right; }
    input { flex: 1 1 160px; width: auto; }
    .rec .a { flex: 1 1 auto; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  }
</style>
