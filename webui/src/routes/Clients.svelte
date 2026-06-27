<script>
  import { ui } from '../lib/store.svelte.js'
  import { getJSON, fmtBytes, fmtRate, sinceSeconds, catColor, ago } from '../lib/format.js'
  import Mix from '../lib/Mix.svelte'
  import Spark from '../lib/Spark.svelte'
  import Icon from '../lib/Icon.svelte'
  import HealthPill from '../lib/HealthPill.svelte'

  let data = $state(null)
  let err = $state(null)
  let search = $state('')
  let sort = $state('total')

  $effect(() => {
    const s = ui.since
    load(s)
  })
  async function load(s) {
    try {
      data = await getJSON('/api/clients?since=' + s)
      err = null
    } catch (e) {
      err = e.message
    }
  }

  const rows = $derived.by(() => {
    const needle = search.trim().toLowerCase()
    let r = (data?.clients || []).filter((c) => !needle || c.name.toLowerCase().includes(needle))
    r = [...r].sort((a, b) => (sort === 'name' ? a.name.localeCompare(b.name) : b.total - a.total))
    return r
  })
  const secs = $derived(sinceSeconds(ui.since))
</script>

<div class="head">
  <h1 class="serif">Clients <HealthPill /></h1>
  <div class="tools">
    <button class:on={sort === 'total'} onclick={() => (sort = 'total')}>volume</button>
    <button class:on={sort === 'name'} onclick={() => (sort = 'name')}>name</button>
    <span class="srch"><Icon name="search" size={15} /><input placeholder="find client" bind:value={search} /></span>
  </div>
</div>

{#if err}
  <p class="err">Couldn't load clients. Is <code>wgflow web</code> running? ({err})</p>
{:else if !data}
  <p class="dim">Loading…</p>
{:else}
  <div class="cnt">{rows.length} active · last {ui.since}</div>
  <div class="ledger">
    <div class="rowh">
      <span>Client · doing now</span><span>net</span><span class="r">rate</span><span class="r">volume</span><span>mix</span>
    </div>
    {#each rows as c (c.name)}
      <a class="row" href="#/clients/{encodeURIComponent(c.name)}">
        <div class="nm">
          <span class="dot"></span>
          <div class="tx">
            <div class="name">{c.name}</div>
            <div class="site">
              {#if c.current_site}<span class="cd" style="background:{catColor(c.top_category)}"></span>→ {c.current_site}{:else}<span class="muted">— {c.top_category || ''}</span>{/if}
            </div>
          </div>
        </div>
        <div class="spk"><Spark values={c.series || []} color="var(--color-coral)" h={22} /></div>
        <div class="rate mono">{fmtRate(c.total, secs)}<small>Mbit/s</small></div>
        <div class="vol mono">{fmtBytes(c.total)}</div>
        <div class="mix"><Mix cats={c.cats} /></div>
      </a>
    {/each}
    {#if rows.length === 0}<p class="dim pad">No active clients in this window.</p>{/if}
  </div>
{/if}

<style>
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 14px;
  }
  h1 {
    font-size: 22px;
    font-weight: 500;
    margin: 0;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .tools {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .tools button {
    background: transparent;
    border: 1px solid var(--color-border);
    border-radius: 7px;
    color: var(--color-dim);
    padding: 6px 10px;
    cursor: pointer;
    font-size: 12px;
  }
  .tools button.on {
    background: var(--color-coral-dim);
    color: var(--color-coral);
    border-color: transparent;
  }
  .srch {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    border: 1px solid var(--color-border);
    border-radius: 7px;
    padding: 0 9px;
    color: var(--color-muted);
  }
  .srch input {
    background: transparent;
    border: 0;
    outline: none;
    padding: 7px 0;
    width: 120px;
  }
  .cnt {
    color: var(--color-muted);
    font-size: 12px;
    margin-bottom: 8px;
  }
  .ledger {
    background: var(--color-s1);
    border: 1px solid var(--color-border);
    border-radius: 12px;
    overflow: hidden;
  }
  .rowh,
  .row {
    display: grid;
    grid-template-columns: 1fr 56px 84px 84px 118px;
    gap: 12px;
    align-items: center;
    padding: 11px 16px;
  }
  .rowh {
    font-size: 11px;
    color: var(--color-muted);
    border-bottom: 1px solid var(--color-border);
  }
  .rowh .r {
    text-align: right;
  }
  .row {
    border-bottom: 1px solid var(--color-border);
    color: inherit;
  }
  .row:last-child {
    border-bottom: 0;
  }
  .row:hover {
    background: var(--color-s2);
  }
  .nm {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
  }
  .nm .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--color-ok);
    flex: 0 0 8px;
  }
  .tx {
    min-width: 0;
  }
  .name {
    font-weight: 500;
    font-size: 14px;
  }
  .site {
    font-size: 12px;
    color: var(--color-dim);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    margin-top: 1px;
  }
  .site .cd {
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 2px;
    margin-right: 5px;
  }
  .muted {
    color: var(--color-muted);
  }
  .spk {
    display: flex;
    align-items: center;
    min-width: 0;
  }
  .rate {
    text-align: right;
    font-size: 14px;
    font-weight: 500;
  }
  .rate small {
    display: block;
    font-size: 10px;
    color: var(--color-muted);
    font-weight: 400;
  }
  .vol {
    text-align: right;
    color: var(--color-dim);
    font-size: 13px;
  }
  .err {
    color: var(--color-danger);
  }
  .dim {
    color: var(--color-muted);
  }
  .pad {
    padding: 16px;
  }
</style>
