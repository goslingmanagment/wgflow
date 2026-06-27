<script>
  import { ui } from '../lib/store.svelte.js'
  import { getJSON, fmtBytes, catColor } from '../lib/format.js'
  import Win from '../lib/Win.svelte'
  import Donut from '../lib/Donut.svelte'

  let data = $state(null)
  let err = $state(null)
  $effect(() => {
    const s = ui.since
    load(s)
  })
  async function load(s) {
    try {
      data = await getJSON('/api/categories?since=' + s)
      err = null
    } catch (e) {
      err = e.message
    }
  }
  const list = $derived(data?.categories || [])
  const total = $derived(list.reduce((s, c) => s + c.total, 0) || 1)
</script>

<div class="head"><h1 class="serif">Categories</h1><Win /></div>

{#if err}<p class="err">Couldn't load categories. ({err})</p>{:else if !data}<p class="dim">Loading…</p>{:else}
  <div class="card hero">
    <Donut items={list} size={118} />
    <div class="sum">
      <div class="big">{fmtBytes(total)}</div>
      <div class="lbl">{list.length} categories · last {ui.since}</div>
      {#if list[0]}<div class="lbl">largest <b>{list[0].category}</b> {((list[0].total / total) * 100).toFixed(0)}%</div>{/if}
    </div>
  </div>
  <div class="card">
    {#each list as c}
      <div class="row">
        <div class="top">
          <span class="nm"><span class="cd" style="background:{catColor(c.category)}"></span>{c.category}</span>
          <span class="bar"><span style="width:{((c.total / total) * 100).toFixed(1)}%;background:{catColor(c.category)}"></span></span>
          <span class="pc mono">{((c.total / total) * 100).toFixed(0)}%</span>
          <span class="tot mono">{fmtBytes(c.total)}</span>
        </div>
        <div class="sub">top client <b>{c.top_client}</b> · top target <b>{c.top_target}</b></div>
      </div>
    {/each}
  </div>
{/if}

<style>
  .head { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }
  h1 { font-size: 22px; font-weight: 500; margin: 0; }
  .card { background: var(--color-s1); border: 1px solid var(--color-border); border-radius: 12px; padding: 6px 16px; }
  .hero { display: flex; align-items: center; gap: 24px; padding: 16px; margin-bottom: 14px; }
  .sum .big { font-family: var(--font-serif); font-size: 30px; font-weight: 500; line-height: 1; font-variant-numeric: tabular-nums; }
  .sum .lbl { font-size: 12.5px; color: var(--color-dim); margin-top: 8px; }
  .sum .lbl b { color: var(--color-text); font-weight: 500; }
  .row { padding: 12px 0; border-bottom: 1px solid var(--color-border); }
  .row:last-child { border-bottom: 0; }
  .top { display: grid; grid-template-columns: 120px 1fr 42px 84px; gap: 12px; align-items: center; }
  .nm { font-weight: 500; font-size: 13.5px; }
  .cd { display: inline-block; width: 9px; height: 9px; border-radius: 2px; margin-right: 8px; }
  .bar { height: 8px; border-radius: 5px; background: var(--color-s3); overflow: hidden; }
  .bar span { display: block; height: 100%; border-radius: 5px; }
  .pc { text-align: right; color: var(--color-dim); font-size: 12.5px; }
  .tot { text-align: right; font-weight: 500; font-size: 13px; }
  .sub { font-size: 11.5px; color: var(--color-muted); margin-top: 6px; padding-left: 17px; }
  .sub b { color: var(--color-text); font-weight: 400; }
  .err { color: var(--color-danger); }
  .dim { color: var(--color-muted); }
</style>
