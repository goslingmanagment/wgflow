<script>
  import { setGroup, trackRefreshTick, ui } from '../lib/store.svelte.js'
  import { getJSON, fmtBytes, fmtRate, sinceSeconds, catColor, ago, verdictColor, deviceGlyph } from '../lib/format.js'
  import { createLatestRunner, errorMessage } from '../lib/load.js'
  import Mix from '../lib/Mix.svelte'
  import Spark from '../lib/Spark.svelte'
  import Icon from '../lib/Icon.svelte'
  import HealthPill from '../lib/HealthPill.svelte'
  import VerdictBadge from '../lib/VerdictBadge.svelte'
  import Srez from '../lib/Srez.svelte'

  let data = $state(null)
  let err = $state(null)
  let search = $state('')
  let sort = $state('total')
  let srezOpen = $state(false)
  const runLatest = createLatestRunner()

  $effect(() => {
    trackRefreshTick()
    const s = ui.since
    load(s)
  })
  async function load(s) {
    await runLatest(
      () => getJSON('/api/clients?since=' + s),
      (next) => {
        data = next
        err = null
      },
      (e) => {
        err = errorMessage(e)
      },
    )
  }

  let manualOpen = $state(new Set())

  const rows = $derived.by(() => {
    const needle = search.trim().toLowerCase()
    let r = (data?.clients || []).filter((c) => !needle || c.name.toLowerCase().includes(needle) || (c.person || '').toLowerCase().includes(needle))
    r = [...r].sort((a, b) => (sort === 'name' ? a.name.localeCompare(b.name) : b.total - a.total))
    return r
  })

  // Group devices into people (server-resolved `person`, from clients.yaml or the
  // prefix fallback). Auto-expand when a person's devices disagree — the case the
  // owner most wants to see (phone active while the laptop is silent).
  const ORDER = { active: 3, 'likely-background': 2, silent: 1 }
  function aggVerdict(devices) {
    let best = null
    for (const d of devices) {
      if (!best || (ORDER[d.verdict?.status] || 0) > (ORDER[best.status] || 0)) best = d.verdict
    }
    return best
  }
  const grouped = $derived.by(() => {
    const m = {}
    for (const c of rows) {
      const p = c.person || c.name
      if (!m[p]) m[p] = { person: p, devices: [], total: 0, cats: {} }
      m[p].devices.push(c)
      m[p].total += c.total
      for (const x of c.cats || []) m[p].cats[x.category] = (m[p].cats[x.category] || 0) + Number(x.bytes || 0)
    }
    return Object.values(m)
      .map((g) => ({
        person: g.person,
        devices: [...g.devices].sort((a, b) => b.total - a.total),
        total: g.total,
        cats: Object.entries(g.cats)
          .map(([category, bytes]) => ({ category, bytes }))
          .sort((a, b) => b.bytes - a.bytes),
        verdict: aggVerdict(g.devices),
        disagree: new Set(g.devices.map((d) => d.verdict?.status)).size > 1,
      }))
      .sort((a, b) => (sort === 'name' ? a.person.localeCompare(b.person) : b.total - a.total))
  })
  function isOpen(g) {
    return manualOpen.has(g.person) || g.disagree || g.devices.length === 1
  }
  function toggle(person) {
    const s = new Set(manualOpen)
    s.has(person) ? s.delete(person) : s.add(person)
    manualOpen = s
  }
  const secs = $derived(sinceSeconds(ui.since))
</script>

<div class="head">
  <h1 class="serif">Clients <HealthPill /></h1>
  <div class="tools">
    <button class:on={sort === 'total'} onclick={() => (sort = 'total')}>volume</button>
    <button class:on={sort === 'name'} onclick={() => (sort = 'name')}>name</button>
    <span class="srch"><Icon name="search" size={15} /><input placeholder="find client" bind:value={search} /></span>
    <button class="srez-btn" onclick={() => (srezOpen = true)}>Срез</button>
  </div>
</div>

<Srez open={srezOpen} onClose={() => (srezOpen = false)} names={(data?.clients || []).map((c) => c.name)} />

{#if err}
  <p class="err">Couldn't load clients. Is <code>wgflow web</code> running? ({err})</p>
{:else if !data}
  <p class="dim">Loading…</p>
{:else}
  <div class="cnt">
    <span class="grp">group
      <button class:on={ui.group === 'person'} onclick={() => setGroup('person')}>person</button>
      <button class:on={ui.group === 'device'} onclick={() => setGroup('device')}>device</button>
    </span>
    {#if ui.group === 'person'}· {grouped.length} people · {rows.length} devices{:else}· {rows.length} seen{/if} · last {ui.since} · classification inferred
  </div>
  {#if data.logger_ok === false}
    <div class="outage" role="alert">
      ⚠ Логгер не подтверждён — нулевые строки могут быть сбоем, не тишиной. Тишина не доказана; проверьте System.
    </div>
  {/if}

  {#snippet deviceRow(c, sub)}
    <a class="row" class:sub href="#/clients/{encodeURIComponent(c.name)}">
      <div class="nm">
        <span class="dot" style="background:{verdictColor(c.verdict?.status)}"></span>
        <div class="tx">
          <div class="name">{#if deviceGlyph(c.device_kind)}<span class="dev" title={c.device_kind}>{deviceGlyph(c.device_kind)}</span>{/if}{c.name} <VerdictBadge verdict={c.verdict} loggerOk={data.logger_ok} compact /></div>
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
  {/snippet}

  <div class="ledger">
    <div class="rowh">
      <span>{ui.group === 'person' ? 'Person · device' : 'Client · doing now'}</span><span>net</span><span class="r">rate</span><span class="r">volume</span><span>mix</span>
    </div>
    {#if ui.group === 'person'}
      {#each grouped as g (g.person)}
        <div class="pgroup">
          <button class="phead" onclick={() => toggle(g.person)}>
            <div class="nm">
              <span class="dot" style="background:{verdictColor(g.verdict?.status)}"></span>
              <div class="tx">
                <div class="name"><span class="pname serif">{g.person}</span> <VerdictBadge verdict={g.verdict} loggerOk={data.logger_ok} compact /></div>
                <div class="site"><span class="muted">{g.devices.length} устр. {g.devices.map((d) => deviceGlyph(d.device_kind)).filter(Boolean).join(' ')}{#if g.disagree} · устройства расходятся{/if}</span></div>
              </div>
            </div>
            <div class="spk caret">{isOpen(g) ? '▾' : '▸'}</div>
            <div class="rate"></div>
            <div class="vol mono">{fmtBytes(g.total)}</div>
            <div class="mix"><Mix cats={g.cats} /></div>
          </button>
          {#if isOpen(g)}
            {#each g.devices as c (c.name)}{@render deviceRow(c, true)}{/each}
          {/if}
        </div>
      {/each}
      {#if grouped.length === 0}<p class="dim pad">No clients in this window.</p>{/if}
    {:else}
      {#each rows as c (c.name)}{@render deviceRow(c, false)}{/each}
      {#if rows.length === 0}<p class="dim pad">No clients in this window.</p>{/if}
    {/if}
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
  .srez-btn {
    background: var(--color-coral);
    color: #fff;
    border: 0;
    border-radius: 7px;
    padding: 6px 14px;
    cursor: pointer;
    font-size: 13px;
    font-weight: 500;
  }
  .srez-btn:hover {
    filter: brightness(1.05);
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
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }
  .grp {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .grp button {
    background: transparent;
    border: 1px solid var(--color-border);
    border-radius: 6px;
    color: var(--color-dim);
    padding: 2px 9px;
    cursor: pointer;
    font-size: 11px;
  }
  .grp button.on {
    background: var(--color-coral-dim);
    color: var(--color-coral);
    border-color: transparent;
  }
  .outage {
    background: color-mix(in srgb, var(--color-warn) 16%, transparent);
    border: 1px solid color-mix(in srgb, var(--color-warn) 40%, transparent);
    color: var(--color-warn);
    border-radius: 9px;
    padding: 9px 12px;
    font-size: 12.5px;
    margin-bottom: 10px;
  }
  .dev {
    margin-right: 5px;
    font-size: 12px;
  }
  .ledger {
    background: var(--color-s1);
    border: 1px solid var(--color-border);
    border-radius: 12px;
    overflow: hidden;
  }
  .rowh,
  .row,
  .phead {
    display: grid;
    grid-template-columns: 1fr 56px 84px 84px 118px;
    gap: 12px;
    align-items: center;
    padding: 11px 16px;
  }
  .phead {
    width: 100%;
    border: 0;
    border-bottom: 1px solid var(--color-border);
    background: transparent;
    color: inherit;
    cursor: pointer;
    text-align: left;
    font: inherit;
  }
  .phead:hover {
    background: var(--color-s2);
  }
  .pname {
    font-size: 15px;
    font-weight: 500;
  }
  .caret {
    color: var(--color-muted);
    font-size: 11px;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .row.sub {
    padding-left: 32px;
    background: color-mix(in srgb, var(--color-bg) 35%, transparent);
  }
  .row.sub .name {
    font-size: 13px;
  }
  .pgroup:last-child .row:last-child {
    border-bottom: 0;
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
