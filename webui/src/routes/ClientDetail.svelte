<script>
  import { ui } from '../lib/store.svelte.js'
  import { getJSON, fmtBytes, fmtRate, sinceSeconds, catColor, ago, dnsRcodeName, hhmmMSK } from '../lib/format.js'
  import Icon from '../lib/Icon.svelte'
  import Chart from '../lib/Chart.svelte'
  import DayTimeline from '../lib/DayTimeline.svelte'
  import HealthPill from '../lib/HealthPill.svelte'

  let { param } = $props()
  let data = $state(null)
  let err = $state(null)

  $effect(() => {
    const n = param
    const s = ui.since
    load(n, s)
  })
  async function load(n, s) {
    try {
      data = await getJSON('/api/clients/' + encodeURIComponent(n) + '?since=' + s)
      err = null
    } catch (e) {
      err = e.message
    }
  }

  const secs = $derived(sinceSeconds(ui.since))
  const seriesPoints = $derived.by(() => {
    const arr = data?.series || []
    const start = data?.series_start_minute
    // Anchor the x-axis to the server's minute timestamps, not the browser clock,
    // so it matches the window (and MSK labels) the owner is reconstructing.
    if (arr.length < 2 || !start) return []
    return arr.map((b, i) => ({ t: (start + i) * 60, v: (b * 8) / 60 / 1e6 }))
  })
</script>

<a class="back" href="#/clients"><Icon name="chevron" size={14} /> Clients</a>

{#if err}
  <p class="err">Couldn't load this client. ({err})</p>
{:else if !data}
  <p class="dim">Loading…</p>
{:else}
  <div class="who">
    <h1 class="serif">{data.name}</h1>
    <HealthPill />
  </div>

  <div class="kpis">
    <div class="kpi"><div class="k">Rate · last {ui.since}</div><div class="v mono">{fmtRate(data.total, secs)} <small>Mbit/s</small></div></div>
    <div class="kpi"><div class="k">Download</div><div class="v mono">{fmtBytes(data.down)}</div></div>
    <div class="kpi"><div class="k">Upload</div><div class="v mono">{fmtBytes(data.up)}</div></div>
    <div class="kpi"><div class="k">Top category</div><div class="v"><span class="cd" style="background:{catColor(data.categories[0]?.category)}"></span>{data.categories[0]?.category || '—'}</div></div>
  </div>

  {#if seriesPoints.length > 1}
    <div class="card">
      <div class="ch"><h3 class="serif">Throughput</h3><span class="hint">last {ui.since} · Mbit/s</span></div>
      <Chart points={seriesPoints} color="#e06a3f" unit="Mbit/s" height={130} />
    </div>
  {/if}

  <div class="card">
    <div class="ch"><h3 class="serif">Across the day</h3><span class="hint">24h · by category</span></div>
    <DayTimeline day={data.day} />
  </div>

  <div class="two">
    <div class="card">
      <div class="ch"><h3 class="serif">Top targets</h3></div>
      <table class="t">
        <thead><tr><th>Target</th><th>Cat</th><th class="r">Down</th><th class="r">Up</th></tr></thead>
        <tbody>
          {#each data.top_targets.slice(0, 8) as t}
            <tr><td class="tgt" title={t.target}>{t.target}</td><td><span class="cd" style="background:{catColor(t.category)}"></span>{t.category}</td><td class="r mono">{fmtBytes(t.down)}</td><td class="r mono">{fmtBytes(t.up)}</td></tr>
          {/each}
          {#if data.top_targets.length === 0}<tr><td colspan="4" class="empty">No traffic in this window.</td></tr>{/if}
        </tbody>
      </table>
    </div>
    <div class="card">
      <div class="ch"><h3 class="serif">Recent sites</h3><span class="hint">TLS · МСК</span></div>
      {#each data.recent_tls.slice(0, 6) as r}
        <div class="li"><Icon name="lock" size={13} /><span class="g">{r.server_name}</span><span class="ago mono">{hhmmMSK(r.ts)}</span></div>
      {/each}
      {#if data.recent_tls.length === 0}<div class="empty">No TLS connections recently.</div>{/if}
      <div class="ch" style="margin-top:12px"><h3 class="serif">Recent DNS</h3><span class="hint">МСК</span></div>
      {#each data.recent_dns.slice(0, 6) as r}
        <div class="li"><span class="qt mono">{r.qtype}</span><span class="g">{r.query}</span>{#if r.rcode !== 0}<span class="nx">{dnsRcodeName(r.rcode)}</span>{:else}<span class="ago mono">{hhmmMSK(r.ts)}</span>{/if}</div>
      {/each}
      {#if data.recent_dns.length === 0}<div class="empty">No DNS queries recently — likely cached or encrypted (DoH/DoT).</div>{/if}
    </div>
  </div>
{/if}

<style>
  .back {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    color: var(--color-dim);
    font-size: 13px;
    margin-bottom: 10px;
  }
  .back:hover {
    color: var(--color-text);
  }
  .who {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
  }
  h1 {
    font-size: 24px;
    font-weight: 500;
    margin: 0;
  }
  .kpis {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 10px;
    margin-bottom: 14px;
  }
  .kpi {
    background: var(--color-s1);
    border: 1px solid var(--color-border);
    border-radius: 10px;
    padding: 12px 14px;
  }
  .kpi .k {
    font-size: 11px;
    color: var(--color-muted);
  }
  .kpi .v {
    font-size: 20px;
    font-weight: 500;
    margin-top: 4px;
  }
  .kpi .v small {
    font-size: 12px;
    color: var(--color-dim);
  }
  .cd {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 2px;
    margin-right: 6px;
  }
  .card {
    background: var(--color-s1);
    border: 1px solid var(--color-border);
    border-radius: 12px;
    padding: 14px 16px;
    margin-bottom: 14px;
  }
  .ch {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    margin-bottom: 12px;
  }
  .ch h3 {
    font-size: 16px;
    font-weight: 500;
    margin: 0;
  }
  .hint {
    font-size: 11px;
    color: var(--color-muted);
  }
  .two {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px;
  }
  @media (max-width: 760px) {
    .two {
      grid-template-columns: 1fr;
    }
  }
  table.t {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
    table-layout: fixed;
  }
  .t th {
    text-align: left;
    color: var(--color-muted);
    font-weight: 400;
    font-size: 11px;
    padding: 4px 6px 6px 0;
    border-bottom: 1px solid var(--color-border);
  }
  .t td {
    padding: 6px 6px 6px 0;
    border-bottom: 1px solid var(--color-border);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .t tr:last-child td {
    border-bottom: 0;
  }
  .r {
    text-align: right;
  }
  .tgt {
    color: var(--color-text);
  }
  .li {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 5px 0;
    font-size: 12.5px;
    color: var(--color-dim);
    border-bottom: 1px solid var(--color-border);
  }
  .li:last-child {
    border-bottom: 0;
  }
  .li .g {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--color-text);
  }
  .qt {
    font-size: 10px;
    color: var(--color-muted);
    width: 34px;
  }
  .ago {
    color: var(--color-muted);
    font-size: 11px;
  }
  .nx {
    color: var(--color-warn);
    font-size: 11px;
    font-weight: 500;
  }
  .err {
    color: var(--color-danger);
  }
  .dim {
    color: var(--color-muted);
  }
  .empty {
    color: var(--color-muted);
    font-size: 12px;
    padding: 8px 0;
  }
  td.empty {
    text-align: center;
    padding: 16px 0;
  }
</style>
