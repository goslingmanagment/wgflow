<script>
  import { trackRefreshTick, ui } from '../lib/store.svelte.js'
  import { fmtBytes, fmtShort, catColor } from '../lib/format.js'
  import { createResource } from '../lib/resource.svelte.js'
  import Chart from '../lib/Chart.svelte'
  import Mix from '../lib/Mix.svelte'
  import StaleBanner from '../lib/StaleBanner.svelte'

  const res = createResource()

  $effect(() => {
    trackRefreshTick()
    const s = ui.since
    res.load(['/api/system', '/api/throughput?since=' + s, '/api/clients?since=' + s, '/api/categories?since=' + s])
  })
  const sys = $derived(res.data?.[0])
  const thr = $derived(res.data?.[1])
  const clients = $derived(res.data?.[2])
  const cats = $derived(res.data?.[3])

  const st = $derived(sys?.stats || {})
  const thrPoints = $derived((thr?.points || []).map((p) => ({ t: p.t, v: ((p.down + p.up) * 8) / 60 / 1e6 })))
  const matchRate = $derived(st.packet_seen ? ((st.packet_matched / st.packet_seen) * 100).toFixed(1) : '—')
  const topClients = $derived((clients?.clients || []).slice(0, 5))
  const catList = $derived(cats?.categories || [])
  const catTotal = $derived(catList.reduce((s, c) => s + c.total, 0) || 1)
</script>

{#if res.err && !res.data}
  <p class="err">Couldn't load overview. ({res.err})</p>
{:else if !res.data}
  <!-- Never render zero KPIs before the first response: "0.0 Mbit/s" would read
       as measured silence, and zero ≠ proven quiet. -->
  <h1 class="serif">Overview</h1>
  <p class="dim">Loading…</p>
{:else}
  <h1 class="serif">Overview</h1>
  {#if res.stale}
    <StaleBanner lastUpdatedAt={res.lastUpdatedAt} err={res.err} />
  {/if}
  {#if clients?.db_ok === false}
    <div class="outage" role="alert">⚠ Rollup DB unavailable — verdicts are unknown and totals may be incomplete.</div>
  {/if}
  <div class="kpis">
    <div class="kpi"><div class="k">Throughput</div><div class="v mono">{(st.bit_rate_per_second / 1e6 || 0).toFixed(1)}</div><div class="s">Mbit/s now · avg {(st.average_bit_rate_per_second / 1e6 || 0).toFixed(0)}</div></div>
    <div class="kpi"><div class="k">Packets/s</div><div class="v mono">{fmtShort(st.packet_rate_per_second || 0)}</div><div class="s">avg {fmtShort(st.average_packet_rate_per_second || 0)}</div></div>
    <div class="kpi"><div class="k">Clients</div><div class="v mono">{clients?.clients?.length ?? 0}</div><div class="s">of {st.client_count ?? 0}</div></div>
    <div class="kpi"><div class="k">Match rate</div><div class="v mono">{matchRate}%</div><div class="s">{fmtShort(st.packet_matched || 0)} matched</div></div>
    <div class="kpi"><div class="k">Kernel drops</div><div class="v mono" style="color:{st.kernel_packet_socket_drops ? 'var(--color-warn)' : 'var(--color-ok)'}">{fmtShort(st.kernel_packet_socket_drops || 0)}</div><div class="s" style="color:{st.last_kernel_drops_delta ? 'var(--color-warn)' : 'var(--color-ok)'}">Δ {st.last_kernel_drops_delta ?? 0}</div></div>
  </div>

  <div class="card">
    <div class="ch"><h3 class="serif">Throughput</h3><span class="hint">last {ui.since} · Mbit/s</span></div>
    <Chart points={thrPoints} color="#e06a3f" unit="Mbit/s" height={180} />
  </div>

  <div class="two">
    <div class="card">
      <div class="ch"><h3 class="serif">Top clients</h3></div>
      {#each topClients as c}
        <a class="cli" href="#/clients/{encodeURIComponent(c.name)}">
          <div class="row1"><span>{c.name}</span><b class="mono">{fmtBytes(c.total)}</b></div>
          <Mix cats={c.cats} h={7} />
        </a>
      {/each}
    </div>
    <div class="card">
      <div class="ch"><h3 class="serif">Categories</h3></div>
      {#each catList.slice(0, 7) as c}
        <div class="cat">
          <span class="nm"><span class="cd" style="background:{catColor(c.category)}"></span>{c.category}</span>
          <span class="bar"><span style="width:{((c.total / catTotal) * 100).toFixed(1)}%;background:{catColor(c.category)}"></span></span>
          <span class="pc mono">{((c.total / catTotal) * 100).toFixed(0)}%</span>
        </div>
      {/each}
    </div>
  </div>
{/if}

<style>
  h1 {
    font-size: 22px;
    font-weight: 500;
    margin: 0 0 14px;
  }
  .kpis {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
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
    font-size: 21px;
    font-weight: 500;
    margin-top: 3px;
  }
  .kpi .s {
    font-size: 11px;
    color: var(--color-dim);
    margin-top: 2px;
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
  .cli {
    display: block;
    margin-bottom: 12px;
  }
  .cli:last-child {
    margin-bottom: 0;
  }
  .row1 {
    display: flex;
    justify-content: space-between;
    font-size: 13px;
    margin-bottom: 5px;
  }
  .cat {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 9px;
    font-size: 12.5px;
  }
  .cat .nm {
    width: 84px;
    flex: 0 0 84px;
  }
  .cd {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 2px;
    margin-right: 6px;
  }
  .cat .bar {
    flex: 1;
    height: 7px;
    border-radius: 4px;
    background: var(--color-s3);
    overflow: hidden;
  }
  .cat .bar span {
    display: block;
    height: 100%;
    border-radius: 4px;
  }
  .cat .pc {
    width: 32px;
    text-align: right;
    color: var(--color-dim);
  }
  .err {
    color: var(--color-danger);
  }
  .dim {
    color: var(--color-muted);
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
</style>
