<script>
  import { trackRefreshTick, ui } from '../lib/store.svelte.js'
  import { getJSON, fmtBytes, fmtRate, sinceSeconds, catColor, ago, dnsRcodeName, hhmmMSK, deviceGlyph, mskAnchorUnix } from '../lib/format.js'
  import { createLatestRunner, errorMessage } from '../lib/load.js'
  import Icon from '../lib/Icon.svelte'
  import Chart from '../lib/Chart.svelte'
  import DayTimeline from '../lib/DayTimeline.svelte'
  import VerdictBadge from '../lib/VerdictBadge.svelte'
  import Ribbon from '../lib/Ribbon.svelte'

  // "last real-use trace" (last >100KB minute), falling back to last-any (last
  // ping). Never "проснулась" — only a trace, always MSK.
  function traceLine(v) {
    if (!v) return ''
    const sig = v.last_significant_at
    const any = v.evidence?.last_any_at
    if (sig) return `последний заметный след ${hhmmMSK(sig)} МСК (${ago(sig)})`
    if (any) return `последний след ${hhmmMSK(any)} МСК (${ago(any)})`
    return 'нет заметных следов в окне'
  }

  let { param } = $props()
  let data = $state(null)
  let err = $state(null)
  let fromAnchor = $state(null) // unix seconds, or null = relative window
  let anchorInput = $state('')
  const runLatest = createLatestRunner()

  // Reset any anchor when switching clients (declared first so it runs before the
  // loader, which would otherwise fire once with the previous client's anchor).
  $effect(() => {
    param
    fromAnchor = null
    anchorInput = ''
  })
  $effect(() => {
    trackRefreshTick()
    const n = param
    const s = ui.since
    const f = fromAnchor
    load(n, s, f)
  })
  async function load(n, s, f) {
    try {
      const u = new URLSearchParams()
      if (f) u.set('from', f)
      else u.set('since', s)
      await runLatest(
        () => getJSON('/api/clients/' + encodeURIComponent(n) + '?' + u.toString()),
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
  function applyAnchor() {
    const u = mskAnchorUnix(anchorInput)
    if (u) fromAnchor = u
  }
  function clearAnchor() {
    fromAnchor = null
    anchorInput = ''
  }

  // window length in seconds: absolute span when anchored, else the relative since
  const secs = $derived(data?.from && data?.to ? data.to - data.from : sinceSeconds(ui.since))
  const windowLabel = $derived(fromAnchor && data?.from ? 'после ' + hhmmMSK(data.from) + ' МСК' : 'last ' + ui.since)
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
    <VerdictBadge verdict={data.verdict} loggerOk={data.logger_ok} />
  </div>
  {#if data.verdict}
    <div class="trace">{#if deviceGlyph(data.device_kind)}<span class="dev" title={data.device_kind}>{deviceGlyph(data.device_kind)}</span> {/if}{traceLine(data.verdict)}</div>
  {/if}

  <div class="anchor">
    <span class="lbl">окно:</span>
    <input class="mono" placeholder="после HH:MM" bind:value={anchorInput} onkeydown={(e) => e.key === 'Enter' && applyAnchor()} />
    <button onclick={applyAnchor}>показать</button>
    {#if fromAnchor}<button class="clr" onclick={clearAnchor}>↺ относительное ({ui.since})</button>{/if}
    <span class="now">{windowLabel}</span>
  </div>

  <div class="kpis">
    <div class="kpi"><div class="k">Rate · {windowLabel}</div><div class="v mono">{fmtRate(data.total, secs)} <small>Mbit/s</small></div></div>
    <div class="kpi"><div class="k">Download</div><div class="v mono">{fmtBytes(data.down)}</div></div>
    <div class="kpi"><div class="k">Upload</div><div class="v mono">{fmtBytes(data.up)}</div></div>
    <div class="kpi"><div class="k">Top category</div><div class="v"><span class="cd" style="background:{catColor(data.categories[0]?.category)}"></span>{data.categories[0]?.category || '—'}</div></div>
  </div>
  <div class="caveat" title="Wire bytes are ~94–95% of these totals and packet counts are approximate: the kernel coalesces segments (GSO/GRO) before wgflow counts them. HTTPS payloads are never inspected.">~94–95% of bytes · packets approximate (GSO/GRO)</div>

  {#if seriesPoints.length > 1}
    <div class="card">
      <div class="ch"><h3 class="serif">Throughput</h3><span class="hint">{windowLabel} · Mbit/s</span></div>
      <Chart points={seriesPoints} color="#e06a3f" unit="Mbit/s" height={130} />
    </div>
  {/if}

  <div class="two">
    <div class="card">
      <div class="ch"><h3 class="serif">Top targets</h3><span class="hint mono" title="Wire bytes are ~94–95% of these totals; packet counts are approximate (GSO/GRO coalescing).">~94–95% (GSO/GRO)</span></div>
      <div class="tscroll">
        <table class="t">
          <thead><tr><th>Target</th><th>Cat</th><th class="r">Down</th><th class="r">Up</th></tr></thead>
          <tbody>
            {#each data.top_targets.slice(0, 8) as t}
              <tr class:bg={t.category === 'apple'}>
                <td class="tgt" title={t.resolved_target ? `${t.resolved_target} · ${t.target}` : t.target}>
                  <span>{t.resolved_target || t.target}</span>
                  {#if t.resolved_target}
                    <span class="noname">· {t.target}</span>
                  {:else if t.is_ip}
                    <span class="noname">· no hostname{t.proto === 'udp' ? ' (QUIC)' : ''}</span>
                  {/if}
                  {#if t.target_org}<span class="org">{t.target_org}</span>{/if}
                </td>
                <td><span class="cd" style="background:{catColor(t.category)}"></span>{t.category}{#if t.category === 'apple'}<span class="hedge" title="Apple endpoints are usually background — push, OCSP, iCloud. Inferred from the IP range, not proven.">push/OCSP?</span>{/if}</td>
                <td class="r mono">{fmtBytes(t.down)}</td>
                <td class="r mono">{fmtBytes(t.up)}</td>
              </tr>
            {/each}
            {#if data.top_targets.length === 0}<tr><td colspan="4" class="empty">No traffic in this window.</td></tr>{/if}
          </tbody>
        </table>
      </div>
    </div>
    <div class="card">
      <div class="ch"><h3 class="serif">Recent sites</h3><span class="hint">TLS/QUIC · МСК</span></div>
      {#each data.recent_tls.slice(0, 6) as r}
        <div class="li">
          <Icon name={r.protocol === 'quic' ? 'activity' : 'lock'} size={13} />
          <span class="g">{r.server_name}</span>
          <span class="proto mono" class:quic={r.protocol === 'quic'}>{(r.protocol || 'tls').toUpperCase()}</span>
          <span class="ago mono">{hhmmMSK(r.ts)}</span>
        </div>
      {/each}
      {#if data.recent_tls.length === 0}<div class="empty">No TLS/QUIC handshakes recently.</div>{/if}
      <div class="ch" style="margin-top:12px"><h3 class="serif">Recent DNS</h3><span class="hint">МСК</span></div>
      {#each data.recent_dns.slice(0, 6) as r}
        <div class="li"><span class="qt mono">{r.qtype}</span><span class="g">{r.query}</span>{#if r.rcode !== 0}<span class="nx">{dnsRcodeName(r.rcode)}</span>{:else}<span class="ago mono">{hhmmMSK(r.ts)}</span>{/if}</div>
      {/each}
      {#if data.recent_dns.length === 0}<div class="empty">No DNS queries recently — likely cached or encrypted (DoH/DoT).</div>{/if}
    </div>
  </div>

  <div class="card">
    <div class="ch"><h3 class="serif">Across the day</h3><span class="hint">24h · by category</span></div>
    <DayTimeline day={data.day} />
  </div>

  {#if data.minutes?.length}
    <Ribbon minutes={data.minutes} name={data.name} />
  {/if}
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
    margin-bottom: 6px;
  }
  .trace {
    color: var(--color-muted);
    font-size: 12.5px;
    margin-bottom: 12px;
  }
  .anchor {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 14px;
  }
  .anchor .lbl {
    color: var(--color-muted);
    font-size: 12px;
  }
  .anchor input {
    background: var(--color-s1);
    border: 1px solid var(--color-border);
    border-radius: 7px;
    padding: 6px 10px;
    color: var(--color-text);
    width: 120px;
    font-size: 12px;
  }
  .anchor button {
    background: var(--color-coral-dim);
    color: var(--color-coral);
    border: 0;
    border-radius: 7px;
    padding: 6px 12px;
    cursor: pointer;
    font-size: 12px;
  }
  .anchor .clr {
    background: transparent;
    border: 1px solid var(--color-border);
    color: var(--color-dim);
  }
  .anchor .now {
    color: var(--color-muted);
    font-size: 12px;
    margin-left: auto;
    font-family: var(--font-mono);
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
  .caveat {
    text-align: right;
    color: var(--color-muted);
    font-size: 11px;
    margin: -6px 0 14px;
  }
  .noname {
    color: var(--color-muted);
    margin-left: 6px;
    font-size: 11px;
  }
  .org {
    color: var(--color-muted);
    border: 1px solid var(--color-border);
    border-radius: 4px;
    padding: 0 4px;
    margin-left: 6px;
    font-size: 10px;
  }
  .hedge {
    color: var(--color-muted);
    margin-left: 7px;
    font-size: 10px;
    cursor: help;
  }
  tr.bg .tgt {
    color: var(--color-dim);
  }
  .card {
    background: var(--color-s1);
    border: 1px solid var(--color-border);
    border-radius: 12px;
    padding: 14px 16px;
    margin-bottom: 14px;
    /* Grid items default to min-width:auto, which would let the inner scrollable
       table expand the column past the viewport; pin to 0 so .tscroll scrolls. */
    min-width: 0;
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
  .tscroll {
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
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
  .proto {
    flex: 0 0 auto;
    color: var(--color-muted);
    background: var(--color-s3);
    border-radius: 4px;
    padding: 1px 5px;
    font-size: 10px;
  }
  .proto.quic {
    color: var(--color-accent);
    background: var(--color-accent-dim);
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

  @media (max-width: 640px) {
    .kpis {
      grid-template-columns: 1fr 1fr;
      gap: 8px;
    }
    .kpi {
      padding: 10px 12px;
    }
    .kpi .v {
      font-size: 18px;
    }
    /* keep the targets table readable: scroll horizontally rather than crush it */
    table.t {
      min-width: 420px;
    }
    .anchor input {
      flex: 1 1 140px;
      width: auto;
    }
    .anchor .now {
      margin-left: 0;
    }
  }
</style>
