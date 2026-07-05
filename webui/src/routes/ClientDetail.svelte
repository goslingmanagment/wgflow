<script>
  import { trackRefreshTick, ui } from '../lib/store.svelte.js'
  import { fmtBytes, fmtRate, sinceSeconds, catColor, ago, dnsRcodeName, hhmmMSK, deviceGlyph, mskAnchorUnix } from '../lib/format.js'
  import { createResource } from '../lib/resource.svelte.js'
  import StaleBanner from '../lib/StaleBanner.svelte'
  import InfoTip from '../lib/InfoTip.svelte'
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

  // Collapse a top-target's app-identity and infrastructure layers into one cell:
  // a primary identity (app hostname, or the bare IP when that's all we have) over
  // a dim infra/provenance subline. Replaces the old two-column App|Infra split,
  // which needed more width than the half-page card has and so overflowed/truncated.
  function targetView(t) {
    const ident = t.app_target || t.target
    const identIsIP = !t.app_target && t.is_ip
    let infra = ''
    let prov = ''
    let provTitle = ''
    if (!t.is_ip) {
      infra = 'direct'
    } else {
      const parts = []
      if (t.target_org) parts.push(t.target_org)
      if (t.app_target) parts.push(t.target) // app served from this IP — show where
      else if (t.resolved_target) parts.push(t.resolved_target)
      else parts.push(t.proto === 'udp' ? 'QUIC' : 'no PTR')
      infra = parts.join(' · ')
      if (t.attribution_source) {
        const more = t.attribution_candidates?.length > 1 ? ' +' + (t.attribution_candidates.length - 1) : ''
        prov = t.attribution_source.replace(/^TLS /, '') + more
        provTitle = t.attribution_source + (more ? ' · ' + t.attribution_candidates.join(', ') : '')
      }
    }
    return { ident, identIsIP, infra, prov, provTitle, title: infra ? `${ident} · ${infra}` : ident }
  }

  let { param } = $props()
  let fromAnchor = $state(null) // unix seconds, or null = relative window
  let anchorInput = $state('')
  const res = createResource()

  // Reset any anchor when switching clients (declared first so it runs before the
  // loader, which would otherwise fire once with the previous client's anchor).
  $effect(() => {
    param
    fromAnchor = null
    anchorInput = ''
  })
  $effect(() => {
    trackRefreshTick()
    const u = new URLSearchParams()
    if (fromAnchor) u.set('from', fromAnchor)
    else u.set('since', ui.since)
    res.load('/api/clients/' + encodeURIComponent(param) + '?' + u.toString())
  })
  const data = $derived(res.data)
  // The API 404s for a peer wgflow doesn't know (it used to answer 200 with
  // zeros); show "not found" rather than a raw HTTP error, even if an earlier
  // client's data is still around.
  const notFound = $derived(res.errStatus === 404)
  // Defensive defaults: one nil slice on the Go side must not crash the route.
  const targets = $derived(data?.top_targets ?? [])
  const recentTls = $derived(data?.recent_tls ?? [])
  const recentDns = $derived(data?.recent_dns ?? [])
  const categories = $derived(data?.categories ?? [])
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

{#if notFound}
  <p class="err">Client “{param}” not found — no such peer in the WireGuard config or logs.</p>
  <p class="dim">Pick one from the <a class="lnk" href="#/clients">Clients</a> list.</p>
{:else if res.err && !data}
  <p class="err">Couldn't load this client. ({res.err})</p>
{:else if !data}
  <p class="dim">Loading…</p>
{:else}
  {#if res.stale}
    <StaleBanner lastUpdatedAt={res.lastUpdatedAt} err={res.err} />
  {/if}
  <div class="who">
    <h1 class="serif">{data.name}</h1>
    <VerdictBadge verdict={data.verdict} loggerOk={data.logger_ok} />
    {#if data.encrypted_dns}
      <InfoTip text="Клиент использует шифрованный DNS (DoH/DoT) — DNS-журнал неполон, атрибуция доменов может занижаться."><span class="edns">DoH/DoT</span></InfoTip>
    {/if}
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
    <div class="kpi"><div class="k">Top category</div><div class="v"><span class="cd" style="background:{catColor(categories[0]?.category)}"></span>{categories[0]?.category || '—'}</div></div>
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
          <thead><tr><th>Target</th><th class="c-cat">Cat</th><th class="r c-num">Down</th><th class="r c-num">Up</th></tr></thead>
          <tbody>
            {#each targets.slice(0, 8) as t}
              {@const v = targetView(t)}
              <tr class:bg={t.category === 'apple'}>
                <td class="tgt" title={v.title}>
                  <div class="ident" class:mono={v.identIsIP}>
                    <span class="name">{v.ident}</span>
                    {#if v.prov}<span class="prov" title={v.provTitle}>{v.prov}</span>{/if}
                  </div>
                  {#if v.infra}<div class="infra">{v.infra}</div>{/if}
                </td>
                <td class="cat"><span class="cd" style="background:{catColor(t.category)}"></span>{t.category}{#if t.category === 'apple'}<InfoTip text="Apple endpoints are usually background — push, OCSP, iCloud. Inferred from the IP range, not proven."><span class="hedge">?</span></InfoTip>{/if}</td>
                <td class="r mono">{fmtBytes(t.down)}</td>
                <td class="r mono">{fmtBytes(t.up)}</td>
              </tr>
            {/each}
            {#if targets.length === 0}<tr><td colspan="4" class="empty">No traffic in this window.</td></tr>{/if}
          </tbody>
        </table>
      </div>
    </div>
    <div class="card">
      <div class="ch"><h3 class="serif">Recent sites</h3><span class="hint">TLS/QUIC · МСК</span></div>
      {#each recentTls.slice(0, 6) as r}
        <!-- protocol is tls | quic | http (plain HTTP Host from port 80: seen,
             not encrypted — no lock icon for it) -->
        <div class="li">
          <Icon name={r.protocol === 'quic' ? 'activity' : r.protocol === 'http' ? 'dns' : 'lock'} size={13} />
          <span class="g">{r.server_name}</span>
          <span class="proto mono" class:quic={r.protocol === 'quic'} class:http={r.protocol === 'http'}>{(r.protocol || 'tls').toUpperCase()}</span>
          <span class="ago mono">{hhmmMSK(r.ts)}</span>
        </div>
      {/each}
      {#if recentTls.length === 0}<div class="empty">No TLS/QUIC handshakes recently.</div>{/if}
      <div class="ch" style="margin-top:12px"><h3 class="serif">Recent DNS</h3><span class="hint">МСК</span></div>
      {#each recentDns.slice(0, 6) as r}
        <div class="li"><span class="qt mono">{r.qtype}</span><span class="g">{r.query}</span>{#if r.rcode !== 0}<span class="nx">{dnsRcodeName(r.rcode)}</span>{:else}<span class="ago mono">{hhmmMSK(r.ts)}</span>{/if}</div>
      {/each}
      {#if recentDns.length === 0}<div class="empty">No DNS queries recently — likely cached or encrypted (DoH/DoT).</div>{/if}
    </div>
  </div>

  <div class="card">
    <div class="ch"><h3 class="serif">Across the day</h3><span class="hint">24h · by category</span></div>
    <DayTimeline day={data.day ?? []} />
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
  /* DoH/DoT chip: same pill idiom as VerdictBadge, tinted with the dns cyan.
     It marks "the DNS log is incomplete for this client", not a verdict. */
  .edns {
    display: inline-flex;
    align-items: center;
    font-size: 11px;
    padding: 2px 9px;
    border-radius: 999px;
    color: #56b6c2;
    background: color-mix(in srgb, #56b6c2 14%, transparent);
    white-space: nowrap;
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
  .t td.tgt {
    white-space: normal;
  }
  .ident {
    display: flex;
    align-items: baseline;
    gap: 6px;
    min-width: 0;
  }
  .ident .name {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .prov {
    flex: 0 0 auto;
    color: var(--color-muted);
    border: 1px solid var(--color-border);
    border-radius: 4px;
    padding: 0 4px;
    font-size: 9px;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }
  .infra {
    margin-top: 2px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--color-muted);
    font-size: 10.5px;
  }
  .hedge {
    margin-left: 5px;
    color: var(--color-muted);
    border: 1px solid var(--color-border);
    border-radius: 4px;
    padding: 0 4px;
    font-size: 9px;
    cursor: help;
  }
  tr.bg .tgt .name,
  tr.bg .tgt .infra {
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
  @media (max-width: 900px) {
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
    min-width: 0;
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
  /* Fixed layout: these header widths set the columns; Target takes the rest. */
  .t th.c-cat {
    width: 88px;
  }
  .t th.c-num {
    width: 82px;
  }
  .t td {
    padding: 6px 6px 6px 0;
    border-bottom: 1px solid var(--color-border);
    vertical-align: top;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .t td.cat {
    color: var(--color-dim);
  }
  .t tr:last-child td {
    border-bottom: 0;
  }
  .r {
    text-align: right;
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
  /* plain HTTP: unencrypted — warn tint, never the lock's neutral look */
  .proto.http {
    color: var(--color-warn);
    background: color-mix(in srgb, var(--color-warn) 15%, transparent);
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
  .lnk {
    color: var(--color-coral);
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
    .anchor input {
      flex: 1 1 140px;
      width: auto;
    }
    .anchor .now {
      margin-left: 0;
    }
  }
</style>
