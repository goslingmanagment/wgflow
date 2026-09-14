<script>
  import { fmtBytes, hhmmMSK, catColor, sinceSeconds, roleLabel, dirGlyph, dirTitle } from './format.js'
  import { createResource } from './resource.svelte.js'
  import { trackRefreshTick } from './store.svelte.js'
  import StaleBanner from './StaleBanner.svelte'

  // "Чем занимался" — the headline read of the client page: the window's active
  // minutes folded into sessions, each headlined by the service that carried
  // most of its bytes.
  //
  // Every line here is metadata inference and says so. The leader is the
  // biggest NAMED, non-infrastructure service of the stretch — a session whose
  // whole volume was ad/telemetry chatter gets NO leader, because naming one
  // would assert an app the evidence does not show. Bare-IP flows are labeled
  // by network owner and marked «без имени (QUIC)»; a domain is never invented
  // for them, and "новое" means "first trace in this window against a 2h
  // baseline", not "installed" or "started using".
  let { name = '', from = null, since = '15m' } = $props()

  // The rollup-backed timeline is capped server-side; past that it returns a
  // note and null sessions. Don't even ask — say so in one line instead.
  const MAX_WINDOW_SECONDS = 6 * 3600
  // Mirrors timelineInfraCategories in timeline.go: "whose backbone" labels that
  // answer the wrong question ("the person used Cloudflare" is not an activity).
  const INFRA_CATEGORIES = new Set(['cloudflare', 'aws', 'cdn'])
  const SDK_ROLES = new Set(['ads', 'telemetry'])
  const MAX_CHIPS = 5

  const res = createResource()
  const windowSeconds = $derived(from ? Math.max(0, Math.round(Date.now() / 1000 - from)) : sinceSeconds(since))
  const tooWide = $derived(windowSeconds > MAX_WINDOW_SECONDS)

  $effect(() => {
    trackRefreshTick()
    if (!name || tooWide) return
    const u = new URLSearchParams()
    if (from) u.set('from', String(from))
    else u.set('since', since)
    res.load('/api/clients/' + encodeURIComponent(name) + '/timeline?' + u.toString())
  })

  const data = $derived(res.data)
  const gapMinutes = $derived(Math.max(1, Math.round((data?.gap_seconds || 0) / 60)))

  let openAt = $state(null)
  function toggle(s) {
    openAt = openAt === s.from ? null : s.from
  }

  const svcKey = (x) => `${x.service}|${x.role}`

  // A service we could not name is labeled by the network that owns the address
  // — "Google · без имени (QUIC)" — and never by a domain we did not see.
  function serviceLabel(x, unnamed) {
    if (!x) return ''
    if (unnamed) return x.service ? `${x.service} · без имени (QUIC)` : 'без имени (QUIC)'
    return x.service || 'без имени (QUIC)'
  }

  // The session rows carry bytes and direction but not the per-minute
  // `unnamed`/`new` flags, so those are read back off the minutes the session
  // spans. Without this a bare-IP aggregate would silently lose its «без имени»
  // label at the session level and read like a named destination.
  function marksIn(session) {
    const marks = new Map()
    for (const m of data?.minutes || []) {
      if (m.t < session.from || m.t >= session.to) continue
      for (const x of m.services || []) {
        const k = svcKey(x)
        const cur = marks.get(k) || { unnamed: false, fresh: false }
        if (x.unnamed) cur.unnamed = true
        if (x.new) cur.fresh = true
        marks.set(k, cur)
      }
    }
    return marks
  }

  // One view model per session: the leader line, the supporting chips (named or
  // owner-labeled services that are neither the leader, nor ad/telemetry
  // chatter — that gets its own muted line — nor pure infrastructure), and the
  // full service list for the expanded detail.
  const sessions = $derived.by(() =>
    (data?.sessions ?? []).map((s) => {
      const marks = marksIn(s)
      const mark = (x) => marks.get(svcKey(x)) || { unnamed: false, fresh: false }
      const newSet = new Set(s.new_services || [])
      const seen = new Set()
      if (s.leader) seen.add(svcKey(s.leader))
      const chips = []
      for (const x of s.services || []) {
        if (SDK_ROLES.has(x.role) || INFRA_CATEGORIES.has(x.category)) continue
        const k = svcKey(x)
        if (seen.has(k)) continue
        seen.add(k)
        chips.push({ ...x, label: serviceLabel(x, mark(x).unnamed) })
        if (chips.length >= MAX_CHIPS) break
      }
      return {
        ...s,
        chips,
        leaderLabel: s.leader ? serviceLabel(s.leader, mark(s.leader).unnamed) : 'только SDK/фон — ведущего сервиса нет',
        detail: (s.services || []).map((x) => {
          const m = mark(x)
          return { ...x, label: serviceLabel(x, m.unnamed), unnamed: m.unnamed, fresh: m.fresh || newSet.has(x.service) }
        }),
      }
    })
  )
</script>

<div class="card">
  <div class="ch">
    <h3 class="serif">Чем занимался</h3>
    <span class="hint">сессии по метаданным · вероятно</span>
  </div>

  {#if tooWide}
    <div class="dim line">Окно шире 6 часов — сессии не строятся; выберите окно до 6 часов или поставьте якорь «после HH:MM».</div>
  {:else if res.err && !data}
    <div class="err line">Не удалось построить сессии. ({res.err})</div>
  {:else if !data}
    <div class="dim line">Загрузка…</div>
  {:else}
    {#if res.stale}
      <StaleBanner lastUpdatedAt={res.lastUpdatedAt} err={res.err} />
    {/if}
    {#if data.logger_ok === false}
      <div class="outage" role="alert">⚠ Логгер не подтверждён — пустые сессии могут быть сбоем, не тишиной. Тишина не доказана; проверьте System.</div>
    {/if}
    {#if data.db_ok === false}
      <div class="warn" role="status">⚠ Rollup недоступен — сессии не построены. Это не тишина, а отсутствие данных.</div>
    {/if}
    {#if data.note}
      <div class="dim note">{data.note}</div>
    {/if}

    {#if sessions.length === 0}
      {#if data.db_ok !== false}
        <div class="dim line">нет активных минут в окне</div>
      {/if}
    {:else}
      <div class="sessions">
        {#each sessions as s (s.from)}
          <button class="s" class:open={openAt === s.from} onclick={() => toggle(s)}>
            <span class="when mono">{hhmmMSK(s.from)}–{hhmmMSK(s.to)} <span class="msk">МСК</span></span>
            <span class="body">
              <span class="lead" class:none={!s.leader}>
                {#if s.leader}<span class="cd" style="background:{catColor(s.leader.category)}" title={s.leader.category}></span>{/if}{s.leaderLabel}{#if s.leader && roleLabel(s.leader.role)}<span class="role" title="роль по имени хоста — вероятно {roleLabel(s.leader.role)}">{roleLabel(s.leader.role)}</span>{/if}
              </span>
              <span class="by mono"
                >{fmtBytes(s.bytes)}{#if dirGlyph(s.direction)}<span class="dir" title={dirTitle(s.direction)}>{dirGlyph(s.direction)}</span>{/if}</span
              >
              {#each s.chips as c}
                <span class="chip"
                  ><span class="cd" style="background:{catColor(c.category)}" title={c.category}></span>{c.label}{#if roleLabel(c.role)}<span class="role" title="роль по имени хоста — вероятно {roleLabel(c.role)}">{roleLabel(c.role)}</span>{/if}</span
                >
              {/each}
              {#if s.sdk?.length}
                <span class="sdk" title="Рекламные/аналитические SDK отчитываются из запущенного приложения — признак, что что-то было открыто, но не доказательство действия человека."
                  >+ реклама/аналитика: {s.sdk.join(', ')}</span
                >
              {/if}
              {#if s.new_services?.length}
                <span class="new" title="Первый след в этом окне против 2-часовой базы — «новое здесь», не «начал пользоваться».">новое: {s.new_services.join(', ')}</span>
              {/if}
            </span>
            <span class="car">{openAt === s.from ? '▾' : '▸'}</span>
          </button>
          {#if openAt === s.from}
            <div class="det">
              <div class="dline mono">{s.minutes} мин · ↓{fmtBytes(s.down)} · ↑{fmtBytes(s.up)}</div>
              {#each s.detail as x}
                <div class="drow">
                  <span class="cd" style="background:{catColor(x.category)}" title={x.category}></span>
                  <span class="dn">{x.label}</span>
                  {#if roleLabel(x.role)}<span class="role">{roleLabel(x.role)}</span>{/if}
                  {#if x.fresh}<span class="tag new" title="первый след в этом окне против 2-часовой базы">новое</span>{/if}
                  {#if x.unnamed}<span class="tag" title="bare IP без SNI — имя сети, не домен">без имени</span>{/if}
                  <span class="db mono"
                    >{fmtBytes(x.bytes)}{#if dirGlyph(x.direction)}<span class="dir" title={dirTitle(x.direction)}>{dirGlyph(x.direction)}</span>{/if}</span
                  >
                </div>
              {/each}
              {#if !s.detail.length}<span class="dim">без названных сервисов в этой сессии</span>{/if}
            </div>
          {/if}
        {/each}
      </div>
      <div class="foot">{sessions.length} сесс. · пауза ≥ {gapMinutes} мин делит сессии · ведущий сервис — по байтам, не по намерению</div>
    {/if}
  {/if}
</div>

<style>
  .card {
    background: var(--color-s1);
    border: 1px solid var(--color-border);
    border-radius: 12px;
    padding: 14px 16px;
    margin-bottom: 14px;
    min-width: 0;
  }
  .ch {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 10px;
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
  .line {
    font-size: 12.5px;
    padding: 4px 0;
  }
  .dim {
    color: var(--color-muted);
  }
  .err {
    color: var(--color-danger);
  }
  .note {
    font-size: 11.5px;
    margin-bottom: 8px;
  }
  .outage {
    background: color-mix(in srgb, var(--color-danger) 14%, transparent);
    border: 1px solid color-mix(in srgb, var(--color-danger) 40%, transparent);
    color: var(--color-danger);
    border-radius: 9px;
    padding: 8px 11px;
    font-size: 12px;
    margin-bottom: 10px;
  }
  .warn {
    background: color-mix(in srgb, var(--color-warn) 16%, transparent);
    border: 1px solid color-mix(in srgb, var(--color-warn) 40%, transparent);
    color: var(--color-warn);
    border-radius: 9px;
    padding: 8px 11px;
    font-size: 12px;
    margin-bottom: 10px;
  }
  .sessions {
    display: flex;
    flex-direction: column;
  }
  .s {
    display: grid;
    grid-template-columns: 118px 1fr 12px;
    gap: 10px;
    align-items: start;
    width: 100%;
    padding: 7px 4px;
    background: transparent;
    border: 0;
    border-bottom: 1px solid var(--color-border);
    border-radius: 5px;
    cursor: pointer;
    text-align: left;
    color: inherit;
    font: inherit;
  }
  .s:last-child {
    border-bottom: 0;
  }
  .s:hover,
  .s.open {
    background: var(--color-s2);
  }
  .when {
    font-size: 11.5px;
    color: var(--color-dim);
    white-space: nowrap;
    padding-top: 2px;
  }
  .when .msk {
    color: var(--color-muted);
    font-size: 10px;
  }
  .body {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
    min-width: 0;
  }
  .lead {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 13px;
    font-weight: 500;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .lead.none {
    color: var(--color-muted);
    font-weight: 400;
    font-style: italic;
  }
  .by {
    font-size: 11.5px;
    color: var(--color-dim);
    white-space: nowrap;
  }
  .dir {
    color: var(--color-muted);
    margin-left: 2px;
    cursor: help;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    max-width: 100%;
    border: 1px solid var(--color-border);
    border-radius: 999px;
    padding: 1px 9px;
    font-size: 11px;
    color: var(--color-dim);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .cd {
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 2px;
    flex: 0 0 auto;
  }
  .role {
    color: var(--color-muted);
    background: var(--color-s3);
    border-radius: 4px;
    padding: 0 5px;
    font-size: 9.5px;
    flex: 0 0 auto;
  }
  .sdk {
    font-size: 11px;
    color: var(--color-muted);
    cursor: help;
  }
  .new {
    font-size: 11px;
    color: var(--color-warn);
    cursor: help;
  }
  .car {
    color: var(--color-muted);
    font-size: 10px;
    padding-top: 3px;
  }
  .det {
    padding: 4px 8px 10px 132px;
    font-size: 11.5px;
  }
  .dline {
    color: var(--color-muted);
    margin-bottom: 4px;
  }
  .drow {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 2px 0;
    color: var(--color-dim);
    min-width: 0;
  }
  .drow .dn {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .drow .db {
    margin-left: auto;
    white-space: nowrap;
  }
  .tag {
    border: 1px solid var(--color-border);
    border-radius: 4px;
    padding: 0 5px;
    font-size: 9.5px;
    color: var(--color-muted);
    flex: 0 0 auto;
  }
  .tag.new {
    color: var(--color-warn);
    border-color: color-mix(in srgb, var(--color-warn) 40%, transparent);
    cursor: default;
  }
  .foot {
    margin-top: 8px;
    font-size: 11px;
    color: var(--color-muted);
  }

  @media (max-width: 640px) {
    .s {
      grid-template-columns: 1fr 12px;
      gap: 4px 8px;
    }
    .when {
      grid-column: 1 / 2;
      padding-top: 0;
    }
    .body {
      grid-column: 1 / -1;
    }
    .det {
      padding-left: 6px;
    }
  }
</style>
