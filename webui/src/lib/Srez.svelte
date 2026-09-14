<script>
  import { fmtBytes, hhmmMSK } from './format.js'
  import { createResource } from './resource.svelte.js'
  import { aggVerdict, personOf } from './verdict.js'
  import { trackRefreshTick } from './store.svelte.js'
  import StaleBanner from './StaleBanner.svelte'

  // The Срез drawer. It assembles ONE plain-text verdict block, renders that
  // exact string, and copies that exact string — so the screen and the clipboard
  // can never disagree, and the honesty caveat always travels inside the copied
  // text. Verdicts are refused-as-confident when logger_ok is false.
  // `names` is a comma-joined string (not an array) so an unchanged client list
  // compares equal across refresh ticks and doesn't refire the load effect.
  let { open = false, onClose = () => {}, names = '' } = $props()

  let win = $state('5m')
  let copied = $state(false)
  let copyErr = $state(false)
  let snapWin = $state('')
  let drawerEl = $state(null)
  const res = createResource()
  const snap = $derived(res.data)

  // Move focus into the drawer on open and hand it back on close (no full focus
  // trap — this is a single-owner home panel, Escape + backdrop are enough).
  let prevFocus = null
  $effect(() => {
    if (open && drawerEl) {
      prevFocus = document.activeElement
      drawerEl.focus()
      return () => {
        prevFocus?.focus?.()
        prevFocus = null
      }
    }
  })

  const CAVEAT =
    '⚠ inferred из метаданных. HTTPS не виден; QUIC даёт IP без имени; ' +
    '«проснулась» недоказуемо — только первый заметный след. Байты ~94–95% (GSO/GRO).'

  $effect(() => {
    trackRefreshTick()
    const w = win
    const n = names
    if (open) load(w, n)
  })

  async function load(w, clients) {
    // A new window must never show the old window's text under its label —
    // blank first (the copy button copies exactly what's on screen).
    if (snapWin && snapWin !== w) {
      res.reset()
      snapWin = ''
    }
    const u = new URLSearchParams({ since: w })
    if (clients) u.set('clients', clients)
    const applied = await res.load('/api/snapshot?' + u.toString())
    if (applied) snapWin = w
  }

  const WL = { '5m': '5 минут', '10m': '10 минут', '15m': '15 минут', '30m': '30 минут' }
  const windowLabel = (w) => WL[w] || 'окно ' + w
  const deviceLabel = (n) => (n.indexOf('-') > 0 ? n.slice(n.indexOf('-') + 1) : n)

  function statusWord(v, loggerOk) {
    if (!v) return '—'
    if (!loggerOk) return v.status === 'silent' ? 'тишина не подтверждена' : 'не подтверждено (логгер молчит)'
    const hedged = v.confidence !== 'high'
    if (v.status === 'active') return hedged ? 'вероятно активна' : 'активна'
    if (v.status === 'likely-background') return hedged ? 'вероятно фон' : 'фон'
    if (v.status === 'silent') return 'тишина'
    if (v.status === 'unknown') return 'нет вердикта (rollup недоступен)'
    return v.status
  }

  const SDK_ROLES = new Set(['ads', 'telemetry'])

  function deviceDoing(c, loggerOk) {
    if (c.total === 0) return statusWord(c.verdict, loggerOk)
    const cat = c.cats?.[0]?.category || ''
    // Newer backends answer with services, not raw SNIs: name up to three real
    // destinations and fold every ad/telemetry host into one "+ реклама" — a
    // tail of AppLovin/Vungle hostnames told the reader nothing about the person.
    const services = c.recent_services
    if (Array.isArray(services) && services.length) {
      const named = []
      let sdk = false
      for (const s of services) {
        if (SDK_ROLES.has(s.role)) {
          sdk = true
          continue
        }
        const label = s.service || s.host
        if (!label || named.includes(label)) continue
        if (named.length < 3) named.push(label)
      }
      const parts = [cat, ...named]
      if (sdk) parts.push('+ реклама')
      // bytes, but nothing we could name — never invent a domain
      if (!named.length && !sdk) parts.push('без имени (QUIC)')
      return parts.filter(Boolean).join(' · ')
    }
    // Older backend (no recent_services): raw SNIs, as before.
    const sites = (c.recent_sites || []).slice(0, 3)
    if (sites.length) return [cat, ...sites].filter(Boolean).join(' · ')
    return [cat, 'без имени (QUIC)'].filter(Boolean).join(' · ')
  }

  function personConclusion(devices, loggerOk) {
    if (!loggerOk) return 'логгер не подтверждён — активность и тишина не доказаны'
    const names = (ds) => ds.map((d) => deviceLabel(d.name)).join(', ')
    const active = devices.filter((d) => d.verdict?.status === 'active')
    const bg = devices.filter((d) => d.verdict?.status === 'likely-background')
    const silent = devices.filter((d) => d.verdict?.status === 'silent')
    const unknown = devices.filter((d) => d.verdict?.status === 'unknown')
    if (active.length) {
      const others = [...bg, ...silent]
      return `активна с ${names(active)}` + (others.length ? `, ${names(others)} — не участвует` : '')
    }
    if (bg.length) return `вероятно фон (${names(bg)}), не человек`
    // No verdict is not silence — the rollup DB was unreachable, nothing proven.
    if (unknown.length) return 'вердикт недоступен (rollup БД не отвечает) — тишина не доказана'
    return 'тишина (логгер исправен, 0 байт)'
  }

  const text = $derived.by(() => {
    if (!snap) return ''
    const out = []
    if (!snap.logger_ok) out.push('⚠ ЛОГГЕР НЕ ПОДТВЕРЖДЁН — выводы ненадёжны, тишина не доказана.', '')
    out.push(`Срез на ${hhmmMSK(snap.generated_at)} МСК, последние ${windowLabel(snapWin)}.`, '')
    const groups = {}
    // person comes from the server (clients.yaml or its prefix fallback)
    for (const c of snap.clients || []) (groups[c.person || personOf(c.name)] ||= []).push(c)
    const people = Object.entries(groups)
      .map(([person, devices]) => ({ person, devices, total: devices.reduce((s, d) => s + d.total, 0) }))
      .sort((a, b) => b.total - a.total)
    if (!people.length) out.push('Нет устройств с трафиком в окне.')
    for (const { person, devices, total } of people) {
      devices.sort((a, b) => b.total - a.total)
      out.push(`${person} · ${statusWord(aggVerdict(devices), snap.logger_ok)} · ${fmtBytes(total)}`)
      // "(шифрованный DNS)" travels inside the copied text: the reader must
      // know the domain list for that device is incomplete, not exhaustive.
      for (const c of devices) out.push(`  ${deviceLabel(c.name)}  ${fmtBytes(c.total)} · ${deviceDoing(c, snap.logger_ok)}${c.encrypted_dns ? ' (шифрованный DNS)' : ''}`)
      out.push(`  Вывод: ${personConclusion(devices, snap.logger_ok)}`)
      out.push('─'.repeat(44))
    }
    out.push('', CAVEAT)
    return out.join('\n')
  })

  function flash() {
    copied = true
    setTimeout(() => (copied = false), 1500)
  }
  async function copy() {
    // Never touch `err` here — that would replace the Срез with an error.
    try {
      await navigator.clipboard.writeText(text)
      flash()
      return
    } catch {}
    try {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.focus()
      ta.select()
      const ok = document.execCommand('copy')
      document.body.removeChild(ta)
      if (ok) return flash()
    } catch {}
    copyErr = true
    setTimeout(() => (copyErr = false), 2500)
  }
</script>

<svelte:window onkeydown={(e) => open && e.key === 'Escape' && onClose()} />

{#if open}
  <div class="backdrop" onclick={onClose} role="presentation"></div>
  <div class="drawer" role="dialog" aria-modal="true" aria-label="Срез" tabindex="-1" bind:this={drawerEl}>
    <header>
      <div class="title serif">Срез <span>· последние {win}</span></div>
      <div class="acts">
        <button class="ic" title="Обновить" onclick={() => load(win, names)} aria-label="Обновить">↻</button>
        <button class="copy" class:done={copied} onclick={copy} disabled={!text}>{copied ? 'скопировано' : 'copy'}</button>
        <button class="ic" title="Закрыть" onclick={onClose} aria-label="Закрыть">✕</button>
      </div>
    </header>
    <div class="seg">
      {#each ['5m', '10m', '30m'] as w}
        <button class:on={win === w} onclick={() => (win = w)}>{w}</button>
      {/each}
    </div>
    {#if snap && !snap.logger_ok}
      <div class="warn">⚠ Логгер не подтверждён — выводы ненадёжны, тишина не доказана.</div>
    {/if}
    {#if copyErr}
      <div class="copyhint">Не удалось скопировать автоматически — выделите текст и ⌘/Ctrl+C.</div>
    {/if}
    {#if res.err && !snap}
      <p class="err">Не удалось получить срез. ({res.err})</p>
    {:else if !snap}
      <p class="dim">Загрузка…</p>
    {:else}
      {#if res.stale}
        <div class="stalepad"><StaleBanner lastUpdatedAt={res.lastUpdatedAt} err={res.err} /></div>
      {/if}
      <pre class="srez">{text}</pre>
    {/if}
  </div>
{/if}

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.45);
    z-index: 40;
  }
  .drawer {
    position: fixed;
    top: 0;
    right: 0;
    height: 100vh;
    height: 100dvh; /* iOS Safari: real visible height, not the toolbar-inflated 100vh */
    width: min(460px, 94vw);
    background: var(--color-s1);
    border-left: 1px solid var(--color-border);
    z-index: 41;
    display: flex;
    flex-direction: column;
    box-shadow: -16px 0 40px rgba(0, 0, 0, 0.35);
    overscroll-behavior: contain;
  }
  .drawer:focus {
    outline: none; /* programmatic focus target only; a ring around the whole drawer is noise */
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 14px 16px;
    padding-top: max(14px, env(safe-area-inset-top));
    padding-right: max(16px, env(safe-area-inset-right));
    border-bottom: 1px solid var(--color-border);
  }
  .title {
    font-size: 18px;
    font-weight: 500;
  }
  .title span {
    color: var(--color-muted);
    font-size: 12px;
    font-family: var(--font-mono);
  }
  .acts {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .ic {
    background: transparent;
    border: 1px solid var(--color-border);
    border-radius: 7px;
    color: var(--color-dim);
    width: 30px;
    height: 30px;
    cursor: pointer;
    font-size: 14px;
  }
  .ic:hover {
    color: var(--color-text);
    background: var(--color-s2);
  }
  .copy {
    background: var(--color-coral);
    color: #fff;
    border: 0;
    border-radius: 7px;
    padding: 6px 14px;
    cursor: pointer;
    font-size: 13px;
    font-weight: 500;
  }
  .copy.done {
    background: var(--color-ok);
  }
  .copy:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .seg {
    display: inline-flex;
    margin: 12px 16px 0;
    border: 1px solid var(--color-border);
    border-radius: 8px;
    width: max-content;
  }
  .seg button {
    background: transparent;
    border: 0;
    color: var(--color-dim);
    padding: 5px 12px;
    cursor: pointer;
    font-family: var(--font-mono);
    font-size: 12px;
  }
  .seg button.on {
    background: var(--color-coral-dim);
    color: var(--color-coral);
  }
  .warn {
    margin: 12px 16px 0;
    background: color-mix(in srgb, var(--color-warn) 16%, transparent);
    border: 1px solid color-mix(in srgb, var(--color-warn) 40%, transparent);
    color: var(--color-warn);
    border-radius: 8px;
    padding: 8px 11px;
    font-size: 12px;
  }
  .srez {
    flex: 1;
    overflow: auto;
    overscroll-behavior: contain;
    margin: 12px 0 0;
    padding: 4px 16px calc(18px + env(safe-area-inset-bottom));
    padding-right: max(16px, env(safe-area-inset-right));
    font-family: var(--font-mono);
    font-size: 12px;
    line-height: 1.55;
    color: var(--color-text);
    white-space: pre-wrap;
    word-break: break-word;
  }
  .copyhint {
    margin: 10px 16px 0;
    color: var(--color-muted);
    font-size: 11.5px;
  }
  .stalepad {
    margin: 12px 16px 0;
  }
  .err {
    color: var(--color-danger);
    padding: 0 16px;
  }
  .dim {
    color: var(--color-muted);
    padding: 0 16px;
  }
</style>
