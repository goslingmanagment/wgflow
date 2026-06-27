<script>
  import { getJSON, fmtBytes, hhmmMSK } from './format.js'

  // The Срез drawer. It assembles ONE plain-text verdict block, renders that
  // exact string, and copies that exact string — so the screen and the clipboard
  // can never disagree, and the honesty caveat always travels inside the copied
  // text. Verdicts are refused-as-confident when logger_ok is false.
  let { open = false, onClose = () => {}, names = [] } = $props()

  let win = $state('5m')
  let snap = $state(null)
  let err = $state(null)
  let loading = $state(false)
  let copied = $state(false)
  let copyErr = $state(false)

  const CAVEAT =
    '⚠ inferred из метаданных. HTTPS не виден; QUIC даёт IP без имени; ' +
    '«проснулась» недоказуемо — только первый заметный след. Байты ~94–95% (GSO/GRO).'

  $effect(() => {
    if (open) load(win, names.join(','))
  })

  async function load(w, clients) {
    loading = true
    try {
      const u = new URLSearchParams({ since: w })
      if (clients) u.set('clients', clients)
      snap = await getJSON('/api/snapshot?' + u.toString())
      err = null
    } catch (e) {
      err = e.message
    } finally {
      loading = false
    }
  }

  const WL = { '5m': '5 минут', '10m': '10 минут', '15m': '15 минут', '30m': '30 минут' }
  const windowLabel = (w) => WL[w] || 'окно ' + w
  const personOf = (n) => (n.indexOf('-') > 0 ? n.slice(0, n.indexOf('-')) : n)
  const deviceLabel = (n) => (n.indexOf('-') > 0 ? n.slice(n.indexOf('-') + 1) : n)

  function statusWord(v, loggerOk) {
    if (!v) return '—'
    if (!loggerOk) return v.status === 'silent' ? 'тишина не подтверждена' : 'не подтверждено (логгер молчит)'
    const hedged = v.confidence !== 'high'
    if (v.status === 'active') return hedged ? 'вероятно активна' : 'активна'
    if (v.status === 'likely-background') return hedged ? 'вероятно фон' : 'фон'
    if (v.status === 'silent') return 'тишина'
    return v.status
  }

  function deviceDoing(c, loggerOk) {
    if (c.total === 0) return statusWord(c.verdict, loggerOk)
    const sites = (c.recent_sites || []).slice(0, 3)
    const cat = c.cats?.[0]?.category || ''
    if (sites.length) return [cat, ...sites].filter(Boolean).join(' · ')
    // bytes but no named domains — never invent one
    return [cat, 'без имени (QUIC)'].filter(Boolean).join(' · ')
  }

  function personVerdict(devices) {
    const order = { active: 3, 'likely-background': 2, silent: 1 }
    let best = null
    for (const d of devices) {
      if (!best || (order[d.verdict?.status] || 0) > (order[best.status] || 0)) best = d.verdict
    }
    return best
  }

  function personConclusion(devices, loggerOk) {
    if (!loggerOk) return 'логгер не подтверждён — активность и тишина не доказаны'
    const names = (ds) => ds.map((d) => deviceLabel(d.name)).join(', ')
    const active = devices.filter((d) => d.verdict?.status === 'active')
    const bg = devices.filter((d) => d.verdict?.status === 'likely-background')
    const silent = devices.filter((d) => d.verdict?.status === 'silent')
    if (active.length) {
      const others = [...bg, ...silent]
      return `активна с ${names(active)}` + (others.length ? `, ${names(others)} — не участвует` : '')
    }
    if (bg.length) return `вероятно фон (${names(bg)}), не человек`
    return 'тишина (логгер исправен, 0 байт)'
  }

  const text = $derived.by(() => {
    if (!snap) return ''
    const out = []
    if (!snap.logger_ok) out.push('⚠ ЛОГГЕР НЕ ПОДТВЕРЖДЁН — выводы ненадёжны, тишина не доказана.', '')
    out.push(`Срез на ${hhmmMSK(snap.generated_at)} МСК, последние ${windowLabel(win)}.`, '')
    const groups = {}
    for (const c of snap.clients || []) (groups[personOf(c.name)] ||= []).push(c)
    const people = Object.entries(groups)
      .map(([person, devices]) => ({ person, devices, total: devices.reduce((s, d) => s + d.total, 0) }))
      .sort((a, b) => b.total - a.total)
    if (!people.length) out.push('Нет устройств с трафиком в окне.')
    for (const { person, devices, total } of people) {
      devices.sort((a, b) => b.total - a.total)
      out.push(`${person} · ${statusWord(personVerdict(devices), snap.logger_ok)} · ${fmtBytes(total)}`)
      for (const c of devices) out.push(`  ${deviceLabel(c.name)}  ${fmtBytes(c.total)} · ${deviceDoing(c, snap.logger_ok)}`)
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

{#if open}
  <div class="backdrop" onclick={onClose} role="presentation"></div>
  <aside class="drawer" role="dialog" aria-label="Срез">
    <header>
      <div class="title serif">Срез <span>· последние {win}</span></div>
      <div class="acts">
        <button class="ic" title="Обновить" onclick={() => load(win, names.join(','))} aria-label="Обновить">↻</button>
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
    {#if err}
      <p class="err">Не удалось получить срез. ({err})</p>
    {:else if loading && !snap}
      <p class="dim">Загрузка…</p>
    {:else}
      <pre class="srez">{text}</pre>
    {/if}
  </aside>
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
    width: min(460px, 94vw);
    background: var(--color-s1);
    border-left: 1px solid var(--color-border);
    z-index: 41;
    display: flex;
    flex-direction: column;
    box-shadow: -16px 0 40px rgba(0, 0, 0, 0.35);
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 14px 16px;
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
    margin: 12px 0 0;
    padding: 4px 16px 18px;
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
  .err {
    color: var(--color-danger);
    padding: 0 16px;
  }
  .dim {
    color: var(--color-muted);
    padding: 0 16px;
  }
</style>
