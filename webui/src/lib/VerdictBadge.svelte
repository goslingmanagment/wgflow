<script>
  // Renders the per-device verdict. Honesty is structural: the label is hedged
  // by confidence ("вероятно активна"), it always carries an "inferred" marker,
  // the firing rule + standing caveat live in the tooltip, and a SILENT verdict
  // is downgraded to "тишина не подтверждена" whenever the logger isn't healthy.
  let { verdict = null, loggerOk = true, compact = false } = $props()

  const CAVEAT = ' — предположение по метаданным; не доказывает действие человека.'

  const view = $derived.by(() => {
    const v = verdict
    if (!v || !v.status) return { cls: 'silent', label: '—', title: 'нет данных' }
    const title = (v.reasons || []).join(' · ') + CAVEAT
    const hedged = v.confidence !== 'high'
    if (v.status === 'active') return { cls: 'active', label: hedged ? 'вероятно активна' : 'активна', title }
    if (v.status === 'likely-background') return { cls: 'bg', label: hedged ? 'вероятно фон' : 'фон', title }
    if (v.status === 'silent') {
      if (!loggerOk) return { cls: 'unconfirmed', label: 'тишина не подтв.', title: 'логгер не подтверждён — тишина недоказуема' + CAVEAT }
      return { cls: 'silent', label: 'тишина', title }
    }
    return { cls: 'silent', label: v.status, title }
  })
</script>

<span class="vb {view.cls}" class:compact title={view.title}>
  <span class="dot"></span>{view.label}<span class="inf">inferred</span>
</span>

<style>
  .vb {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    padding: 3px 10px;
    border-radius: 999px;
    white-space: nowrap;
  }
  .vb.compact {
    font-size: 11px;
    padding: 1px 8px;
    gap: 5px;
  }
  .vb .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: currentColor;
    flex: 0 0 auto;
  }
  .vb.compact .dot {
    width: 6px;
    height: 6px;
  }
  .vb .inf {
    color: var(--color-muted);
    font-size: 9px;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }
  .vb.active {
    color: var(--color-coral);
    background: var(--color-coral-dim);
  }
  .vb.bg {
    color: var(--color-warn);
    background: color-mix(in srgb, var(--color-warn) 15%, transparent);
  }
  .vb.silent {
    color: var(--color-muted);
    background: var(--color-s2);
  }
  .vb.unconfirmed {
    color: var(--color-danger);
    background: color-mix(in srgb, var(--color-danger) 15%, transparent);
  }
</style>
