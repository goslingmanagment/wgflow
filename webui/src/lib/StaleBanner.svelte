<script>
  import { onMount } from 'svelte'
  import { ago } from './format.js'

  // Shown when a refresh failed but older data is still on screen. Honesty rule:
  // the numbers stay visible (they were real), but they must never masquerade as
  // current — so the banner names the age of what you're looking at.
  let { lastUpdatedAt = null, err = '' } = $props()

  // Local 1s clock so the age keeps counting even while refreshes keep failing.
  let now = $state(Date.now())
  onMount(() => {
    const t = setInterval(() => (now = Date.now()), 1000)
    return () => clearInterval(t)
  })
  const age = $derived.by(() => {
    now
    return lastUpdatedAt ? ago(lastUpdatedAt) : '—'
  })
</script>

<div class="stale" role="status">⚠ Обновление не удалось — на экране данные {age} назад{err ? ` (${err})` : ''}.</div>

<style>
  .stale {
    background: color-mix(in srgb, var(--color-warn) 16%, transparent);
    border: 1px solid color-mix(in srgb, var(--color-warn) 40%, transparent);
    color: var(--color-warn);
    border-radius: 9px;
    padding: 7px 12px;
    font-size: 12px;
    margin-bottom: 10px;
  }
</style>
