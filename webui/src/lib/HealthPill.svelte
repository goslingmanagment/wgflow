<script>
  import { health } from './store.svelte.js'
  // The single status chip used everywhere. Color + label are driven by the
  // shared logger-health verdict, so no screen can show a hardcoded green dot.
  let { rate = false } = $props()
  const CLS = { live: 'ok', stale: 'warn', down: 'down' }
  const LABEL = { live: 'live', stale: 'stale', down: 'offline' }
</script>

<span class="hp {CLS[health.status] || 'down'}" title={health.detail}>
  <span class="dot" class:pulse={health.status === 'live'}></span>
  {#if rate && health.status === 'live' && health.mbit != null}
    {health.mbit.toFixed(1)}<small>Mbit/s</small>
  {:else}
    {LABEL[health.status] || 'offline'}
  {/if}
</span>

<style>
  .hp {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: var(--font-mono);
    font-size: 12px;
    padding: 3px 10px;
    border-radius: 999px;
    white-space: nowrap;
  }
  .hp small {
    color: var(--color-dim);
    font-size: 10px;
    margin-left: 3px;
  }
  .hp .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: currentColor;
    flex: 0 0 auto;
  }
  .hp.ok {
    color: var(--color-ok);
    background: color-mix(in srgb, var(--color-ok) 14%, transparent);
  }
  .hp.warn {
    color: var(--color-warn);
    background: color-mix(in srgb, var(--color-warn) 16%, transparent);
  }
  .hp.down {
    color: var(--color-danger);
    background: color-mix(in srgb, var(--color-danger) 15%, transparent);
  }
</style>
