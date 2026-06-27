<script>
  import { ui } from './store.svelte.js'
  import { WINDOWS } from './format.js'
  let { day = true } = $props()
  const options = $derived(day ? WINDOWS : WINDOWS.filter((w) => w.value !== '24h'))
</script>

<div class="seg" role="group" aria-label="Time window">
  {#each options as w}
    <button class:on={ui.since === w.value} onclick={() => (ui.since = w.value)}>{w.label}</button>
  {/each}
</div>

<style>
  .seg {
    display: inline-flex;
    align-items: stretch;
    border: 1px solid var(--color-border);
    border-radius: 8px;
    max-width: 100%;
    overflow-x: auto;
    scrollbar-width: none;
  }
  .seg::-webkit-scrollbar {
    display: none;
  }
  .seg button {
    flex: 0 0 auto;
    background: transparent;
    border: 0;
    color: var(--color-dim);
    padding: 5px 9px;
    cursor: pointer;
    font-family: var(--font-mono);
    font-size: 12px;
    white-space: nowrap;
  }
  .seg button:hover {
    color: var(--color-text);
  }
  .seg button.on {
    background: var(--color-coral-dim);
    color: var(--color-coral);
  }
</style>
