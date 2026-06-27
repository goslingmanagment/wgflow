<script>
  import { setAutoRefresh, ui } from './store.svelte.js'
  import Icon from './Icon.svelte'
</script>

<button
  class="auto"
  class:on={ui.autoRefresh}
  title={ui.autoRefresh ? 'Автообновление включено' : 'Автообновление выключено'}
  aria-label={ui.autoRefresh ? 'Выключить автообновление' : 'Включить автообновление'}
  aria-pressed={ui.autoRefresh}
  onclick={() => setAutoRefresh(!ui.autoRefresh)}
>
  <Icon name="refresh" size={15} />
  <span>{ui.autoRefresh ? '5s' : 'off'}</span>
</button>

<style>
  .auto {
    width: 54px;
    height: 30px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 5px;
    border: 1px solid var(--color-border);
    border-radius: 8px;
    background: transparent;
    color: var(--color-dim);
    cursor: pointer;
    font-family: var(--font-mono);
    font-size: 11px;
    line-height: 1;
    flex: 0 0 auto;
  }
  .auto:hover {
    color: var(--color-text);
  }
  .auto.on {
    background: var(--color-accent-dim);
    color: var(--color-accent);
    border-color: transparent;
  }
</style>
