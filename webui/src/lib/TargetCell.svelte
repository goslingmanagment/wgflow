<script module>
  // Shared td-title helpers so the routes' tooltips can't drift either.
  export function appTitle(row) {
    return row.app_target || (!row.is_ip ? row.target : '')
  }
  export function infraTitle(row) {
    return row.resolved_target ? `${row.target} · ${row.resolved_target}` : row.target
  }
</script>

<script>
  // One renderer for the App/Infra target pair, used by ClientDetail's Top
  // targets and the Traffic table. The two inline copies had already diverged
  // once ("no PTR" vs "no hostname (QUIC)") — the wording lives here now.
  let { row = {}, kind = 'app' } = $props()
</script>

{#if kind === 'app'}
  <span class="target-main">{row.app_target || (!row.is_ip ? row.target : '—')}</span>
  {#if row.attribution_source}
    <span class="target-meta">
      <span>{row.attribution_source}</span>
      {#if row.attribution_candidates?.length > 1}
        <span class="org" title={row.attribution_candidates.join(', ')}>+{row.attribution_candidates.length - 1}</span>
      {/if}
    </span>
  {/if}
{:else}
  <span class="target-main">{row.is_ip ? row.target : 'direct'}</span>
  <span class="target-meta">
    {#if row.resolved_target}<span>{row.resolved_target}</span>{:else if row.is_ip}<span>no hostname{row.proto === 'udp' ? ' (QUIC)' : ''}</span>{/if}
    {#if row.target_org}<span class="org">{row.target_org}</span>{/if}
  </span>
{/if}

<style>
  .target-main {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .target-meta {
    display: flex;
    align-items: center;
    gap: 5px;
    min-height: 14px;
    overflow: hidden;
    color: var(--color-muted);
    font-size: 10.5px;
    white-space: nowrap;
  }
  .target-meta > span:first-child {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .org {
    color: var(--color-muted);
    border: 1px solid var(--color-border);
    border-radius: 4px;
    padding: 0 4px;
    font-size: 10px;
    flex: 0 0 auto;
  }
</style>
