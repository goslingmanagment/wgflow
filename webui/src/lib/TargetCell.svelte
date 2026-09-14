<script module>
  // Shared td-title helpers so the routes' tooltips can't drift either.
  export const SDK_TARGET = 'sdk'
  export function appHost(row) {
    return row.app_target || (!row.is_ip ? row.target : '')
  }
  export function appTitle(row) {
    if (row.target === SDK_TARGET) {
      const names = (row.member_names || []).join(', ')
      return `свёрнуто ${row.members || 0} хостов рекламы/аналитики${names ? ': ' + names : ''}`
    }
    const host = appHost(row)
    // service is a label over the host, so the tooltip must still carry the host
    // itself — the reader has to be able to check the claim.
    if (row.service && host && host !== row.service) return `${row.service} · ${host}`
    return row.service || host
  }
  export function infraTitle(row) {
    return row.resolved_target ? `${row.target} · ${row.resolved_target}` : row.target
  }
</script>

<script>
  import { roleLabel } from './format.js'

  // One renderer for the App/Infra target pair, used by ClientDetail's Top
  // targets and the Traffic table. The two inline copies had already diverged
  // once ("no PTR" vs "no hostname (QUIC)") — the wording lives here now.
  let { row = {}, kind = 'app' } = $props()

  // The app column now leads with the SERVICE label when the server has one
  // ("Picsart" over upload.picsart.com); the host stays right underneath, so the
  // label never hides the evidence it was derived from. A bare IP gets neither —
  // it falls through to "—" here and "no hostname (QUIC)" in the infra column.
  const host = $derived(appHost(row))
  const sdk = $derived(row.target === SDK_TARGET)
  const ident = $derived(sdk ? 'Реклама и аналитика' : row.service || host || '—')
  const sub = $derived(sdk ? `${row.members || 0} хостов · ${(row.member_names || []).join(', ')}` : row.service && host && host !== row.service ? host : '')
  const role = $derived(roleLabel(row.role))
</script>

{#if kind === 'app'}
  <span class="target-main">{ident}</span>
  {#if sub || role || row.attribution_source}
    <span class="target-meta">
      {#if role}<span class="role" title="роль по имени хоста — вероятно {role}; это про тип адресата, не про действие человека">{role}</span>{/if}
      {#if sub}<span class="sub">{sub}</span>{:else if row.attribution_source}<span class="sub">{row.attribution_source}</span>{/if}
      {#if sub && row.attribution_source}<span class="org">{row.attribution_source}</span>{/if}
      {#if row.attribution_candidates?.length > 1}
        <span class="org" title={row.attribution_candidates.join(', ')}>+{row.attribution_candidates.length - 1}</span>
      {/if}
    </span>
  {/if}
{:else}
  <span class="target-main">{row.is_ip ? row.target : 'direct'}</span>
  <span class="target-meta">
    {#if row.resolved_target}<span class="sub">{row.resolved_target}</span>{:else if row.is_ip}<span class="sub">no hostname{row.proto === 'udp' ? ' (QUIC)' : ''}</span>{/if}
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
  .target-meta .sub {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  /* role chip: WHAT KIND of endpoint (ads/push/cdn/…) — read-time, hedged,
     never a claim about what the person did. */
  .role {
    flex: 0 0 auto;
    color: var(--color-dim);
    background: var(--color-s3);
    border-radius: 4px;
    padding: 0 5px;
    font-size: 9.5px;
    cursor: help;
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
