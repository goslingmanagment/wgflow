<script>
  import { getJSON, fmtBytes, hhmmMSK, catColor } from './format.js'

  // Per-minute reconstruction. Bytes/flags come pre-computed from the binary
  // bucket; a minute's domains load lazily on click (only flagged/non-silent rows
  // are expandable) so we never do the wide per-minute domain join.
  let { minutes = [], name = '' } = $props()

  const max = $derived(Math.max(1, ...minutes.map((m) => Number(m.bytes) || 0)))
  const flaggedCount = $derived(minutes.filter((m) => m.over_100k).length)
  const firstSig = $derived(minutes.find((m) => m.over_100k))

  let openAt = $state(null)
  let domains = $state({}) // t -> {tls,dns} | 'loading' | 'error'

  async function toggle(m) {
    if (m.bytes === 0) return
    if (openAt === m.t) {
      openAt = null
      return
    }
    openAt = m.t
    if (!domains[m.t]) {
      domains = { ...domains, [m.t]: 'loading' }
      try {
        const d = await getJSON(`/api/clients/${encodeURIComponent(name)}/minute?at=${m.t}`)
        domains = { ...domains, [m.t]: d }
      } catch {
        domains = { ...domains, [m.t]: 'error' }
      }
    }
  }
</script>

<div class="card">
  <div class="ch">
    <h3 class="serif">Поминутно</h3>
    <span class="hint">{minutes.length} мин · МСК · ⚑&gt;100КБ / &gt;1МБ</span>
  </div>
  <div class="rib">
    {#each minutes as m}
      <button class="m" class:silent={m.bytes === 0} class:open={openAt === m.t} onclick={() => toggle(m)} disabled={m.bytes === 0}>
        <span class="t mono">{hhmmMSK(m.t)}</span>
        <span class="bar"><span style="width:{m.bytes ? Math.max(3, (m.bytes / max) * 100) : 0}%;background:{catColor(m.top_category)}"></span></span>
        <span class="by mono">{m.bytes ? fmtBytes(m.bytes) : 'тишина'}</span>
        <span class="fl">
          {#if m.over_1m}<b class="f1">⚑&gt;1МБ</b>{:else if m.over_100k}<b class="f0">⚑&gt;100КБ</b>{/if}
        </span>
        {#if m.top_category}<span class="cd" style="background:{catColor(m.top_category)}" title={m.top_category}></span>{/if}
      </button>
      {#if openAt === m.t}
        <div class="dom">
          {#if domains[m.t] === 'loading'}
            <span class="dim">загрузка…</span>
          {:else if domains[m.t] === 'error'}
            <span class="dim">не удалось загрузить</span>
          {:else if domains[m.t]}
            {#if domains[m.t].tls?.length}<div>Sites: {domains[m.t].tls.join(' · ')}</div>{/if}
            {#if domains[m.t].dns?.length}<div class="dns">DNS: {domains[m.t].dns.join(' · ')}</div>{/if}
            {#if !domains[m.t].tls?.length && !domains[m.t].dns?.length}
              <span class="dim">без имени (QUIC), либо домены вне нерот. логов</span>
            {/if}
          {/if}
        </div>
      {/if}
    {/each}
  </div>
  <div class="foot">
    {#if firstSig}первый заметный след {hhmmMSK(firstSig.t)} МСК · {flaggedCount} flagged{:else}нет минут &gt;100 КБ в окне{/if}
  </div>
</div>

<style>
  .card {
    background: var(--color-s1);
    border: 1px solid var(--color-border);
    border-radius: 12px;
    padding: 14px 16px;
    margin-bottom: 14px;
  }
  .ch {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
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
  .rib {
    display: flex;
    flex-direction: column;
  }
  .m {
    display: grid;
    grid-template-columns: 46px 1fr 74px 64px 12px;
    align-items: center;
    gap: 9px;
    padding: 3px 4px;
    background: transparent;
    border: 0;
    border-radius: 5px;
    cursor: pointer;
    text-align: left;
    color: inherit;
  }
  .m:not(.silent):hover {
    background: var(--color-s2);
  }
  .m.silent {
    cursor: default;
    opacity: 0.6;
  }
  .m.open {
    background: var(--color-s2);
  }
  .t {
    font-size: 11.5px;
    color: var(--color-dim);
  }
  .bar {
    height: 9px;
    background: var(--color-s3);
    border-radius: 3px;
    overflow: hidden;
  }
  .bar span {
    display: block;
    height: 100%;
    border-radius: 3px;
  }
  .by {
    text-align: right;
    font-size: 11.5px;
    color: var(--color-dim);
  }
  .fl b {
    font-size: 9.5px;
    font-weight: 600;
    white-space: nowrap;
  }
  .fl .f1 {
    color: var(--color-coral);
  }
  .fl .f0 {
    color: var(--color-warn);
  }
  .cd {
    width: 8px;
    height: 8px;
    border-radius: 2px;
  }
  .dom {
    font-size: 11.5px;
    color: var(--color-text);
    padding: 4px 8px 8px 55px;
    word-break: break-word;
  }
  .dom .dns {
    color: var(--color-dim);
    margin-top: 2px;
  }
  .dom .dim {
    color: var(--color-muted);
  }
  .foot {
    margin-top: 8px;
    font-size: 11.5px;
    color: var(--color-muted);
    font-family: var(--font-mono);
  }
  @media (max-width: 640px) {
    .m {
      grid-template-columns: 38px 1fr auto auto;
      gap: 7px;
    }
    .cd {
      display: none;
    }
    .dom {
      padding-left: 40px;
    }
  }
</style>
