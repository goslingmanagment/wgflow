<script>
  import { fmtBytes, catColor, hourMSK } from './format.js'
  let { day = [] } = $props()

  const max = $derived(Math.max(1, ...day.map((h) => Number(h.total) || 0)))
  const total = $derived(day.reduce((s, h) => s + (Number(h.total) || 0), 0))
  // Buckets are MSK hours (server-side); the "now" marker must match.
  const nowHour = hourMSK()
  let hover = $state(-1)

  function segs(h) {
    return Object.entries(h?.cats || {})
      .map(([category, bytes]) => ({ category, bytes: Number(bytes) }))
      .filter((s) => s.bytes > 0)
      .sort((a, b) => b.bytes - a.bytes)
  }

  const legend = $derived.by(() => {
    const m = {}
    day.forEach((h) => {
      for (const [c, b] of Object.entries(h.cats || {})) m[c] = (m[c] || 0) + Number(b)
    })
    return Object.entries(m)
      .map(([category, bytes]) => ({ category, bytes }))
      .sort((a, b) => b.bytes - a.bytes)
  })
</script>

<div class="wrap">
  <div class="bars" role="img" aria-label="Hourly traffic for the last 24 hours, colored by category" onmouseleave={() => (hover = -1)}>
    <div class="grid"><i></i><i></i><i></i></div>
    {#each day as h}
      <button
        type="button"
        class="col"
        class:now={h.hour === nowHour}
        class:active={h.hour === hover}
        onmouseenter={() => (hover = h.hour)}
        onfocus={() => (hover = h.hour)}
        aria-label="{String(h.hour).padStart(2, '0')}:00, {fmtBytes(h.total)}"
      >
        <span class="bar" style="height:{h.total > 0 ? Math.max(2, (h.total / max) * 100) : 0}%">
          {#each segs(h) as s}
            <span style="height:{((s.bytes / (h.total || 1)) * 100).toFixed(1)}%;background:{catColor(s.category)}"></span>
          {/each}
        </span>
      </button>
    {/each}

    {#if hover >= 0 && day[hover]}
      <div class="tip" class:left={hover >= 12}>
        <div class="th">{String(hover).padStart(2, '0')}:00 – {String(hover).padStart(2, '0')}:59 МСК</div>
        <div class="tt">{fmtBytes(day[hover].total)}</div>
        {#each segs(day[hover]) as s}
          <div class="tr"><span class="dot" style="background:{catColor(s.category)}"></span>{s.category}<b>{fmtBytes(s.bytes)}</b></div>
        {/each}
        {#if day[hover].total === 0}<div class="quiet">no traffic this hour</div>{/if}
      </div>
    {/if}
  </div>

  <div class="axis">
    {#each [0, 3, 6, 9, 12, 15, 18, 21] as t}<span style="left:{(t / 24) * 100}%">{String(t).padStart(2, '0')}</span>{/each}
    <span class="end">24</span>
  </div>

  <div class="foot">
    <div class="legend">
      {#each legend as c}<span><i style="background:{catColor(c.category)}"></i>{c.category}<b>{fmtBytes(c.bytes)}</b></span>{/each}
    </div>
    <div class="cap">peak <b>{fmtBytes(max)}</b>/h · <b>{fmtBytes(total)}</b> / 24h</div>
  </div>
</div>

<style>
  .wrap {
    position: relative;
  }
  .bars {
    position: relative;
    display: flex;
    align-items: flex-end;
    gap: 2px;
    height: 96px;
    border-bottom: 1px solid var(--color-border);
  }
  .grid {
    position: absolute;
    inset: 0;
    pointer-events: none;
  }
  .grid i {
    position: absolute;
    left: 0;
    right: 0;
    border-top: 1px solid rgba(255, 255, 255, 0.04);
  }
  .grid i:nth-child(1) {
    top: 25%;
  }
  .grid i:nth-child(2) {
    top: 50%;
  }
  .grid i:nth-child(3) {
    top: 75%;
  }
  .col {
    flex: 1;
    height: 100%;
    display: flex;
    align-items: flex-end;
    padding: 0;
    border: 0;
    background: transparent;
    border-radius: 3px 3px 0 0;
    cursor: default;
    position: relative;
  }
  .col:hover,
  .col.active {
    background: var(--color-s2);
  }
  .col.now {
    background: color-mix(in srgb, var(--color-coral) 12%, transparent);
  }
  .col.now::before {
    content: '';
    position: absolute;
    top: -5px;
    left: 50%;
    transform: translateX(-50%);
    width: 4px;
    height: 4px;
    border-radius: 50%;
    background: var(--color-coral);
  }
  .bar {
    width: 100%;
    display: flex;
    flex-direction: column-reverse;
    border-radius: 3px 3px 0 0;
    overflow: hidden;
    min-height: 0;
  }
  .bar span {
    width: 100%;
  }
  .tip {
    position: absolute;
    top: 0;
    right: 0;
    min-width: 156px;
    background: color-mix(in srgb, var(--color-s3) 94%, transparent);
    border: 1px solid var(--color-border2);
    border-radius: 8px;
    padding: 9px 11px;
    z-index: 5;
    pointer-events: none;
    backdrop-filter: blur(3px);
  }
  .tip.left {
    right: auto;
    left: 0;
  }
  .tip .th {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--color-muted);
  }
  .tip .tt {
    font-family: var(--font-mono);
    font-size: 16px;
    font-weight: 500;
    margin: 2px 0 7px;
  }
  .tip .tr {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: 12px;
    color: var(--color-dim);
    padding: 2px 0;
  }
  .tip .tr b {
    margin-left: auto;
    color: var(--color-text);
    font-weight: 400;
    font-family: var(--font-mono);
  }
  .tip .dot {
    width: 8px;
    height: 8px;
    border-radius: 2px;
  }
  .tip .quiet {
    font-size: 12px;
    color: var(--color-muted);
  }
  .axis {
    position: relative;
    height: 14px;
    margin-top: 5px;
    font-size: 10px;
    color: var(--color-muted);
    font-family: var(--font-mono);
  }
  .axis span {
    position: absolute;
    transform: translateX(-50%);
  }
  .axis .end {
    left: 100%;
  }
  .foot {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    flex-wrap: wrap;
    margin-top: 8px;
  }
  .legend {
    display: flex;
    gap: 14px;
    flex-wrap: wrap;
    font-size: 11px;
    color: var(--color-dim);
  }
  .legend span {
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }
  .legend span b {
    color: var(--color-muted);
    font-weight: 400;
    font-family: var(--font-mono);
  }
  .legend i {
    width: 9px;
    height: 9px;
    border-radius: 2px;
  }
  .cap {
    font-size: 11px;
    color: var(--color-muted);
    font-family: var(--font-mono);
    white-space: nowrap;
  }
  .cap b {
    color: var(--color-dim);
    font-weight: 400;
  }
</style>
