<script>
  import uPlot from 'uplot'
  import 'uplot/dist/uPlot.min.css'
  import { onMount } from 'svelte'
  import { hhmmMSK } from './format.js'

  let { points = [], color = '#e06a3f', unit = 'Mbit/s', height = 200 } = $props()

  let host
  let tip
  let plot

  function toData(pts) {
    return [pts.map((p) => p.t), pts.map((p) => p.v)]
  }
  // Axis/tooltip clock is pinned to MSK (t is unix seconds).
  const fmtT = hhmmMSK

  function makeOpts(w) {
    const axis = {
      stroke: '#6b7785',
      grid: { stroke: 'rgba(255,255,255,0.06)', width: 1 },
      ticks: { stroke: 'rgba(255,255,255,0.06)', width: 1, size: 4 },
      font: '11px ui-monospace, monospace',
    }
    return {
      width: w,
      height,
      padding: [12, 10, 0, 6],
      cursor: { y: false, points: { size: 7, width: 2 } },
      legend: { show: false },
      scales: { x: { time: true }, y: { range: (u, min, max) => [0, max <= 0 ? 1 : max * 1.15] } },
      axes: [
        { ...axis, values: (u, ts) => ts.map(fmtT) },
        { ...axis, size: 48, ticks: { ...axis.ticks, stroke: 'transparent' } },
      ],
      series: [{}, { stroke: color, width: 2, fill: color + '22', points: { show: false } }],
      hooks: {
        init: [(u) => u.over.appendChild(tip)],
        setCursor: [
          (u) => {
            const i = u.cursor.idx
            if (i == null || u.cursor.left < 0) {
              tip.style.display = 'none'
              return
            }
            const y = u.data[1][i]
            tip.style.display = 'block'
            tip.style.left = u.cursor.left + 'px'
            tip.innerHTML = `<b>${y == null ? '—' : y.toFixed(1)}</b> ${unit}<i>${fmtT(u.data[0][i])}</i>`
          },
        ],
      },
    }
  }

  onMount(() => {
    plot = new uPlot(makeOpts(host.clientWidth || 600), toData(points), host)
    const ro = new ResizeObserver(() => {
      if (plot && host.clientWidth) plot.setSize({ width: host.clientWidth, height })
    })
    ro.observe(host)
    return () => {
      ro.disconnect()
      plot && plot.destroy()
    }
  })

  $effect(() => {
    const d = toData(points)
    if (plot) plot.setData(d)
  })
</script>

<div class="chart" bind:this={host} style="height:{height}px">
  <div class="tip" bind:this={tip}></div>
</div>

<style>
  .chart {
    width: 100%;
    position: relative;
  }
  .chart :global(.uplot),
  .chart :global(.u-wrap),
  .chart :global(.u-over),
  .chart :global(.u-under) {
    width: 100% !important;
  }
  .tip {
    position: absolute;
    top: 2px;
    transform: translateX(-50%);
    pointer-events: none;
    display: none;
    background: var(--color-s3);
    border: 1px solid var(--color-border2);
    border-radius: 6px;
    padding: 3px 8px;
    font-size: 11px;
    color: var(--color-dim);
    white-space: nowrap;
    z-index: 3;
  }
  .tip :global(b) {
    color: var(--color-text);
    font-family: var(--font-mono);
    font-weight: 500;
  }
  .tip :global(i) {
    color: var(--color-muted);
    font-style: normal;
    margin-left: 7px;
    font-family: var(--font-mono);
  }
</style>
