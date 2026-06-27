<script>
  let { values = [], color = 'var(--color-coral)', h = 22, fill = false, width = '100%' } = $props()

  const path = $derived(build(values, h))
  function build(vals, h) {
    const v = (vals || []).map(Number).filter((x) => !isNaN(x))
    if (v.length < 2) return { line: '', area: '' }
    const W = 100
    const min = 0
    const max = Math.max(...v)
    const span = max - min || 1
    const n = v.length
    let line = ''
    let area = `M0,${h}`
    v.forEach((val, i) => {
      const x = (i / (n - 1)) * W
      const y = h - ((val - min) / span) * (h - 3) - 1.5
      line += (i ? ' L' : 'M') + x.toFixed(2) + ',' + y.toFixed(2)
      area += ' L' + x.toFixed(2) + ',' + y.toFixed(2)
    })
    area += ` L${W},${h} Z`
    return { line, area }
  }
</script>

<svg viewBox="0 0 100 {h}" preserveAspectRatio="none" style="width:{width};height:{h}px;display:block;overflow:visible">
  {#if fill && path.area}<path d={path.area} fill={color} opacity="0.14" />{/if}
  <path d={path.line} fill="none" stroke={color} stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke" />
</svg>
