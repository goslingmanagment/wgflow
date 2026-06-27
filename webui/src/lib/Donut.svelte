<script>
  import { catColor } from './format.js'
  let { items = [], size = 116, thickness = 18 } = $props()

  const r = $derived((size - thickness) / 2)
  const cx = $derived(size / 2)
  const C = $derived(2 * Math.PI * r)

  const segs = $derived.by(() => {
    const data = (items || [])
      .map((i) => ({ name: i.category, val: Number(i.total ?? i.bytes ?? 0) }))
      .filter((d) => d.val > 0)
    const total = data.reduce((s, d) => s + d.val, 0) || 1
    let off = 0
    return data.map((d) => {
      const len = (d.val / total) * C
      const seg = { name: d.name, color: catColor(d.name), len, gap: C - len, off: -off }
      off += len
      return seg
    })
  })
</script>

<svg width={size} height={size} viewBox="0 0 {size} {size}" role="img" aria-label="Category share">
  <circle {cx} cy={cx} {r} fill="none" stroke="var(--color-s3)" stroke-width={thickness} />
  {#each segs as s}
    <circle
      {cx}
      cy={cx}
      {r}
      fill="none"
      stroke={s.color}
      stroke-width={thickness}
      stroke-dasharray="{s.len.toFixed(2)} {s.gap.toFixed(2)}"
      stroke-dashoffset={s.off.toFixed(2)}
      transform="rotate(-90 {cx} {cx})"
    />
  {/each}
</svg>
