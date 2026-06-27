<script>
  import { catColor } from './format.js'
  let { cats = [], h = 8 } = $props()
  const total = $derived((cats || []).reduce((s, c) => s + Number(c.bytes || 0), 0) || 1)
</script>

<div class="mix" style="height:{h}px">
  {#each cats as c}
    <span style="width:{((Number(c.bytes) / total) * 100).toFixed(1)}%;background:{catColor(c.category)}" title={c.category}></span>
  {/each}
</div>

<style>
  .mix {
    display: flex;
    border-radius: 5px;
    overflow: hidden;
    background: var(--color-s3);
    width: 100%;
  }
  .mix span {
    height: 100%;
  }
</style>
