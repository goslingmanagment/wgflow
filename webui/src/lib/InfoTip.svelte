<script>
  // iOS Safari never shows title= tooltips, and the phone is a first-class
  // client here — so the critical explanations (verdict rules, stale reasons,
  // the apple push/OCSP hedge) get a tap-toggled popover instead. Tap outside
  // or Escape closes it; desktop hover still gets the native title.
  //
  // The trigger is a span[role=button], not a <button>: these tips live inside
  // links and buttons (client rows, the header pill), where nesting a real
  // button would be invalid HTML.
  let { text = '', children } = $props()

  let open = $state(false)
  let root = $state(null)
  let pos = $state({ top: 0, left: 0 })

  // The popover is position:fixed and placed from the trigger's viewport rect:
  // several triggers sit inside overflow-hidden table cells where an absolutely
  // positioned child would be clipped.
  const POP_W = 280
  function place() {
    const r = root.getBoundingClientRect()
    const w = Math.min(POP_W, innerWidth - 16)
    pos = { top: r.bottom + 6, left: Math.max(8, Math.min(r.left, innerWidth - w - 8)) }
  }
  function toggle(e) {
    // Swallow the event: triggers sit inside row links / expander buttons and a
    // tap on the tip must not navigate or toggle the row.
    e.preventDefault()
    e.stopPropagation()
    if (!open) place()
    open = !open
  }
  function onKey(e) {
    if (e.key === 'Enter' || e.key === ' ') toggle(e)
  }
  function onDocDown(e) {
    if (open && root && !root.contains(e.target)) open = false
  }
</script>

<svelte:document onpointerdown={onDocDown} />
<svelte:window onkeydown={(e) => open && e.key === 'Escape' && (open = false)} onscroll={() => (open = false)} />

<span class="it" bind:this={root} role="button" tabindex="0" aria-expanded={open} title={text} onclick={toggle} onkeydown={onKey}>
  {@render children?.()}
</span>
{#if open}
  <span class="pop" role="note" style="top:{pos.top}px;left:{pos.left}px;max-width:{POP_W}px">{text}</span>
{/if}

<style>
  .it {
    display: inline-flex;
    align-items: center;
    cursor: help;
    -webkit-tap-highlight-color: transparent;
  }
  .pop {
    position: fixed;
    z-index: 60;
    background: color-mix(in srgb, var(--color-s3) 96%, transparent);
    border: 1px solid var(--color-border2);
    border-radius: 8px;
    padding: 8px 11px;
    font-size: 11.5px;
    line-height: 1.45;
    color: var(--color-dim);
    font-family: var(--font-sans);
    text-transform: none;
    letter-spacing: normal;
    white-space: normal;
    text-align: left;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
    -webkit-backdrop-filter: blur(3px);
    backdrop-filter: blur(3px);
  }
</style>
