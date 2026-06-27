<script>
  import { trackRefreshTick } from '../lib/store.svelte.js'
  import { getJSON, fmtBytes, fmtShort, uptime, ago } from '../lib/format.js'
  import { createLatestRunner, errorMessage } from '../lib/load.js'
  import HealthPill from '../lib/HealthPill.svelte'

  let data = $state(null)
  let err = $state(null)
  const runLatest = createLatestRunner()
  $effect(() => {
    trackRefreshTick()
    load()
  })
  async function load() {
    await runLatest(
      () => getJSON('/api/system'),
      (next) => {
        data = next
        err = null
      },
      (e) => {
        err = errorMessage(e)
      },
    )
  }
  const st = $derived(data?.stats || {})
  const cfg = $derived(data?.config || {})
  const decoded = $derived(st.packet_seen ? (st.packet_decoded / st.packet_seen) * 100 : 0)
  const matched = $derived(st.packet_seen ? (st.packet_matched / st.packet_seen) * 100 : 0)
  const storage = $derived([
    ['flows.jsonl', st.flows_log_bytes || 0],
    ['rollup.db', st.rollup_db_bytes || 0],
    ['dns.jsonl', st.dns_log_bytes || 0],
    ['tls.jsonl', st.tls_log_bytes || 0],
  ])
  const maxStore = $derived(Math.max(1, ...storage.map((s) => s[1])))
</script>

<div class="head"><h1 class="serif">System</h1><HealthPill /></div>

{#if err}<p class="err">Couldn't load system. ({err})</p>{:else if !data}<p class="dim">Loading…</p>{:else}
  <div class="grid">
    <div class="card">
      <h3 class="serif">Configuration</h3>
      <div class="kv"><span>Interface</span><b class="mono">{cfg.interface}</b></div>
      <div class="kv"><span>WG config</span><b class="mono">{cfg.wg_config}</b></div>
      <div class="kv"><span>Log dir</span><b class="mono">{cfg.log_dir}</b></div>
      <div class="kv"><span>Rollup DB</span><b class="mono">{cfg.rollup}</b></div>
      <div class="kv"><span>Uptime</span><b class="mono">{uptime(st.started_at)}</b></div>
      <div class="kv"><span>Config reloads</span><b class="mono">{st.config_reloads} · {st.config_last_loaded_at ? ago(st.config_last_loaded_at) : '—'}</b></div>
    </div>
    <div class="card">
      <h3 class="serif">Capture health</h3>
      <div class="pipe">
        <div class="l"><span>Seen</span><b class="mono">{fmtShort(st.packet_seen || 0)}</b></div><div class="tr"><div class="f" style="width:100%;background:var(--color-accent)"></div></div>
        <div class="l"><span>Decoded</span><b class="mono">{decoded.toFixed(1)}%</b></div><div class="tr"><div class="f" style="width:{decoded}%;background:var(--color-accent)"></div></div>
        <div class="l"><span>Matched</span><b class="mono">{matched.toFixed(1)}%</b></div><div class="tr"><div class="f" style="width:{matched}%;background:var(--color-ok)"></div></div>
      </div>
      <div class="kv"><span>Kernel drops</span><b class="mono" style="color:{st.kernel_packet_socket_drops ? 'var(--color-warn)' : 'var(--color-ok)'}">{(st.kernel_packet_socket_drops || 0).toLocaleString()} · Δ {st.last_kernel_drops_delta ?? 0}</b></div>
      <div class="kv"><span>Rate now</span><b class="mono">{(st.bit_rate_per_second / 1e6 || 0).toFixed(1)} Mbit/s · {fmtShort(st.packet_rate_per_second || 0)} pps</b></div>
      <div class="kv"><span>Flow queue keys</span><b class="mono">{(st.flow_queue_keys || 0).toLocaleString()}</b></div>
      <div class="kv"><span>Rollup pending</span><b class="mono" style="color:{st.rollup_pending_records ? 'var(--color-warn)' : 'var(--color-ok)'}">{(st.rollup_pending_records || 0).toLocaleString()}</b></div>
    </div>
    <div class="card">
      <h3 class="serif">Storage</h3>
      {#each storage as [name, bytes]}
        <div class="st"><span class="nm">{name}</span><span class="bar"><span style="width:{((bytes / maxStore) * 100).toFixed(0)}%"></span></span><span class="sz mono">{fmtBytes(bytes)}</span></div>
      {/each}
      <div class="kv" style="margin-top:8px"><span>Records</span><b class="mono">flows {fmtShort(st.flow_records || 0)} · dns {fmtShort(st.dns_records || 0)} · tls {fmtShort(st.tls_records || 0)}</b></div>
    </div>
  </div>
{/if}

<style>
  .head { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }
  h1 { font-size: 22px; font-weight: 500; margin: 0; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  @media (max-width: 760px) { .grid { grid-template-columns: 1fr; } }
  .card { background: var(--color-s1); border: 1px solid var(--color-border); border-radius: 12px; padding: 14px 16px; }
  h3 { font-size: 15px; font-weight: 500; margin: 0 0 12px; }
  .kv { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; padding: 5px 0; font-size: 12.5px; }
  .kv span { color: var(--color-dim); flex: 0 0 auto; }
  .kv b { font-weight: 400; text-align: right; word-break: break-all; }
  .pipe .l { display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 3px; }
  .pipe .l b { font-weight: 500; }
  .tr { height: 7px; border-radius: 4px; background: var(--color-s3); overflow: hidden; margin-bottom: 9px; }
  .tr .f { height: 100%; border-radius: 4px; }
  .st { display: flex; align-items: center; gap: 9px; padding: 5px 0; font-size: 12.5px; }
  .st .nm { flex: 0 0 84px; color: var(--color-dim); }
  .st .bar { flex: 1; height: 7px; border-radius: 4px; background: var(--color-s3); overflow: hidden; }
  .st .bar span { display: block; height: 100%; background: var(--color-coral); border-radius: 4px; }
  .st .sz { width: 70px; text-align: right; font-weight: 500; }
  .dim { color: var(--color-muted); }
  .err { color: var(--color-danger); }
</style>
