<script>
  import { onMount } from 'svelte'
  import Icon from './lib/Icon.svelte'
  import Win from './lib/Win.svelte'
  import Clients from './routes/Clients.svelte'
  import ClientDetail from './routes/ClientDetail.svelte'
  import Overview from './routes/Overview.svelte'
  import Traffic from './routes/Traffic.svelte'
  import Categories from './routes/Categories.svelte'
  import Dns from './routes/Dns.svelte'
  import Tls from './routes/Tls.svelte'
  import Reports from './routes/Reports.svelte'
  import System from './routes/System.svelte'

  const NAV = [
    { id: 'clients', icon: 'clients', label: 'Clients' },
    { id: 'overview', icon: 'overview', label: 'Overview' },
    { id: 'traffic', icon: 'traffic', label: 'Traffic' },
    { id: 'categories', icon: 'categories', label: 'Categories' },
    { id: 'dns', icon: 'dns', label: 'DNS' },
    { id: 'tls', icon: 'tls', label: 'Sites' },
    { id: 'reports', icon: 'reports', label: 'Reports' },
    { id: 'system', icon: 'system', label: 'System' },
  ]
  const ROUTES = { clients: Clients, overview: Overview, traffic: Traffic, categories: Categories, dns: Dns, tls: Tls, reports: Reports, system: System }

  let route = $state(parse())
  function parse() {
    const h = location.hash.replace(/^#\/?/, '') || 'clients'
    const [name, param] = h.split('/')
    return { name, param: param ? decodeURIComponent(param) : '' }
  }

  const Current = $derived(route.name === 'clients' && route.param ? ClientDetail : ROUTES[route.name] || Clients)
  const activeNav = $derived(route.name === 'clients' && route.param ? 'clients' : route.name)

  let live = $state(null)
  onMount(() => {
    const onHash = () => (route = parse())
    addEventListener('hashchange', onHash)
    let es
    try {
      es = new EventSource('/api/stats/stream')
      es.addEventListener('stats', (e) => {
        try {
          live = JSON.parse(e.data)
        } catch {}
      })
    } catch {}
    return () => {
      removeEventListener('hashchange', onHash)
      es && es.close()
    }
  })

  const mbit = $derived(live ? (live.bit_rate_per_second / 1e6).toFixed(1) : null)
</script>

<div class="shell">
  <nav class="rail">
    <a class="mk" href="#/clients" aria-label="wgflow"><Icon name="activity" size={18} /></a>
    {#each NAV as n}
      <a class:on={activeNav === n.id} href="#/{n.id}" aria-label={n.label} title={n.label}><Icon name={n.icon} /></a>
    {/each}
  </nav>

  <div class="body">
    <header class="top">
      <div class="brand serif">wgflow<span>.</span></div>
      <div class="right">
        <Win />
        <span class="live" class:off={!live}>
          <span class="dot pulse"></span>
          {#if mbit}{mbit}<small>Mbit/s</small>{:else}offline{/if}
        </span>
      </div>
    </header>
    <main class="main">
      <Current param={route.param} />
    </main>
  </div>
</div>

<style>
  .shell {
    display: flex;
    min-height: 100vh;
  }
  .rail {
    flex: 0 0 56px;
    background: var(--color-s1);
    border-right: 1px solid var(--color-border);
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 12px 0;
    gap: 4px;
    position: sticky;
    top: 0;
    height: 100vh;
  }
  .rail .mk {
    width: 34px;
    height: 34px;
    border-radius: 9px;
    background: var(--color-coral);
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 10px;
  }
  .rail a {
    width: 38px;
    height: 38px;
    border-radius: 9px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--color-muted);
  }
  .rail a:hover {
    color: var(--color-text);
    background: var(--color-s2);
  }
  .rail a.on {
    background: var(--color-accent-dim);
    color: var(--color-accent);
  }
  .body {
    flex: 1 1 auto;
    min-width: 0;
  }
  .top {
    position: sticky;
    top: 0;
    z-index: 5;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 12px 20px;
    background: color-mix(in srgb, var(--color-bg) 88%, transparent);
    backdrop-filter: blur(8px);
    border-bottom: 1px solid var(--color-border);
  }
  .brand {
    font-size: 20px;
    font-weight: 500;
  }
  .brand span {
    color: var(--color-coral);
  }
  .right {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .live {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--color-ok);
    background: color-mix(in srgb, var(--color-ok) 14%, transparent);
    padding: 4px 10px;
    border-radius: 999px;
  }
  .live small {
    color: var(--color-dim);
    font-size: 11px;
  }
  .live.off {
    color: var(--color-muted);
    background: var(--color-s2);
  }
  .live .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: currentColor;
  }
  .main {
    padding: 18px 20px 40px;
    max-width: 1100px;
  }
</style>
