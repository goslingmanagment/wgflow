<script>
  import { onMount } from 'svelte'
  import { hhmmssMSK } from './lib/format.js'
  import { maybeAutoRefresh, onStats, onStreamError, refreshHealth, requestRefresh, ui } from './lib/store.svelte.js'
  import Icon from './lib/Icon.svelte'
  import Win from './lib/Win.svelte'
  import AutoRefresh from './lib/AutoRefresh.svelte'
  import HealthPill from './lib/HealthPill.svelte'
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
    { id: 'categories', icon: 'categories', label: 'Categories', short: 'Cats' },
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

  let now = $state(new Date())
  onMount(() => {
    const onHash = () => (route = parse())
    addEventListener('hashchange', onHash)
    const onVisible = () => {
      if (document.visibilityState === 'visible' && ui.autoRefresh) requestRefresh()
    }
    document.addEventListener('visibilitychange', onVisible)
    // 1s heartbeat: advances the wall-clock AND re-derives logger health, so a
    // dead stream/logger decays to stale/down on its own (the old pill never did).
    const clock = setInterval(() => {
      now = new Date()
      refreshHealth()
      maybeAutoRefresh(document.visibilityState === 'visible')
    }, 1000)
    let es
    try {
      es = new EventSource('/api/stats/stream')
      es.addEventListener('stats', (e) => {
        try {
          onStats(JSON.parse(e.data))
        } catch {}
      })
      // EventSource auto-reconnects on error; surface the drop immediately so the
      // pill reflects it without waiting for the next tick.
      es.onerror = () => onStreamError()
    } catch {
      onStreamError()
    }
    return () => {
      removeEventListener('hashchange', onHash)
      document.removeEventListener('visibilitychange', onVisible)
      clearInterval(clock)
      es && es.close()
    }
  })
</script>

<div class="shell">
  <nav class="rail">
    <a class="mk" href="#/clients" aria-label="wgflow"><Icon name="activity" size={18} /></a>
    {#each NAV as n}
      <a class:on={activeNav === n.id} href="#/{n.id}" aria-label={n.label} title={n.label}>
        <Icon name={n.icon} /><span class="lbl">{n.short || n.label}</span>
      </a>
    {/each}
  </nav>

  <div class="body">
    <header class="top">
      <div class="brand serif">wgflow<span>.</span></div>
      <div class="right">
        <span class="clock mono" title="Текущее время МСК">{hhmmssMSK(now)}<small>МСК</small></span>
        <div class="winwrap"><Win /></div>
        <AutoRefresh />
        <HealthPill rate />
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
    min-height: 100dvh; /* iOS Safari: exclude the dynamic toolbar from the height */
  }
  .rail {
    flex: 0 0 56px;
    background: var(--color-s1);
    border-right: 1px solid var(--color-border);
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 12px 0;
    padding-left: env(safe-area-inset-left); /* clear a landscape notch */
    gap: 4px;
    position: sticky;
    top: 0;
    height: 100vh;
    height: 100dvh;
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
  .rail a .lbl {
    display: none; /* icon-only on the desktop rail; labels appear on the mobile bar */
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
    padding-top: max(12px, env(safe-area-inset-top));
    padding-right: max(20px, env(safe-area-inset-right));
    background: color-mix(in srgb, var(--color-bg) 88%, transparent);
    -webkit-backdrop-filter: blur(8px);
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
  .winwrap {
    display: flex;
    min-width: 0;
  }
  .clock {
    font-size: 13px;
    color: var(--color-dim);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }
  .clock small {
    color: var(--color-muted);
    font-size: 10px;
    margin-left: 3px;
  }
  .main {
    padding: 18px 20px 40px;
    padding-right: max(20px, env(safe-area-inset-right));
    max-width: 1100px;
  }

  /* ---- Phones (portrait): side rail -> bottom tab bar, header wraps ---- */
  @media (max-width: 640px) {
    .rail {
      position: fixed;
      inset: auto 0 0 0;
      top: auto;
      height: auto;
      width: 100%;
      flex: none;
      flex-direction: row;
      align-items: stretch;
      gap: 2px;
      padding: 5px 4px;
      padding-left: max(4px, env(safe-area-inset-left));
      padding-right: max(4px, env(safe-area-inset-right));
      padding-bottom: max(5px, env(safe-area-inset-bottom));
      border-right: 0;
      border-top: 1px solid var(--color-border);
      background: color-mix(in srgb, var(--color-s1) 92%, transparent);
      -webkit-backdrop-filter: blur(10px);
      backdrop-filter: blur(10px);
      z-index: 20;
      overflow-x: auto;
      scrollbar-width: none;
    }
    .rail::-webkit-scrollbar {
      display: none;
    }
    .rail .mk {
      display: none;
    }
    .rail a {
      flex: 1 1 auto;
      min-width: 0; /* shrink to fit all 8 tabs on the narrowest phones (no h-scroll) */
      width: auto;
      height: 46px;
      flex-direction: column;
      gap: 2px;
    }
    .rail a .lbl {
      display: block;
      font-size: 9.5px;
      line-height: 1;
      max-width: 100%;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .top {
      flex-wrap: wrap;
      gap: 10px 12px;
      padding: 10px 14px;
      padding-top: max(10px, env(safe-area-inset-top));
    }
    .right {
      flex-wrap: wrap;
      justify-content: flex-end;
      gap: 8px 10px;
      flex: 1 1 auto;
      min-width: 0; /* let the right group + its window strip shrink instead of overflowing */
    }
    .winwrap {
      order: 10;
      flex: 1 1 100%;
    }
    .brand {
      font-size: 18px;
    }
    .main {
      padding: 14px 14px calc(70px + env(safe-area-inset-bottom));
    }
  }
</style>
