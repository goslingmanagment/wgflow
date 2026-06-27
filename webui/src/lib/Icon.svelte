<script>
  let { name, size = 18, stroke = 1.8 } = $props()
  const P = {
    activity: 'M3 12h4l2.5-7 5 14 2.5-7h4',
    clients: 'M9 11a3.2 3.2 0 1 0 0-6.4 3.2 3.2 0 0 0 0 6.4M3.5 19a5.5 5.5 0 0 1 11 0M16 5.2a3 3 0 0 1 0 5.8M20.5 19a5 5 0 0 0-3.5-4.8',
    overview: 'M4 4h7v7H4zM13 4h7v4h-7zM13 11h7v9h-7zM4 13h7v7H4z',
    traffic: 'M4 9h12M13 6l3 3-3 3M20 15H8m3 3l-3-3 3-3',
    categories: 'M12 3a9 9 0 1 0 9 9M12 3v9h9a9 9 0 0 0-9-9',
    dns: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18M3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18',
    tls: 'M6 10V8a6 6 0 0 1 12 0v2M5 10h14v9H5zM12 14v2',
    reports: 'M7 3h7l4 4v14H7zM14 3v4h4M9.5 12h5M9.5 15h5M9.5 9h2',
    system: 'M5 7h14M5 12h14M5 17h14M9 7v0M15 12v0M8 17v0',
    chevron: 'M9 6l6 6-6 6',
    search: 'M11 11m-7 0a7 7 0 1 0 14 0 7 7 0 1 0-14 0M21 21l-4-4',
    download: 'M12 4v10m0 0l4-4m-4 4l-4-4M5 19h14',
    refresh: 'M20 11a8 8 0 1 0-2 6m2 1v-5h-5',
    lock: 'M6 10V8a6 6 0 0 1 12 0v2M5 10h14v9H5z',
    arrowdown: 'M12 5v14m0 0l5-5m-5 5l-5-5',
    arrowup: 'M12 19V5m0 0l5 5m-5-5l-5 5',
  }
</script>

<svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width={stroke} stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
  <path d={P[name] || ''} />
</svg>
