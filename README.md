# wgflow

WireGuard flow, DNS, and TLS SNI logger.

`wgflow` watches a WireGuard interface, maps packets back to clients from
`wg0.conf`, and writes JSONL logs for traffic flows, DNS queries, and TLS SNI
metadata.

## Commands

```sh
wgflow serve --iface wg0 --wg-config /etc/wireguard/wg0.conf --log-dir /var/log/wgflow
wgflow top --since 5m --client diana-iphone --log-dir /var/log/wgflow
wgflow report --since 24h --log-dir /var/log/wgflow
wgflow rollup-import --since 24h
wgflow stats --log-dir /var/log/wgflow --json
wgflow web --listen :8080 --log-dir /var/log/wgflow --rollup /var/lib/wgflow/rollup.db
```

## Service

The included `wgflow.service` runs:

```sh
/usr/local/bin/wgflow serve --iface wg0 --wg-config /etc/wireguard/wg0.conf --log-dir /var/log/wgflow --rollup /var/lib/wgflow/rollup.db --flush 30s
```

Install example:

```sh
go build -o wgflow .
sudo install -m 0755 wgflow /usr/local/bin/wgflow
sudo install -m 0644 wgflow.service /etc/systemd/system/wgflow.service
sudo install -m 0644 wgflow-web.service /etc/systemd/system/wgflow-web.service
sudo install -m 0644 wgflow.logrotate /etc/logrotate.d/wgflow
sudo systemctl daemon-reload
sudo systemctl enable --now wgflow
sudo systemctl enable --now wgflow-web
```

The web UI is embedded in the binary (`webui/dist` is committed), so `go build`
alone produces a self-contained binary — Node is only needed to rebuild the UI.

## Web panel

`wgflow web` serves a single-page dashboard over a read-only JSON API built from
the same rollup DB and JSONL logs. It covers clients (who is doing what, live, in
5–30 minute windows and across the day), traffic, categories, DNS, TLS/SNI sites,
reports, and daemon health. The UI is a Svelte app embedded into the binary with
`go:embed`, so deployment stays a single binary.

Build the UI first, then the binary embeds it:

```sh
cd webui && pnpm install && pnpm build && cd ..
go build -o wgflow .
wgflow web --listen :8080 --log-dir /var/log/wgflow --rollup /var/lib/wgflow/rollup.db
```

For UI development, run the backend and the Vite dev server in parallel — Vite
proxies `/api` to the backend on `:8080`:

```sh
wgflow web --listen :8080 &
pnpm --dir webui dev
```

The panel is read-only. If you expose it outside localhost, set a Basic Auth
password with `WGFLOW_WEB_PASSWORD` or `--auth-password`:

```sh
WGFLOW_WEB_PASSWORD='change-me' wgflow web --listen :8080
```

## Logs

Default runtime paths:

- `/var/log/wgflow/flows.jsonl`
- `/var/log/wgflow/dns.jsonl`
- `/var/log/wgflow/tls.jsonl`
- `/var/log/wgflow/stats.json`
- `/var/lib/wgflow/rollup.db`

The logger records network metadata only. It does not decrypt traffic contents.
