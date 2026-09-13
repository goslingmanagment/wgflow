# wgflow

WireGuard flow, DNS, and TLS SNI logger.

`wgflow` watches a WireGuard interface, maps packets back to clients from
`wg0.conf`, and writes JSONL logs for traffic flows, DNS queries, and TLS SNI
metadata.

## Commands

```sh
wgflow serve --iface wg0 --wg-config /etc/wireguard/wg0.conf --log-dir /var/log/wgflow --rollup-retention 31d --rollup-detail-retention 7d
wgflow top --since 5m --client diana-iphone --log-dir /var/log/wgflow
wgflow report --since 24h --log-dir /var/log/wgflow
wgflow rollup-import --since 24h
wgflow rollup-prune --keep 31d --detail-keep 7d
wgflow stats --log-dir /var/log/wgflow --json
wgflow web --listen :8080 --log-dir /var/log/wgflow --rollup /var/lib/wgflow/rollup.db
```

## Service

The included `wgflow.service` runs:

```sh
/usr/local/bin/wgflow serve --iface wg0 --wg-config /etc/wireguard/wg0.conf --log-dir /var/log/wgflow --rollup /var/lib/wgflow/rollup.db --flush 30s --rollup-retention 31d --rollup-detail-retention 7d
```

One daemon can capture additional WireGuard interfaces, including an interface
inside a Docker network namespace. Each extra source has its own peer config
and VPN CIDRs but shares the same logs and rollup writer:

```sh
pid=$(docker inspect -f '{{.State.Pid}}' wg-easy)
wgflow serve \
  --iface wg0 \
  --wg-config /etc/wireguard/wg0.conf \
  --extra-source "name=wg-easy,iface=wg0,wg-config=/opt/wg-easy/etc-wireguard/wg0.conf,cidrs=10.8.0.0/24|fdcc:ad94:bacf:61a4::/64,netns=/proc/$pid/ns/net"
```

Opening a socket in another network namespace requires `CAP_SYS_ADMIN` during
startup in addition to the capture service's existing `CAP_NET_RAW` and
`CAP_NET_ADMIN`. A capability-sandboxed service that opens another process's
`/proc/<pid>/ns/net` also needs `CAP_SYS_PTRACE`. The namespace path is
monitored; if the container is recreated, `wgflow` exits so its service manager
can restart it with the new container PID.

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

Rollup retention is tiered. Compact per-client/category summaries retain the
30-day report window (`--rollup-retention 31d`), while the much larger
per-target detail bucket can use a shorter window (`--rollup-detail-retention
7d`). If the detail flag is omitted it inherits `--rollup-retention`, preserving
the original single-window behavior. Pruning releases bbolt pages for reuse but
does not shrink the database file; offline compaction is a separate operation.
Detail-backed web endpoints are capped at seven days; 30-day reports use the
compact summary tier and remain complete.

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

The panel is read-only. Listening on a non-loopback address **requires** a
password — without one the server refuses to start (override with
`--allow-no-auth` if you really know what you are doing):

```sh
WGFLOW_WEB_PASSWORD='change-me' wgflow web --listen :8080
```

Opening the panel shows a password-only login page. A successful login creates
an HttpOnly, signed cookie for one year; it is renewed while the panel is used,
survives `wgflow` restarts, and is invalidated when the password changes.
Pre-emptive Basic Auth remains accepted for existing scripts, but the server no
longer sends a browser Basic Auth challenge.

To share one login between panels on sibling hostnames, use the same password on
both servers and set their common parent cookie domain:

```sh
WGFLOW_WEB_PASSWORD='change-me' \
WGFLOW_WEB_COOKIE_DOMAIN='.vpn.example.com' \
wgflow web --listen :8080
```

Browser security does not allow sharing cookies between unrelated domains or
different IP addresses; those require one login per server, after which each
login remains saved.

The password and session cookie travel in cleartext when the panel itself is
plain HTTP. Keep it reachable only over WireGuard, an SSH tunnel, or a
TLS-terminating reverse proxy; do not expose the bare port to the internet.

Day buckets and minute timelines are aggregated in the timezone given by
`--tz` (default `Europe/Moscow`). The UI currently formats times as MSK, so if
you change `--tz`, expect the displayed clock labels to stay in MSK.

Bare-IP targets (nested tunnels, QUIC without SNI) are attributed to their
network owner via a small builtin prefix table. To name networks the table
does not know, point `--asn-db` at any MaxMind-format ASN database — the free
db-ip ASN Lite works without registration (CC-BY): download
`dbip-asn-lite-YYYY-MM.mmdb.gz` from <https://download.db-ip.com/free/>,
gunzip it, and pass the path:

```sh
wgflow web --listen :8080 --asn-db /var/lib/wgflow/dbip-asn-lite.mmdb
```

The database is consulted only after the builtin table misses, only in the web
layer (never on the capture path). A missing or corrupt file logs a warning
and the panel runs without it.

## Development

`go test ./...` runs the unit suite. The packet, DNS, TLS and QUIC parsers all
take untrusted bytes, so they carry fuzz targets — exercise one with e.g.:

```sh
go test -fuzz=FuzzParsePacket -fuzztime=30s
```

For the UI, `pnpm --dir webui check` runs svelte-check alongside the build.

## Logs

Default runtime paths:

- `/var/log/wgflow/flows.jsonl`
- `/var/log/wgflow/dns.jsonl`
- `/var/log/wgflow/tls.jsonl`
- `/var/log/wgflow/stats.json`
- `/var/lib/wgflow/rollup.db`

The logger records network metadata only. It does not decrypt traffic contents.
