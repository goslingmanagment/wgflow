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
sudo install -m 0644 wgflow.logrotate /etc/logrotate.d/wgflow
sudo systemctl daemon-reload
sudo systemctl enable --now wgflow
```

## Logs

Default runtime paths:

- `/var/log/wgflow/flows.jsonl`
- `/var/log/wgflow/dns.jsonl`
- `/var/log/wgflow/tls.jsonl`
- `/var/log/wgflow/stats.json`
- `/var/lib/wgflow/rollup.db`

The logger records network metadata only. It does not decrypt traffic contents.
