# Developing wgflow

Go daemon and web panel for WireGuard flow, DNS and TLS/SNI metadata.

- [README.md](README.md) is the current CLI and operations reference.
  Go code and unit tests live at the root; the Svelte UI is in `webui/`.
- `web.go` embeds tracked `webui/dist` into the binary. For UI changes,
  rebuild the assets and review/commit their diff with the source change;
  `go build` alone embeds the existing assets and does not rebuild Svelte.
- Capture, service installation, rollup import/prune and retention settings are
  operational actions. Never run them against working interfaces/logs/databases
  as a development smoke test. Use synthetic inputs and temporary data in tests.
- Real peer configs, traffic logs and rollup databases contain private network
  data; do not copy them into fixtures or commit them for debugging.
- Preserve the non-loopback authentication guard in `web.go` and the session
  contract in `auth.go`. Do not use `--allow-no-auth` to make a check pass.

From the root, the local Go unit suite is:

```sh
go test ./...
```

With UI dependencies installed, these are separate checks/build steps:

```sh
pnpm --dir webui check
pnpm --dir webui build
```

The Vite dev server proxies `/api` to localhost:8080; that backend may expose
real traffic history. Use controlled test data when checking the interface.
