package main

import (
	"fmt"
	"log"
	"os"
	"time"
)

type Config struct {
	Iface           string
	WGConfigPath    string
	LogDir          string
	RollupPath      string
	FlushInterval   time.Duration
	RollupRetention time.Duration
	VPNCIDRs        []string
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		if err := serve(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "top":
		if err := top(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "report":
		if err := report(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "rollup-import":
		if err := rollupImport(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "rollup-prune":
		if err := rollupPrune(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "stats":
		if err := statsCmd(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "web":
		if err := webCmd(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `wgflow

Usage:
  wgflow serve --iface wg0 --wg-config /etc/wireguard/wg0.conf --log-dir /var/log/wgflow
  wgflow top --since 5m [--client maxim] [--log-dir /var/log/wgflow] [--limit 30]
  wgflow report --since 24h [--log-dir /var/log/wgflow]
  wgflow rollup-import --since 24h [--reset]
  wgflow rollup-prune --keep 30d [--rollup /var/lib/wgflow/rollup.db]
  wgflow stats [--log-dir /var/log/wgflow] [--json]
  wgflow web [--listen :8080] [--log-dir /var/log/wgflow] [--rollup /var/lib/wgflow/rollup.db]

`)
}
