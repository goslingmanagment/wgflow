package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	bolt "go.etcd.io/bbolt"
)

type Config struct {
	Iface         string
	WGConfigPath  string
	LogDir        string
	RollupPath    string
	FlushInterval time.Duration
	VPNCIDRs      []string
}

type RuntimeStats struct {
	StartedAt                  time.Time `json:"started_at"`
	UpdatedAt                  time.Time `json:"updated_at"`
	Interface                  string    `json:"interface"`
	ClientCount                int       `json:"client_count"`
	PacketSeen                 uint64    `json:"packet_seen"`
	PacketDecoded              uint64    `json:"packet_decoded"`
	PacketMatched              uint64    `json:"packet_matched"`
	BytesSeen                  uint64    `json:"bytes_seen"`
	PacketRatePerSecond        float64   `json:"packet_rate_per_second"`
	BitRatePerSecond           float64   `json:"bit_rate_per_second"`
	AveragePacketRatePerSecond float64   `json:"average_packet_rate_per_second"`
	AverageBitRatePerSecond    float64   `json:"average_bit_rate_per_second"`
	FlowRecords                uint64    `json:"flow_records"`
	DNSRecords                 uint64    `json:"dns_records"`
	TLSRecords                 uint64    `json:"tls_records"`
	KernelPacketSocketPackets  uint64    `json:"kernel_packet_socket_packets"`
	KernelPacketSocketDrops    uint64    `json:"kernel_packet_socket_drops"`
	LastKernelDropsDelta       uint64    `json:"last_kernel_drops_delta"`
	LastFlushRecords           uint64    `json:"last_flush_records"`
	LastFlushAt                time.Time `json:"last_flush_at"`
	CurrentFlowKeys            int       `json:"current_flow_keys"`
	FlowQueueKeys              int       `json:"flow_queue_keys"`
	RollupPendingRecords       uint64    `json:"rollup_pending_records"`
	ConfigPath                 string    `json:"config_path"`
	ConfigReloads              uint64    `json:"config_reloads"`
	ConfigLastLoadedAt         time.Time `json:"config_last_loaded_at"`
	ConfigLastModTime          time.Time `json:"config_last_mod_time"`
	FlowsLogBytes              int64     `json:"flows_log_bytes"`
	DNSLogBytes                int64     `json:"dns_log_bytes"`
	TLSLogBytes                int64     `json:"tls_log_bytes"`
	RollupDBBytes              int64     `json:"rollup_db_bytes"`
}

type StatsCollector struct {
	startedAt          time.Time
	iface              string
	statsPath          string
	configPath         string
	flowPath           string
	dnsPath            string
	tlsPath            string
	rollupPath         string
	clientCount        atomic.Uint64
	packetSeen         atomic.Uint64
	packetDecoded      atomic.Uint64
	packetMatched      atomic.Uint64
	bytesSeen          atomic.Uint64
	flowRecords        atomic.Uint64
	dnsRecords         atomic.Uint64
	tlsRecords         atomic.Uint64
	kernelPackets      atomic.Uint64
	kernelDrops        atomic.Uint64
	lastDropsDelta     atomic.Uint64
	lastFlushRecords   atomic.Uint64
	currentFlowKeys    atomic.Uint64
	rollupPending      atomic.Uint64
	configReloads      atomic.Uint64
	configLastLoadedNS atomic.Int64
	configLastModNS    atomic.Int64
	lastFlushNS        atomic.Int64
	rateMu             sync.Mutex
	lastSampleAt       time.Time
	lastSamplePackets  uint64
	lastSampleBytes    uint64
	packetRate         float64
	bitRate            float64
}

type RollupRow struct {
	Minute          int64  `json:"minute"`
	Client          string `json:"client"`
	Category        string `json:"category"`
	Target          string `json:"target"`
	Proto           string `json:"proto"`
	Port            uint16 `json:"port"`
	DownloadBytes   uint64 `json:"download_bytes"`
	UploadBytes     uint64 `json:"upload_bytes"`
	DownloadPackets uint64 `json:"download_packets"`
	UploadPackets   uint64 `json:"upload_packets"`
}

type RollupTotal struct {
	Minute          int64
	Name            string
	DownloadBytes   uint64
	UploadBytes     uint64
	DownloadPackets uint64
	UploadPackets   uint64
}

type RollupStore struct {
	path string
}

type ClientMap struct {
	mu      sync.RWMutex
	byIP    map[string]string
	vpnNets []*net.IPNet
}

type FlowKey struct {
	ClientIP   string
	RemoteIP   string
	Proto      string
	RemotePort uint16
}

type FlowStats struct {
	Client          string
	ClientIP        string
	RemoteIP        string
	Proto           string
	RemotePort      uint16
	UploadBytes     uint64
	DownloadBytes   uint64
	UploadPackets   uint64
	DownloadPackets uint64
}

type FlowRecord struct {
	TSStart               time.Time `json:"ts_start"`
	TSEnd                 time.Time `json:"ts_end"`
	Interface             string    `json:"interface"`
	Client                string    `json:"client"`
	ClientIP              string    `json:"client_ip"`
	RemoteIP              string    `json:"remote_ip"`
	RemotePort            uint16    `json:"remote_port"`
	Proto                 string    `json:"proto"`
	Domain                string    `json:"domain,omitempty"`
	ClientUploadBytes     uint64    `json:"client_upload_bytes"`
	ClientDownloadBytes   uint64    `json:"client_download_bytes"`
	ClientUploadPackets   uint64    `json:"client_upload_packets"`
	ClientDownloadPackets uint64    `json:"client_download_packets"`
}

type DNSAnswer struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

type DNSRecord struct {
	TS        time.Time   `json:"ts"`
	Interface string      `json:"interface"`
	Client    string      `json:"client"`
	ClientIP  string      `json:"client_ip"`
	ServerIP  string      `json:"server_ip"`
	Proto     string      `json:"proto"`
	Query     string      `json:"query"`
	QType     string      `json:"qtype"`
	RCode     int         `json:"rcode"`
	Response  bool        `json:"response"`
	Answers   []DNSAnswer `json:"answers,omitempty"`
}

type TLSRecord struct {
	TS         time.Time `json:"ts"`
	Interface  string    `json:"interface"`
	Client     string    `json:"client"`
	ClientIP   string    `json:"client_ip"`
	RemoteIP   string    `json:"remote_ip"`
	RemotePort uint16    `json:"remote_port"`
	ServerName string    `json:"server_name"`
}

type packetInfo struct {
	SrcIP, DstIP     net.IP
	Proto            uint8
	SrcPort, DstPort uint16
	TransportPayload []byte
	Length           int
}

type domainEntry struct {
	Domain  string
	Expires time.Time
}

type DomainCache struct {
	mu         sync.RWMutex
	byClientIP map[string]domainEntry
	byIP       map[string]domainEntry
}

type JSONLogger struct {
	mu  sync.Mutex
	enc *json.Encoder
	f   *os.File
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
  wgflow stats [--log-dir /var/log/wgflow] [--json]
  wgflow web [--listen :8080] [--log-dir /var/log/wgflow] [--rollup /var/lib/wgflow/rollup.db]

`)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfg := Config{}
	fs.StringVar(&cfg.Iface, "iface", "wg0", "WireGuard interface to capture")
	fs.StringVar(&cfg.WGConfigPath, "wg-config", "/etc/wireguard/wg0.conf", "WireGuard config path")
	fs.StringVar(&cfg.LogDir, "log-dir", "/var/log/wgflow", "log directory")
	fs.StringVar(&cfg.RollupPath, "rollup", "/var/lib/wgflow/rollup.db", "rollup DB path")
	fs.DurationVar(&cfg.FlushInterval, "flush", 30*time.Second, "flow flush interval")
	var cidrList multiFlag
	cidrList = append(cidrList, "10.66.66.0/24", "fd42:42:42::/64")
	fs.Var(&cidrList, "vpn-cidr", "VPN client CIDR; can be repeated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg.VPNCIDRs = cidrList

	if err := os.MkdirAll(cfg.LogDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.RollupPath), 0755); err != nil {
		return err
	}

	clients := &ClientMap{}
	if err := clients.Load(cfg.WGConfigPath, cfg.VPNCIDRs); err != nil {
		return err
	}
	configSig, _ := fileSig(cfg.WGConfigPath)

	flowLog, err := NewJSONLogger(filepath.Join(cfg.LogDir, "flows.jsonl"))
	if err != nil {
		return err
	}
	defer flowLog.Close()
	dnsLog, err := NewJSONLogger(filepath.Join(cfg.LogDir, "dns.jsonl"))
	if err != nil {
		return err
	}
	defer dnsLog.Close()
	tlsLog, err := NewJSONLogger(filepath.Join(cfg.LogDir, "tls.jsonl"))
	if err != nil {
		return err
	}
	defer tlsLog.Close()
	rollup, err := OpenRollup(cfg.RollupPath)
	if err != nil {
		return err
	}
	defer rollup.Close()
	stats := NewStatsCollector(cfg, clients.Count())
	stats.SetConfigLoaded(configSig.ModTime)
	defer stats.Write()

	fd, err := openPacketSocket(cfg.Iface)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	cache := NewDomainCache()
	flows := make(map[FlowKey]*FlowStats)
	var flowMu sync.Mutex
	intervalStart := time.Now()
	flushTicker := time.NewTicker(cfg.FlushInterval)
	defer flushTicker.Stop()
	reloadTicker := time.NewTicker(60 * time.Second)
	defer reloadTicker.Stop()
	statsTicker := time.NewTicker(30 * time.Second)
	defer statsTicker.Stop()
	var pendingRollup []FlowRecord

	log.Printf("wgflow capture started iface=%s log_dir=%s rollup=%s flush=%s clients=%d", cfg.Iface, cfg.LogDir, cfg.RollupPath, cfg.FlushInterval, clients.Count())

	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				log.Printf("recvfrom error: %v", err)
				time.Sleep(time.Second)
				continue
			}
			if n <= 0 {
				continue
			}
			stats.packetSeen.Add(1)
			stats.bytesSeen.Add(uint64(n))
			pkt, ok := parsePacket(buf[:n])
			if !ok {
				continue
			}
			stats.packetDecoded.Add(1)
			if pkt.Proto != 6 && pkt.Proto != 17 {
				continue
			}
			clientIP, clientName, outbound, ok := clients.Match(pkt.SrcIP, pkt.DstIP)
			if !ok {
				continue
			}
			stats.packetMatched.Add(1)
			proto := protoName(pkt.Proto)
			remoteIP := pkt.DstIP.String()
			remotePort := pkt.DstPort
			if !outbound {
				remoteIP = pkt.SrcIP.String()
				remotePort = pkt.SrcPort
			}
			key := FlowKey{ClientIP: clientIP, RemoteIP: remoteIP, Proto: proto, RemotePort: remotePort}
			flowMu.Lock()
			st := flows[key]
			if st == nil {
				st = &FlowStats{
					Client: clientName, ClientIP: clientIP, RemoteIP: remoteIP,
					Proto: proto, RemotePort: remotePort,
				}
				flows[key] = st
			}
			if outbound {
				st.UploadBytes += uint64(pkt.Length)
				st.UploadPackets++
			} else {
				st.DownloadBytes += uint64(pkt.Length)
				st.DownloadPackets++
			}
			flowMu.Unlock()

			if pkt.SrcPort == 53 || pkt.DstPort == 53 {
				if rec, answers := parseDNSPacket(time.Now(), cfg.Iface, clientName, clientIP, remoteIP, proto, outbound, pkt); rec != nil {
					_ = dnsLog.Write(rec)
					stats.dnsRecords.Add(1)
					for _, ans := range answers {
						if ans.Type == "A" || ans.Type == "AAAA" {
							cache.Put(clientIP, ans.Value, rec.Query, ans.TTL)
						}
					}
				}
			}
			if outbound && pkt.Proto == 6 && pkt.DstPort == 443 {
				if sni := parseTLSSNI(pkt.TransportPayload); sni != "" {
					cache.Put(clientIP, remoteIP, sni, 3600)
					_ = tlsLog.Write(TLSRecord{
						TS: time.Now(), Interface: cfg.Iface, Client: clientName,
						ClientIP: clientIP, RemoteIP: remoteIP, RemotePort: pkt.DstPort,
						ServerName: sni,
					})
					stats.tlsRecords.Add(1)
				}
			}
		}
	}()

	for {
		select {
		case sig := <-sigCh:
			if sig == syscall.SIGHUP {
				if err := clients.Load(cfg.WGConfigPath, cfg.VPNCIDRs); err != nil {
					log.Printf("reload failed: %v", err)
				} else {
					configSig, _ = fileSig(cfg.WGConfigPath)
					stats.clientCount.Store(uint64(clients.Count()))
					stats.configReloads.Add(1)
					stats.SetConfigLoaded(configSig.ModTime)
					log.Printf("reloaded %s clients=%d", cfg.WGConfigPath, clients.Count())
				}
				continue
			}
			log.Printf("stopping on %s", sig)
			return nil
		case <-reloadTicker.C:
			nextSig, err := fileSig(cfg.WGConfigPath)
			if err != nil {
				log.Printf("config stat failed: %v", err)
				continue
			}
			if nextSig != configSig {
				if err := clients.Load(cfg.WGConfigPath, cfg.VPNCIDRs); err != nil {
					log.Printf("config reload failed: %v", err)
					continue
				}
				configSig = nextSig
				stats.clientCount.Store(uint64(clients.Count()))
				stats.configReloads.Add(1)
				stats.SetConfigLoaded(configSig.ModTime)
				log.Printf("config changed; reloaded %s clients=%d", cfg.WGConfigPath, clients.Count())
			}
		case now := <-flushTicker.C:
			flowMu.Lock()
			batch := flows
			flows = make(map[FlowKey]*FlowStats)
			start := intervalStart
			intervalStart = now
			flowMu.Unlock()
			records := make([]FlowRecord, 0, len(batch))
			for _, st := range batch {
				rec := FlowRecord{
					TSStart: start, TSEnd: now, Interface: cfg.Iface,
					Client: st.Client, ClientIP: st.ClientIP, RemoteIP: st.RemoteIP,
					RemotePort: st.RemotePort, Proto: st.Proto,
					Domain:            cache.Lookup(st.ClientIP, st.RemoteIP),
					ClientUploadBytes: st.UploadBytes, ClientDownloadBytes: st.DownloadBytes,
					ClientUploadPackets: st.UploadPackets, ClientDownloadPackets: st.DownloadPackets,
				}
				_ = flowLog.Write(rec)
				records = append(records, rec)
			}
			if len(records) > 0 {
				pendingRollup = append(pendingRollup, records...)
			}
			if len(pendingRollup) > 0 {
				if err := rollup.Add(pendingRollup); err != nil {
					log.Printf("rollup write failed: %v pending_records=%d", err, len(pendingRollup))
				} else {
					pendingRollup = nil
				}
			}
			stats.rollupPending.Store(uint64(len(pendingRollup)))
			stats.flowRecords.Add(uint64(len(records)))
			stats.lastFlushRecords.Store(uint64(len(records)))
			stats.currentFlowKeys.Store(0)
			stats.lastFlushNS.Store(now.UnixNano())
			if pkts, drops, err := packetSocketStats(fd); err == nil {
				prevDrops := stats.kernelDrops.Load()
				stats.kernelPackets.Add(pkts)
				stats.kernelDrops.Add(drops)
				stats.lastDropsDelta.Store(stats.kernelDrops.Load() - prevDrops)
			}
			_ = stats.Write()
		case <-statsTicker.C:
			flowMu.Lock()
			stats.currentFlowKeys.Store(uint64(len(flows)))
			flowMu.Unlock()
			_ = stats.Write()
		}
	}
}

type TopAgg struct {
	Client, Category, Target, Proto string
	Port                            uint16
	Up, Down, UpP, DownP            uint64
}

func top(args []string) error {
	fs := flag.NewFlagSet("top", flag.ExitOnError)
	logDir := fs.String("log-dir", "/var/log/wgflow", "log directory")
	rollupPath := fs.String("rollup", "/var/lib/wgflow/rollup.db", "rollup DB path")
	sinceStr := fs.String("since", "30m", "time window, e.g. 5m, 30m, 1h")
	clientFilter := fs.String("client", "", "client name filter")
	source := fs.String("source", "auto", "auto, rollup, or log")
	limit := fs.Int("limit", 30, "row limit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	d, err := time.ParseDuration(*sinceStr)
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-d)
	aggs := map[string]*TopAgg{}
	used := "log"
	if *source == "auto" || *source == "rollup" {
		n, err := aggregateFromRollup(*rollupPath, cutoff, *clientFilter, aggs)
		if err != nil && *source == "rollup" {
			return err
		}
		if n > 0 {
			used = "rollup"
		} else if *source == "rollup" {
			used = "rollup"
		}
	}
	if len(aggs) == 0 && *source != "rollup" {
		path := filepath.Join(*logDir, "flows.jsonl")
		if err := readRecentFlowRecords(path, cutoff, func(rec FlowRecord) {
			if *clientFilter != "" && rec.Client != *clientFilter {
				return
			}
			addFlowAgg(aggs, rec)
		}); err != nil {
			return err
		}
		used = "log-tail"
	}
	rows := make([]*TopAgg, 0, len(aggs))
	for _, a := range aggs {
		rows = append(rows, a)
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Up+rows[i].Down > rows[j].Up+rows[j].Down
	})
	if *limit > len(rows) {
		*limit = len(rows)
	}
	fmt.Printf("Window: last %s, rows=%d, source=%s\n", d, *limit, used)
	fmt.Printf("%-15s %-14s %-42s %-9s %12s %12s %12s\n", "CLIENT", "CATEGORY", "TARGET", "PROTO:PORT", "DOWNLOAD", "UPLOAD", "TOTAL")
	for i := 0; i < *limit; i++ {
		a := rows[i]
		pp := fmt.Sprintf("%s:%d", a.Proto, a.Port)
		fmt.Printf("%-15s %-14s %-42s %-9s %12s %12s %12s\n",
			trunc(a.Client, 15), trunc(a.Category, 14), trunc(a.Target, 42), pp,
			humanBytes(a.Down), humanBytes(a.Up), humanBytes(a.Down+a.Up))
	}
	return nil
}

func report(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	rollupPath := fs.String("rollup", "/var/lib/wgflow/rollup.db", "rollup DB path")
	sinceStr := fs.String("since", "24h", "time window, e.g. 1h, 24h")
	if err := fs.Parse(args); err != nil {
		return err
	}
	d, err := time.ParseDuration(*sinceStr)
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-d)
	byClient, byCategory, n, err := aggregateReportTotalsFromRollup(*rollupPath, cutoff)
	if err != nil {
		return err
	}
	if n == 0 {
		aggs := map[string]*TopAgg{}
		var fallbackRows int
		fallbackRows, err = aggregateFromRollup(*rollupPath, cutoff, "", aggs)
		if err != nil {
			return err
		}
		n = fallbackRows
		for _, a := range aggs {
			c := byClient[a.Client]
			if c == nil {
				c = &TopAgg{Client: a.Client}
				byClient[a.Client] = c
			}
			c.Down += a.Down
			c.Up += a.Up
			k := a.Category
			if k == "" {
				k = "other"
			}
			cat := byCategory[k]
			if cat == nil {
				cat = &TopAgg{Category: k}
				byCategory[k] = cat
			}
			cat.Down += a.Down
			cat.Up += a.Up
		}
	}
	fmt.Printf("Report: last %s, rollup_rows=%d\n\n", d, n)
	printAggList("By client", byClient, func(a *TopAgg) string { return a.Client })
	fmt.Println()
	printAggList("By category", byCategory, func(a *TopAgg) string { return a.Category })
	return nil
}

func rollupImport(args []string) error {
	fs := flag.NewFlagSet("rollup-import", flag.ExitOnError)
	logDir := fs.String("log-dir", "/var/log/wgflow", "log directory")
	rollupPath := fs.String("rollup", "/var/lib/wgflow/rollup.db", "rollup DB path")
	sinceStr := fs.String("since", "24h", "time window to import, e.g. 1h, 24h")
	reset := fs.Bool("reset", false, "delete existing rollup before import")
	if err := fs.Parse(args); err != nil {
		return err
	}
	d, err := time.ParseDuration(*sinceStr)
	if err != nil {
		return err
	}
	if *reset {
		if err := os.Remove(*rollupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(*rollupPath), 0755); err != nil {
		return err
	}
	rollup, err := OpenRollup(*rollupPath)
	if err != nil {
		return err
	}
	defer rollup.Close()
	var batch []FlowRecord
	var count int
	var firstErr error
	flush := func() {
		if len(batch) == 0 || firstErr != nil {
			return
		}
		if err := rollup.Add(batch); err != nil {
			firstErr = err
			return
		}
		count += len(batch)
		batch = batch[:0]
	}
	path := filepath.Join(*logDir, "flows.jsonl")
	if err := readRecentFlowRecords(path, time.Now().Add(-d), func(rec FlowRecord) {
		if firstErr != nil {
			return
		}
		batch = append(batch, rec)
		if len(batch) >= 1000 {
			flush()
		}
	}); err != nil {
		return err
	}
	flush()
	if firstErr != nil {
		return firstErr
	}
	fmt.Printf("imported_records=%d rollup=%s window=%s\n", count, *rollupPath, d)
	return nil
}

func statsCmd(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	logDir := fs.String("log-dir", "/var/log/wgflow", "log directory")
	jsonOut := fs.Bool("json", false, "print raw JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(*logDir, "stats.json"))
	if err != nil {
		return err
	}
	if *jsonOut {
		fmt.Print(string(b))
		return nil
	}
	var s RuntimeStats
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	uptime := time.Since(s.StartedAt).Round(time.Second)
	fmt.Printf("wgflow stats %s\n", s.UpdatedAt.Format(time.RFC3339))
	fmt.Printf("uptime=%s iface=%s clients=%d flow_queue_keys=%d\n", uptime, s.Interface, s.ClientCount, s.FlowQueueKeys)
	fmt.Printf("rate current=%.1f pps %.2f Mbit/s avg=%.1f pps %.2f Mbit/s\n",
		s.PacketRatePerSecond, s.BitRatePerSecond/1000000,
		s.AveragePacketRatePerSecond, s.AverageBitRatePerSecond/1000000)
	fmt.Printf("packets seen=%d decoded=%d matched=%d bytes_seen=%s\n", s.PacketSeen, s.PacketDecoded, s.PacketMatched, humanBytes(s.BytesSeen))
	fmt.Printf("records flows=%d dns=%d tls=%d last_flush=%d at=%s\n", s.FlowRecords, s.DNSRecords, s.TLSRecords, s.LastFlushRecords, s.LastFlushAt.Format(time.RFC3339))
	fmt.Printf("kernel_packet_socket packets=%d drops=%d last_drops_delta=%d\n", s.KernelPacketSocketPackets, s.KernelPacketSocketDrops, s.LastKernelDropsDelta)
	fmt.Printf("logs flows=%s dns=%s tls=%s rollup=%s\n", humanBytes(uint64(max64(s.FlowsLogBytes, 0))), humanBytes(uint64(max64(s.DNSLogBytes, 0))), humanBytes(uint64(max64(s.TLSLogBytes, 0))), humanBytes(uint64(max64(s.RollupDBBytes, 0))))
	fmt.Printf("config reloads=%d last_loaded=%s mod_time=%s\n", s.ConfigReloads, s.ConfigLastLoadedAt.Format(time.RFC3339), s.ConfigLastModTime.Format(time.RFC3339))
	return nil
}

func addFlowAgg(aggs map[string]*TopAgg, rec FlowRecord) {
	target := rec.Domain
	if target == "" {
		target = rec.RemoteIP
	}
	cat := categorize(target, rec.RemoteIP, rec.Proto, rec.RemotePort)
	key := rec.Client + "\t" + cat + "\t" + target + "\t" + rec.Proto + "\t" + strconv.Itoa(int(rec.RemotePort))
	a := aggs[key]
	if a == nil {
		a = &TopAgg{Client: rec.Client, Category: cat, Target: target, Proto: rec.Proto, Port: rec.RemotePort}
		aggs[key] = a
	}
	a.Up += rec.ClientUploadBytes
	a.Down += rec.ClientDownloadBytes
	a.UpP += rec.ClientUploadPackets
	a.DownP += rec.ClientDownloadPackets
}

func printAggList(title string, m map[string]*TopAgg, label func(*TopAgg) string) {
	rows := make([]*TopAgg, 0, len(m))
	for _, a := range m {
		rows = append(rows, a)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Down+rows[i].Up > rows[j].Down+rows[j].Up })
	fmt.Println(title + ":")
	fmt.Printf("%-24s %12s %12s %12s\n", "NAME", "DOWNLOAD", "UPLOAD", "TOTAL")
	for _, a := range rows {
		fmt.Printf("%-24s %12s %12s %12s\n", trunc(label(a), 24), humanBytes(a.Down), humanBytes(a.Up), humanBytes(a.Down+a.Up))
	}
}

func readRecentFlowRecords(path string, cutoff time.Time, fn func(FlowRecord)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	const block = 256 * 1024
	var carry []byte
	for pos := st.Size(); pos > 0; {
		n := int64(block)
		if pos < n {
			n = pos
		}
		pos -= n
		buf := make([]byte, n)
		if _, err := f.ReadAt(buf, pos); err != nil && err != io.EOF {
			return err
		}
		buf = append(buf, carry...)
		lines := strings.Split(string(buf), "\n")
		if pos > 0 {
			carry = []byte(lines[0])
			lines = lines[1:]
		} else {
			carry = nil
		}
		for i := len(lines) - 1; i >= 0; i-- {
			line := strings.TrimSpace(lines[i])
			if line == "" {
				continue
			}
			var rec FlowRecord
			if json.Unmarshal([]byte(line), &rec) != nil {
				continue
			}
			if rec.TSEnd.Before(cutoff) {
				return nil
			}
			fn(rec)
		}
	}
	return nil
}

func categorize(target, remoteIP, proto string, port uint16) string {
	t := strings.ToLower(target)
	ip := remoteIP
	if net.ParseIP(t) != nil {
		ip = t
		t = ""
	}
	switch {
	case containsAny(t, "instagram", "fbcdn", "facebook", "whatsapp", "meta.com") || ipPrefix(ip, "57.144.", "157.240.", "31.13.", "163.70."):
		return "meta"
	case containsAny(t, "youtube", "googlevideo", "ytimg", "googleapis", "googleusercontent") || ipPrefix(ip, "142.250.", "142.251.", "172.217.", "173.194.", "74.125.", "216.239."):
		return "google"
	case containsAny(t, "yandex", "strm.yandex", "appmetrica") || ipPrefix(ip, "87.250.", "213.180.", "37.9.", "5.45."):
		return "yandex"
	case containsAny(t, "icloud", "apple.com", "mzstatic", "itunes", "aaplimg") || ipPrefix(ip, "17."):
		return "apple"
	case containsAny(t, "telegram", "t.me") || ipPrefix(ip, "149.154.", "91.108.", "91.105."):
		return "telegram"
	case containsAny(t, "vk.com", "vkontakte", "userapi.com", "vk-cdn", "mycdn.me", "vkuser", "vkgroup", "vk.me") || ipPrefix(ip, "87.240.", "93.186.", "95.142.", "95.213."):
		return "vk"
	case containsAny(t, "netflix", "nflxvideo", "nflximg", "nflxext", "nflxso"):
		return "netflix"
	case containsAny(t, "spotify", "scdn.co", "pscdn.co", "spotifycdn"):
		return "spotify"
	case containsAny(t, "twitch", "ttvnw.net", "jtvnw.net", "live-video.net"):
		return "twitch"
	case containsAny(t, "discord", "discordapp"):
		return "discord"
	case containsAny(t, "microsoft", "windowsupdate", "office.com", "office365", "live.com", "outlook", "msedge", "bing.com", "azureedge", "msftncsi", "msftconnecttest", "skype"):
		return "microsoft"
	case containsAny(t, "wildberries"):
		return "wildberries"
	case containsAny(t, "fansly", "fbuddy"):
		return "fansly"
	case containsAny(t, "one.one.one.one") || ip == "1.1.1.1" || ip == "1.0.0.1":
		return "dns"
	case containsAny(t, "cloudflare", "workers.dev", "pages.dev") || ipPrefix(ip,
		"104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
		"104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "104.29.", "104.30.", "104.31.",
		"162.158.", "162.159.", "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
		"172.70.", "172.71.", "188.114."):
		return "cloudflare"
	case containsAny(t, "cloudfront", "amazonaws", "awsstatic"):
		return "aws"
	case containsAny(t, "battle.net", "blizzard", "steam", "steampowered", "steamcontent", "epicgames", "riotgames", "xboxlive", "playstation"):
		return "games"
	case containsAny(t, "akamai", "akamaized", "fastly", "edgekey", "edgesuite", "llnwd", "cdn77", "jsdelivr", "stackpath"):
		return "cdn"
	case port == 6881 || (port >= 6881 && port <= 6999):
		return "p2p"
	default:
		return "other"
	}
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func ipPrefix(ip string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	return false
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

var rollupBucket = []byte("flow_minute_v1")
var rollupClientBucket = []byte("flow_client_minute_v1")
var rollupCategoryBucket = []byte("flow_category_minute_v1")
var rollupClientCategoryBucket = []byte("flow_client_category_minute_v1")

type RollupClientCategoryTotal struct {
	Minute          int64
	Client          string
	Category        string
	DownloadBytes   uint64
	UploadBytes     uint64
	DownloadPackets uint64
	UploadPackets   uint64
}

func OpenRollup(path string) (*RollupStore, error) {
	return &RollupStore{path: path}, nil
}

func (r *RollupStore) Close() error {
	return nil
}

func (r *RollupStore) Add(records []FlowRecord) error {
	if r == nil || r.path == "" || len(records) == 0 {
		return nil
	}
	db, err := bolt.Open(r.path, 0644, &bolt.Options{Timeout: 30 * time.Second})
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(rollupBucket)
		if err != nil {
			return err
		}
		clientTotals := map[string]*RollupTotal{}
		categoryTotals := map[string]*RollupTotal{}
		clientCategoryTotals := map[string]*RollupClientCategoryTotal{}
		for _, rec := range records {
			target := rec.Domain
			if target == "" {
				target = rec.RemoteIP
			}
			category := categorize(target, rec.RemoteIP, rec.Proto, rec.RemotePort)
			row := RollupRow{
				Minute:          rec.TSEnd.Unix() / 60,
				Client:          rec.Client,
				Category:        category,
				Target:          target,
				Proto:           rec.Proto,
				Port:            rec.RemotePort,
				DownloadBytes:   rec.ClientDownloadBytes,
				UploadBytes:     rec.ClientUploadBytes,
				DownloadPackets: rec.ClientDownloadPackets,
				UploadPackets:   rec.ClientUploadPackets,
			}
			addRollupTotal(clientTotals, row.Minute, row.Client, row.DownloadBytes, row.UploadBytes, row.DownloadPackets, row.UploadPackets)
			addRollupTotal(categoryTotals, row.Minute, row.Category, row.DownloadBytes, row.UploadBytes, row.DownloadPackets, row.UploadPackets)
			addRollupClientCategoryTotal(clientCategoryTotals, row.Minute, row.Client, row.Category, row.DownloadBytes, row.UploadBytes, row.DownloadPackets, row.UploadPackets)
			key := rollupKey(row)
			if old := b.Get(key); old != nil {
				var existing RollupRow
				if json.Unmarshal(old, &existing) == nil {
					row.DownloadBytes += existing.DownloadBytes
					row.UploadBytes += existing.UploadBytes
					row.DownloadPackets += existing.DownloadPackets
					row.UploadPackets += existing.UploadPackets
				}
			}
			raw, err := json.Marshal(row)
			if err != nil {
				return err
			}
			if err := b.Put(key, raw); err != nil {
				return err
			}
		}
		if err := putRollupTotals(tx, rollupClientBucket, clientTotals); err != nil {
			return err
		}
		if err := putRollupTotals(tx, rollupCategoryBucket, categoryTotals); err != nil {
			return err
		}
		if err := putRollupClientCategoryTotals(tx, clientCategoryTotals); err != nil {
			return err
		}
		return nil
	})
}

func rollupKey(row RollupRow) []byte {
	return []byte(fmt.Sprintf("%012d\t%s\t%s\t%s\t%s\t%d", row.Minute, row.Client, row.Category, row.Target, row.Proto, row.Port))
}

func rollupTotalKey(minute int64, name string) []byte {
	return []byte(fmt.Sprintf("%012d\t%s", minute, name))
}

func rollupClientCategoryKey(minute int64, client, category string) []byte {
	return []byte(fmt.Sprintf("%s\t%012d\t%s", client, minute, category))
}

func addRollupTotal(m map[string]*RollupTotal, minute int64, name string, down, up, downP, upP uint64) {
	key := fmt.Sprintf("%012d\t%s", minute, name)
	t := m[key]
	if t == nil {
		t = &RollupTotal{Minute: minute, Name: name}
		m[key] = t
	}
	t.DownloadBytes += down
	t.UploadBytes += up
	t.DownloadPackets += downP
	t.UploadPackets += upP
}

func addRollupClientCategoryTotal(m map[string]*RollupClientCategoryTotal, minute int64, client, category string, down, up, downP, upP uint64) {
	key := string(rollupClientCategoryKey(minute, client, category))
	t := m[key]
	if t == nil {
		t = &RollupClientCategoryTotal{Minute: minute, Client: client, Category: category}
		m[key] = t
	}
	t.DownloadBytes += down
	t.UploadBytes += up
	t.DownloadPackets += downP
	t.UploadPackets += upP
}

func putRollupTotals(tx *bolt.Tx, bucket []byte, totals map[string]*RollupTotal) error {
	if len(totals) == 0 {
		return nil
	}
	b, err := tx.CreateBucketIfNotExists(bucket)
	if err != nil {
		return err
	}
	for _, t := range totals {
		key := rollupTotalKey(t.Minute, t.Name)
		if old := b.Get(key); len(old) == 32 {
			existing := decodeRollupTotalValue(old)
			t.DownloadBytes += existing.DownloadBytes
			t.UploadBytes += existing.UploadBytes
			t.DownloadPackets += existing.DownloadPackets
			t.UploadPackets += existing.UploadPackets
		}
		if err := b.Put(key, encodeRollupTotalValue(t)); err != nil {
			return err
		}
	}
	return nil
}

func putRollupClientCategoryTotals(tx *bolt.Tx, totals map[string]*RollupClientCategoryTotal) error {
	if len(totals) == 0 {
		return nil
	}
	b, err := tx.CreateBucketIfNotExists(rollupClientCategoryBucket)
	if err != nil {
		return err
	}
	for _, t := range totals {
		key := rollupClientCategoryKey(t.Minute, t.Client, t.Category)
		if old := b.Get(key); len(old) == 32 {
			existing := decodeRollupTotalValue(old)
			t.DownloadBytes += existing.DownloadBytes
			t.UploadBytes += existing.UploadBytes
			t.DownloadPackets += existing.DownloadPackets
			t.UploadPackets += existing.UploadPackets
		}
		val := &RollupTotal{
			DownloadBytes:   t.DownloadBytes,
			UploadBytes:     t.UploadBytes,
			DownloadPackets: t.DownloadPackets,
			UploadPackets:   t.UploadPackets,
		}
		if err := b.Put(key, encodeRollupTotalValue(val)); err != nil {
			return err
		}
	}
	return nil
}

func encodeRollupTotalValue(t *RollupTotal) []byte {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b[0:8], t.DownloadBytes)
	binary.BigEndian.PutUint64(b[8:16], t.UploadBytes)
	binary.BigEndian.PutUint64(b[16:24], t.DownloadPackets)
	binary.BigEndian.PutUint64(b[24:32], t.UploadPackets)
	return b
}

func decodeRollupTotalValue(b []byte) RollupTotal {
	if len(b) < 32 {
		return RollupTotal{}
	}
	return RollupTotal{
		DownloadBytes:   binary.BigEndian.Uint64(b[0:8]),
		UploadBytes:     binary.BigEndian.Uint64(b[8:16]),
		DownloadPackets: binary.BigEndian.Uint64(b[16:24]),
		UploadPackets:   binary.BigEndian.Uint64(b[24:32]),
	}
}

func aggregateReportTotalsFromRollup(path string, cutoff time.Time) (map[string]*TopAgg, map[string]*TopAgg, int, error) {
	byClient := map[string]*TopAgg{}
	byCategory := map[string]*TopAgg{}
	db, err := bolt.Open(path, 0444, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return byClient, byCategory, 0, err
	}
	defer db.Close()
	cutoffMinute := cutoff.Unix() / 60
	count := 0
	err = db.View(func(tx *bolt.Tx) error {
		count += readRollupTotalBucket(tx, rollupClientBucket, cutoffMinute, byClient, true)
		count += readRollupTotalBucket(tx, rollupCategoryBucket, cutoffMinute, byCategory, false)
		return nil
	})
	return byClient, byCategory, count, err
}

func readRollupTotalBucket(tx *bolt.Tx, bucket []byte, cutoffMinute int64, dst map[string]*TopAgg, client bool) int {
	b := tx.Bucket(bucket)
	if b == nil {
		return 0
	}
	count := 0
	start := []byte(fmt.Sprintf("%012d", cutoffMinute))
	c := b.Cursor()
	for k, v := c.Seek(start); k != nil; k, v = c.Next() {
		parts := strings.SplitN(string(k), "\t", 2)
		if len(parts) != 2 {
			continue
		}
		minute, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || minute < cutoffMinute {
			continue
		}
		name := parts[1]
		total := decodeRollupTotalValue(v)
		a := dst[name]
		if a == nil {
			a = &TopAgg{}
			if client {
				a.Client = name
			} else {
				a.Category = name
			}
			dst[name] = a
		}
		a.Down += total.DownloadBytes
		a.Up += total.UploadBytes
		a.DownP += total.DownloadPackets
		a.UpP += total.UploadPackets
		count++
	}
	return count
}

func aggregateFromRollup(path string, cutoff time.Time, clientFilter string, aggs map[string]*TopAgg) (int, error) {
	db, err := bolt.Open(path, 0444, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return 0, err
	}
	defer db.Close()
	cutoffMinute := cutoff.Unix() / 60
	count := 0
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(rollupBucket)
		if b == nil {
			return nil
		}
		start := []byte(fmt.Sprintf("%012d", cutoffMinute))
		c := b.Cursor()
		for k, v := c.Seek(start); k != nil; k, v = c.Next() {
			var row RollupRow
			if json.Unmarshal(v, &row) != nil {
				continue
			}
			if row.Minute < cutoffMinute {
				continue
			}
			if clientFilter != "" && row.Client != clientFilter {
				continue
			}
			key := row.Client + "\t" + row.Category + "\t" + row.Target + "\t" + row.Proto + "\t" + strconv.Itoa(int(row.Port))
			a := aggs[key]
			if a == nil {
				a = &TopAgg{Client: row.Client, Category: row.Category, Target: row.Target, Proto: row.Proto, Port: row.Port}
				aggs[key] = a
			}
			a.Down += row.DownloadBytes
			a.Up += row.UploadBytes
			a.DownP += row.DownloadPackets
			a.UpP += row.UploadPackets
			count++
		}
		return nil
	})
	return count, err
}

func NewStatsCollector(cfg Config, clientCount int) *StatsCollector {
	s := &StatsCollector{
		startedAt:  time.Now(),
		iface:      cfg.Iface,
		statsPath:  filepath.Join(cfg.LogDir, "stats.json"),
		configPath: cfg.WGConfigPath,
		flowPath:   filepath.Join(cfg.LogDir, "flows.jsonl"),
		dnsPath:    filepath.Join(cfg.LogDir, "dns.jsonl"),
		tlsPath:    filepath.Join(cfg.LogDir, "tls.jsonl"),
		rollupPath: cfg.RollupPath,
	}
	s.clientCount.Store(uint64(clientCount))
	return s
}

func (s *StatsCollector) SetConfigLoaded(mod time.Time) {
	s.configLastLoadedNS.Store(time.Now().UnixNano())
	s.configLastModNS.Store(mod.UnixNano())
}

func (s *StatsCollector) updateRates() {
	now := time.Now()
	packets := s.packetSeen.Load()
	bytesSeen := s.bytesSeen.Load()
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	if s.lastSampleAt.IsZero() {
		s.lastSampleAt = now
		s.lastSamplePackets = packets
		s.lastSampleBytes = bytesSeen
		return
	}
	seconds := now.Sub(s.lastSampleAt).Seconds()
	if seconds < 5 {
		return
	}
	s.packetRate = float64(packets-s.lastSamplePackets) / seconds
	s.bitRate = float64(bytesSeen-s.lastSampleBytes) * 8 / seconds
	s.lastSampleAt = now
	s.lastSamplePackets = packets
	s.lastSampleBytes = bytesSeen
}

func (s *StatsCollector) Snapshot() RuntimeStats {
	uptimeSeconds := time.Since(s.startedAt).Seconds()
	if uptimeSeconds <= 0 {
		uptimeSeconds = 1
	}
	s.rateMu.Lock()
	packetRate := s.packetRate
	bitRate := s.bitRate
	s.rateMu.Unlock()
	packetSeen := s.packetSeen.Load()
	bytesSeen := s.bytesSeen.Load()
	flowKeys := int(s.currentFlowKeys.Load())
	st := RuntimeStats{
		StartedAt:                  s.startedAt,
		UpdatedAt:                  time.Now(),
		Interface:                  s.iface,
		ClientCount:                int(s.clientCount.Load()),
		PacketSeen:                 packetSeen,
		PacketDecoded:              s.packetDecoded.Load(),
		PacketMatched:              s.packetMatched.Load(),
		BytesSeen:                  bytesSeen,
		PacketRatePerSecond:        packetRate,
		BitRatePerSecond:           bitRate,
		AveragePacketRatePerSecond: float64(packetSeen) / uptimeSeconds,
		AverageBitRatePerSecond:    float64(bytesSeen) * 8 / uptimeSeconds,
		FlowRecords:                s.flowRecords.Load(),
		DNSRecords:                 s.dnsRecords.Load(),
		TLSRecords:                 s.tlsRecords.Load(),
		KernelPacketSocketPackets:  s.kernelPackets.Load(),
		KernelPacketSocketDrops:    s.kernelDrops.Load(),
		LastKernelDropsDelta:       s.lastDropsDelta.Load(),
		LastFlushRecords:           s.lastFlushRecords.Load(),
		LastFlushAt:                time.Unix(0, s.lastFlushNS.Load()),
		CurrentFlowKeys:            flowKeys,
		FlowQueueKeys:              flowKeys,
		RollupPendingRecords:       s.rollupPending.Load(),
		ConfigPath:                 s.configPath,
		ConfigReloads:              s.configReloads.Load(),
		ConfigLastLoadedAt:         time.Unix(0, s.configLastLoadedNS.Load()),
		ConfigLastModTime:          time.Unix(0, s.configLastModNS.Load()),
		FlowsLogBytes:              fileSize(s.flowPath),
		DNSLogBytes:                fileSize(s.dnsPath),
		TLSLogBytes:                fileSize(s.tlsPath),
		RollupDBBytes:              fileSize(s.rollupPath),
	}
	return st
}

func (s *StatsCollector) Write() error {
	s.updateRates()
	raw, err := json.MarshalIndent(s.Snapshot(), "", "  ")
	if err != nil {
		return err
	}
	tmp := s.statsPath + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.statsPath)
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

type FileSig struct {
	ModTime time.Time
	Size    int64
}

func fileSig(path string) (FileSig, error) {
	st, err := os.Stat(path)
	if err != nil {
		return FileSig{}, err
	}
	return FileSig{ModTime: st.ModTime(), Size: st.Size()}, nil
}

func NewJSONLogger(path string) (*JSONLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &JSONLogger{f: f, enc: json.NewEncoder(f)}, nil
}

func (l *JSONLogger) Write(v any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enc.Encode(v)
}

func (l *JSONLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

func NewDomainCache() *DomainCache {
	return &DomainCache{byClientIP: map[string]domainEntry{}, byIP: map[string]domainEntry{}}
}

func (d *DomainCache) Put(clientIP, ip, domain string, ttl uint32) {
	if ip == "" || domain == "" {
		return
	}
	if ttl == 0 {
		ttl = 300
	}
	exp := time.Now().Add(time.Duration(ttl) * time.Second)
	ent := domainEntry{Domain: strings.TrimSuffix(domain, "."), Expires: exp}
	d.mu.Lock()
	d.byClientIP[clientIP+"|"+ip] = ent
	d.byIP[ip] = ent
	d.mu.Unlock()
}

func (d *DomainCache) Lookup(clientIP, ip string) string {
	now := time.Now()
	d.mu.RLock()
	if ent, ok := d.byClientIP[clientIP+"|"+ip]; ok && ent.Expires.After(now) {
		d.mu.RUnlock()
		return ent.Domain
	}
	if ent, ok := d.byIP[ip]; ok && ent.Expires.After(now) {
		d.mu.RUnlock()
		return ent.Domain
	}
	d.mu.RUnlock()
	return ""
}

func (c *ClientMap) Load(path string, cidrs []string) error {
	byIP := map[string]string{}
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	var currentName string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "### Client ") {
			currentName = strings.TrimSpace(strings.TrimPrefix(line, "### Client "))
			continue
		}
		if strings.HasPrefix(line, "AllowedIPs") && currentName != "" {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			for _, raw := range strings.Split(parts[1], ",") {
				raw = strings.TrimSpace(raw)
				ip, _, err := net.ParseCIDR(raw)
				if err == nil && ip != nil {
					byIP[ip.String()] = currentName
					continue
				}
				if ip := net.ParseIP(raw); ip != nil {
					byIP[ip.String()] = currentName
				}
			}
		}
	}
	var nets []*net.IPNet
	for _, raw := range cidrs {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return fmt.Errorf("parse vpn cidr %q: %w", raw, err)
		}
		nets = append(nets, n)
	}
	c.mu.Lock()
	c.byIP = byIP
	c.vpnNets = nets
	c.mu.Unlock()
	return nil
}

func (c *ClientMap) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.byIP)
}

func (c *ClientMap) Match(src, dst net.IP) (clientIP, clientName string, outbound bool, ok bool) {
	srcS, dstS := src.String(), dst.String()
	c.mu.RLock()
	defer c.mu.RUnlock()
	srcIn, dstIn := c.inVPNLocked(src), c.inVPNLocked(dst)
	if srcIn && !dstIn {
		return srcS, c.nameLocked(srcS), true, true
	}
	if dstIn && !srcIn {
		return dstS, c.nameLocked(dstS), false, true
	}
	return "", "", false, false
}

func (c *ClientMap) inVPNLocked(ip net.IP) bool {
	for _, n := range c.vpnNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *ClientMap) nameLocked(ip string) string {
	if n := c.byIP[ip]; n != "" {
		return n
	}
	return "unknown:" + ip
}

func parsePacket(b []byte) (packetInfo, bool) {
	if len(b) < 1 {
		return packetInfo{}, false
	}
	switch b[0] >> 4 {
	case 4:
		return parseIPv4(b)
	case 6:
		return parseIPv6(b)
	default:
		return packetInfo{}, false
	}
}

func parseIPv4(b []byte) (packetInfo, bool) {
	if len(b) < 20 {
		return packetInfo{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return packetInfo{}, false
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total <= 0 || total > len(b) {
		total = len(b)
	}
	proto := b[9]
	p := packetInfo{
		SrcIP:  append(net.IP(nil), b[12:16]...),
		DstIP:  append(net.IP(nil), b[16:20]...),
		Proto:  proto,
		Length: total,
	}
	payload := b[ihl:total]
	if !parsePorts(&p, payload) {
		return packetInfo{}, false
	}
	return p, true
}

func parseIPv6(b []byte) (packetInfo, bool) {
	if len(b) < 40 {
		return packetInfo{}, false
	}
	payloadLen := int(binary.BigEndian.Uint16(b[4:6]))
	end := 40 + payloadLen
	if end > len(b) {
		end = len(b)
	}
	next := b[6]
	off := 40
	for {
		switch next {
		case 0, 43, 60:
			if off+2 > end {
				return packetInfo{}, false
			}
			next = b[off]
			off += (int(b[off+1]) + 1) * 8
		case 44:
			if off+8 > end {
				return packetInfo{}, false
			}
			next = b[off]
			off += 8
		default:
			goto done
		}
		if off > end {
			return packetInfo{}, false
		}
	}
done:
	p := packetInfo{
		SrcIP:  append(net.IP(nil), b[8:24]...),
		DstIP:  append(net.IP(nil), b[24:40]...),
		Proto:  next,
		Length: end,
	}
	if !parsePorts(&p, b[off:end]) {
		return packetInfo{}, false
	}
	return p, true
}

func parsePorts(p *packetInfo, payload []byte) bool {
	switch p.Proto {
	case 6:
		if len(payload) < 20 {
			return false
		}
		p.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		p.DstPort = binary.BigEndian.Uint16(payload[2:4])
		off := int(payload[12]>>4) * 4
		if off < 20 || off > len(payload) {
			return false
		}
		p.TransportPayload = payload[off:]
		return true
	case 17:
		if len(payload) < 8 {
			return false
		}
		p.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		p.DstPort = binary.BigEndian.Uint16(payload[2:4])
		p.TransportPayload = payload[8:]
		return true
	default:
		return false
	}
}

func parseDNSPacket(ts time.Time, iface, client, clientIP, serverIP, proto string, outbound bool, pkt packetInfo) (*DNSRecord, []DNSAnswer) {
	msg := pkt.TransportPayload
	if proto == "tcp" {
		if len(msg) < 2 {
			return nil, nil
		}
		l := int(binary.BigEndian.Uint16(msg[:2]))
		if l <= 0 || l > len(msg)-2 {
			return nil, nil
		}
		msg = msg[2 : 2+l]
	}
	parsed, ok := parseDNSMessage(msg)
	if !ok || parsed.Query == "" {
		return nil, nil
	}
	rec := &DNSRecord{
		TS: ts, Interface: iface, Client: client, ClientIP: clientIP,
		ServerIP: serverIP, Proto: proto, Query: parsed.Query, QType: parsed.QType,
		RCode: parsed.RCode, Response: parsed.Response, Answers: parsed.Answers,
	}
	return rec, parsed.Answers
}

type dnsParsed struct {
	Query    string
	QType    string
	RCode    int
	Response bool
	Answers  []DNSAnswer
}

func parseDNSMessage(msg []byte) (dnsParsed, bool) {
	if len(msg) < 12 {
		return dnsParsed{}, false
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	var qname string
	var qtype uint16
	for i := 0; i < qd; i++ {
		name, next, ok := parseDNSName(msg, off, 0)
		if !ok || next+4 > len(msg) {
			return dnsParsed{}, false
		}
		qname = name
		qtype = binary.BigEndian.Uint16(msg[next : next+2])
		off = next + 4
	}
	var answers []DNSAnswer
	for i := 0; i < an && off < len(msg); i++ {
		_, next, ok := parseDNSName(msg, off, 0)
		if !ok || next+10 > len(msg) {
			return dnsParsed{}, false
		}
		typ := binary.BigEndian.Uint16(msg[next : next+2])
		ttl := binary.BigEndian.Uint32(msg[next+4 : next+8])
		rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rdataOff := next + 10
		if rdataOff+rdLen > len(msg) {
			return dnsParsed{}, false
		}
		if ans, ok := parseDNSAnswer(msg, typ, ttl, rdataOff, rdLen); ok {
			answers = append(answers, ans)
		}
		off = rdataOff + rdLen
	}
	return dnsParsed{
		Query:    strings.TrimSuffix(qname, "."),
		QType:    dnsType(qtype),
		RCode:    int(flags & 0x000f),
		Response: flags&0x8000 != 0,
		Answers:  answers,
	}, true
}

func parseDNSAnswer(msg []byte, typ uint16, ttl uint32, off, ln int) (DNSAnswer, bool) {
	switch typ {
	case 1:
		if ln == 4 {
			return DNSAnswer{Type: "A", Value: net.IP(msg[off : off+4]).String(), TTL: ttl}, true
		}
	case 28:
		if ln == 16 {
			return DNSAnswer{Type: "AAAA", Value: net.IP(msg[off : off+16]).String(), TTL: ttl}, true
		}
	case 5:
		name, _, ok := parseDNSName(msg, off, 0)
		if ok {
			return DNSAnswer{Type: "CNAME", Value: strings.TrimSuffix(name, "."), TTL: ttl}, true
		}
	}
	return DNSAnswer{}, false
}

func parseDNSName(msg []byte, off int, depth int) (string, int, bool) {
	if depth > 12 {
		return "", 0, false
	}
	var labels []string
	next := off
	for {
		if off >= len(msg) {
			return "", 0, false
		}
		l := int(msg[off])
		if l == 0 {
			off++
			next = off
			break
		}
		if l&0xc0 == 0xc0 {
			if off+1 >= len(msg) {
				return "", 0, false
			}
			pointerNext := off + 2
			ptr := ((l & 0x3f) << 8) | int(msg[off+1])
			name, _, ok := parseDNSName(msg, ptr, depth+1)
			if !ok {
				return "", 0, false
			}
			if name != "" {
				labels = append(labels, strings.Split(name, ".")...)
			}
			off += 2
			next = pointerNext
			break
		}
		off++
		if off+l > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}
	return strings.Join(labels, "."), next, true
}

func parseTLSSNI(payload []byte) string {
	if len(payload) < 9 || payload[0] != 22 {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if recLen <= 0 || 5+recLen > len(payload) {
		return ""
	}
	hs := payload[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 1 {
		return ""
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if hsLen <= 0 || 4+hsLen > len(hs) {
		return ""
	}
	body := hs[4 : 4+hsLen]
	off := 0
	if len(body) < 2+32+1 {
		return ""
	}
	off += 2 + 32
	sidLen := int(body[off])
	off++
	if off+sidLen+2 > len(body) {
		return ""
	}
	off += sidLen
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+csLen+1 > len(body) {
		return ""
	}
	off += csLen
	compLen := int(body[off])
	off++
	if off+compLen+2 > len(body) {
		return ""
	}
	off += compLen
	extLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+extLen > len(body) {
		return ""
	}
	end := off + extLen
	for off+4 <= end {
		typ := binary.BigEndian.Uint16(body[off : off+2])
		ln := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+ln > end {
			return ""
		}
		ext := body[off : off+ln]
		off += ln
		if typ != 0 || len(ext) < 5 {
			continue
		}
		listLen := int(binary.BigEndian.Uint16(ext[0:2]))
		if listLen+2 > len(ext) {
			continue
		}
		pos := 2
		for pos+3 <= 2+listLen {
			nameType := ext[pos]
			nameLen := int(binary.BigEndian.Uint16(ext[pos+1 : pos+3]))
			pos += 3
			if pos+nameLen > len(ext) {
				return ""
			}
			if nameType == 0 {
				name := strings.ToLower(string(ext[pos : pos+nameLen]))
				if validHostname(name) {
					return name
				}
			}
			pos += nameLen
		}
	}
	return ""
}

func validHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, " \t\r\n/") {
		return false
	}
	return strings.Contains(s, ".")
}

func protoName(p uint8) string {
	if p == 6 {
		return "tcp"
	}
	if p == 17 {
		return "udp"
	}
	return strconv.Itoa(int(p))
}

func dnsType(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 28:
		return "AAAA"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	default:
		return strconv.Itoa(int(t))
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func readJSONLines(path string, fn func(FlowRecord)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var rec FlowRecord
			if json.Unmarshal(line, &rec) == nil {
				fn(rec)
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func humanBytes(v uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	f := float64(v)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.2f%s", f, units[i])
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
