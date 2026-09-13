package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type ClientMap struct {
	mu      sync.RWMutex
	byIP    map[string]string
	vpnNets []*net.IPNet
}

// CaptureSourceSpec describes one plaintext WireGuard interface. NetNSPath is
// optional; when set, the packet socket is opened inside that network
// namespace and remains usable after the opening thread returns to the host
// namespace. This is how one wgflow process can capture a host wg0 and a
// Docker-contained wg0 while still owning the log files and rollup DB exactly
// once.
type CaptureSourceSpec struct {
	Name         string
	Iface        string
	WGConfigPath string
	VPNCIDRs     []string
	NetNSPath    string
}

type captureSource struct {
	spec      CaptureSourceSpec
	clients   *ClientMap
	configSig FileSig
	fd        int
	netNSInfo os.FileInfo
}

// maxFlowKeysPerFlush caps the per-interval flows map; overflow traffic is
// aggregated under overflowRemoteIP with port 0 per client so byte counts
// survive even a port scan that would otherwise mint millions of keys.
const maxFlowKeysPerFlush = 200_000

// overflowRemoteIP is the synthetic remote for flows folded by the cap.
const overflowRemoteIP = "other"

type FlowKey struct {
	Interface  string
	ClientIP   string
	RemoteIP   string
	Proto      string
	RemotePort uint16
}

type FlowStats struct {
	Interface       string
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

type domainEntry struct {
	Domain  string
	Expires time.Time
}

// domainCacheMaxEntries bounds each DomainCache map. Entries are small, but a
// client replaying crafted DNS answers could otherwise grow the maps forever.
const domainCacheMaxEntries = 65536

type DomainCache struct {
	mu         sync.RWMutex
	byClientIP map[string]domainEntry
	byIP       map[string]domainEntry
	maxEntries int
}

type JSONLogger struct {
	mu           sync.Mutex
	enc          *json.Encoder
	f            *os.File
	path         string
	lastErrLogNS int64 // guarded by mu; rate-limits the error log line
}

// logWriteErrors counts failed JSONLogger writes across all log files. It is
// package-level because the loggers are created before the StatsCollector and
// the stats snapshot only needs the total.
var logWriteErrors atomic.Uint64

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfg := Config{}
	fs.StringVar(&cfg.Iface, "iface", "wg0", "WireGuard interface to capture")
	fs.StringVar(&cfg.WGConfigPath, "wg-config", "/etc/wireguard/wg0.conf", "WireGuard config path")
	fs.StringVar(&cfg.LogDir, "log-dir", "/var/log/wgflow", "log directory")
	fs.StringVar(&cfg.RollupPath, "rollup", "/var/lib/wgflow/rollup.db", "rollup DB path")
	fs.DurationVar(&cfg.FlushInterval, "flush", 30*time.Second, "flow flush interval")
	retentionStr := fs.String("rollup-retention", "0", "retain compact rollup summaries for this long, e.g. 31d (0 = keep forever)")
	detailRetentionStr := fs.String("rollup-detail-retention", "", "retain per-target rollup detail for this long, e.g. 7d (default: same as --rollup-retention)")
	var cidrList multiFlag
	cidrList = append(cidrList, "10.66.66.0/24", "fd42:42:42::/64")
	fs.Var(&cidrList, "vpn-cidr", "VPN client CIDR; can be repeated")
	var extraSourceList multiFlag
	fs.Var(&extraSourceList, "extra-source", "additional capture source: name=NAME,iface=IFACE,wg-config=PATH,cidrs=CIDR|CIDR,netns=PATH")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg.VPNCIDRs = cidrList
	retention, err := parseRetention(*retentionStr)
	if err != nil {
		return fmt.Errorf("--rollup-retention: %w", err)
	}
	if retention < 0 {
		return fmt.Errorf("--rollup-retention must not be negative")
	}
	cfg.RollupRetention = retention
	if strings.TrimSpace(*detailRetentionStr) == "" {
		// Preserve the original one-tier behavior unless the operator explicitly
		// opts into a shorter per-target detail window.
		cfg.RollupDetailRetention = retention
	} else {
		detailRetention, err := parseRetention(*detailRetentionStr)
		if err != nil {
			return fmt.Errorf("--rollup-detail-retention: %w", err)
		}
		if detailRetention < 0 {
			return fmt.Errorf("--rollup-detail-retention must not be negative")
		}
		cfg.RollupDetailRetention = detailRetention
	}
	if cfg.RollupRetention > 0 && (cfg.RollupDetailRetention == 0 || cfg.RollupDetailRetention > cfg.RollupRetention) {
		return fmt.Errorf("--rollup-detail-retention must be positive and no longer than --rollup-retention")
	}

	sourceSpecs := []CaptureSourceSpec{{
		Name: cfg.Iface, Iface: cfg.Iface, WGConfigPath: cfg.WGConfigPath,
		VPNCIDRs: append([]string(nil), cfg.VPNCIDRs...),
	}}
	sourceNames := map[string]bool{cfg.Iface: true}
	for _, raw := range extraSourceList {
		spec, err := parseExtraCaptureSource(raw)
		if err != nil {
			return fmt.Errorf("--extra-source %q: %w", raw, err)
		}
		if sourceNames[spec.Name] {
			return fmt.Errorf("--extra-source %q: duplicate source name %q", raw, spec.Name)
		}
		sourceNames[spec.Name] = true
		sourceSpecs = append(sourceSpecs, spec)
	}

	if err := os.MkdirAll(cfg.LogDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.RollupPath), 0755); err != nil {
		return err
	}

	sources := make([]*captureSource, 0, len(sourceSpecs))
	for _, spec := range sourceSpecs {
		clients := &ClientMap{}
		if err := clients.Load(spec.WGConfigPath, spec.VPNCIDRs); err != nil {
			return fmt.Errorf("capture source %s config: %w", spec.Name, err)
		}
		sig, err := fileSig(spec.WGConfigPath)
		if err != nil {
			return fmt.Errorf("capture source %s config stat: %w", spec.Name, err)
		}
		sources = append(sources, &captureSource{spec: spec, clients: clients, configSig: sig, fd: -1})
	}

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
	statsCfg := cfg
	statsCfg.Iface = captureSourceNames(sources)
	statsCfg.WGConfigPath = captureSourceConfigPaths(sources)
	stats := NewStatsCollector(statsCfg, captureClientCount(sources))
	stats.SetConfigLoaded(latestCaptureConfigMod(sources))
	defer stats.Write()

	for _, source := range sources {
		fd, err := openPacketSocketInNetNS(source.spec.Iface, source.spec.NetNSPath)
		if err != nil {
			for _, opened := range sources {
				if opened.fd >= 0 {
					_ = syscall.Close(opened.fd)
					opened.fd = -1
				}
			}
			return fmt.Errorf("open capture source %s (iface=%s netns=%s): %w", source.spec.Name, source.spec.Iface, source.spec.NetNSPath, err)
		}
		source.fd = fd
		if source.spec.NetNSPath != "" {
			info, err := os.Stat(source.spec.NetNSPath)
			if err != nil {
				for _, opened := range sources {
					if opened.fd >= 0 {
						_ = syscall.Close(opened.fd)
						opened.fd = -1
					}
				}
				return fmt.Errorf("stat capture source %s netns: %w", source.spec.Name, err)
			}
			source.netNSInfo = info
		}
	}
	// The capture goroutine blocks in Recvfrom with no way to interrupt it
	// directly. Shutdown sets the flag and closes the fds; the goroutines treat
	// any recv error while the flag is set as the exit signal, so it never
	// spins on a closed (or worse, reused) descriptor.
	var captureStopped atomic.Bool
	var closeCaptureOnce sync.Once
	captureStopCh := make(chan struct{})
	closeCapture := func() {
		captureStopped.Store(true)
		closeCaptureOnce.Do(func() {
			close(captureStopCh)
			for _, source := range sources {
				if source.fd >= 0 {
					_ = syscall.Close(source.fd)
					source.fd = -1
				}
			}
		})
	}
	defer closeCapture()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	cache := NewDomainCache()
	domainCachePath := filepath.Join(cfg.LogDir, "domains.cache.json")
	// Restore IP->domain mappings from the previous run: connections opened
	// before the restart never resend a ClientHello or DNS query, so without
	// this their flows would stay nameless. Failure is never fatal — a
	// missing file is simply the first start.
	if n, err := cache.LoadFrom(domainCachePath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("domain cache load failed: %v", err)
		}
	} else {
		log.Printf("domain cache restored entries=%d from %s", n, domainCachePath)
	}
	saveDomainCache := func() {
		if err := cache.SaveTo(domainCachePath); err != nil {
			log.Printf("domain cache save failed: %v", err)
		}
	}
	tlsAsm := newTLSReassembler()
	quicAsm := newQUICReassembler()
	httpDedup := newHTTPHostDeduper()
	flows := make(map[FlowKey]*FlowStats)
	var flowMu sync.Mutex
	intervalStart := time.Now()
	flushTicker := time.NewTicker(cfg.FlushInterval)
	defer flushTicker.Stop()
	reloadTicker := time.NewTicker(60 * time.Second)
	defer reloadTicker.Stop()
	statsTicker := time.NewTicker(30 * time.Second)
	defer statsTicker.Stop()
	pruneTicker := time.NewTicker(24 * time.Hour)
	defer pruneTicker.Stop()
	domainSaveTicker := time.NewTicker(5 * time.Minute)
	defer domainSaveTicker.Stop()
	var pendingRollup []FlowRecord

	// Prune runs in its own goroutine: opening bbolt blocks on the file lock,
	// and stalling the main select loop would delay flushes and even SIGTERM
	// handling. One prune at a time; bbolt's flock serializes it against the
	// flush-path openings, which already retry via pendingRollup.
	var pruneRunning atomic.Bool
	runPrune := func() {
		if cfg.RollupRetention <= 0 && cfg.RollupDetailRetention <= 0 {
			return
		}
		if !pruneRunning.CompareAndSwap(false, true) {
			return
		}
		go func() {
			defer pruneRunning.Store(false)
			now := time.Now()
			var summaryCutoff, detailCutoff time.Time
			if cfg.RollupRetention > 0 {
				summaryCutoff = now.Add(-cfg.RollupRetention)
			}
			if cfg.RollupDetailRetention > 0 {
				detailCutoff = now.Add(-cfg.RollupDetailRetention)
			}
			detailDeleted, summaryDeleted, err := pruneRollupTiers(cfg.RollupPath, summaryCutoff, detailCutoff)
			if err != nil {
				log.Printf("rollup prune failed: %v", err)
			} else if detailDeleted+summaryDeleted > 0 {
				log.Printf("rollup prune: deleted detail=%d summary=%d (detail retention=%s, summary retention=%s)",
					detailDeleted, summaryDeleted, cfg.RollupDetailRetention, cfg.RollupRetention)
			}
		}()
	}
	runPrune()

	log.Printf("wgflow capture started sources=%s log_dir=%s rollup=%s flush=%s clients=%d", captureSourceNames(sources), cfg.LogDir, cfg.RollupPath, cfg.FlushInterval, captureClientCount(sources))

	handlePacket := func(source *captureSource, raw []byte) {
		stats.packetSeen.Add(1)
		stats.bytesSeen.Add(uint64(len(raw)))
		pkt, ok := parsePacket(raw)
		if !ok {
			return
		}
		stats.packetDecoded.Add(1)
		if pkt.Proto != 6 && pkt.Proto != 17 {
			return
		}
		clientIP, clientName, outbound, ok := source.clients.Match(pkt.SrcIP, pkt.DstIP)
		if !ok {
			return
		}
		stats.packetMatched.Add(1)
		proto := protoName(pkt.Proto)
		remoteIP := pkt.DstIP.String()
		remotePort := pkt.DstPort
		if !outbound {
			remoteIP = pkt.SrcIP.String()
			remotePort = pkt.SrcPort
		}
		key := FlowKey{Interface: source.spec.Name, ClientIP: clientIP, RemoteIP: remoteIP, Proto: proto, RemotePort: remotePort}
		flowMu.Lock()
		st := flows[key]
		if st == nil && len(flows) >= maxFlowKeysPerFlush {
			// A port scan can mint millions of distinct keys within one
			// flush interval. Past the cap, fold new flows into a
			// per-client overflow bucket so the bytes are still counted.
			key = FlowKey{Interface: source.spec.Name, ClientIP: clientIP, RemoteIP: overflowRemoteIP, Proto: proto}
			st = flows[key]
		}
		if st == nil {
			st = &FlowStats{
				Interface: source.spec.Name, Client: clientName, ClientIP: clientIP,
				RemoteIP: key.RemoteIP, Proto: proto, RemotePort: key.RemotePort,
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

		now := time.Now()
		if pkt.SrcPort == 53 || pkt.DstPort == 53 {
			if rec, answers := parseDNSPacket(now, source.spec.Name, clientName, clientIP, remoteIP, proto, outbound, pkt); rec != nil {
				_ = dnsLog.Write(rec)
				stats.dnsRecords.Add(1)
				for _, ans := range answers {
					switch ans.Type {
					case "A", "AAAA":
						cache.Put(clientIP, ans.Value, rec.Query, ans.TTL)
					case "HTTPS", "SVCB":
						owner := ans.Name
						if owner == "" {
							owner = rec.Query
						}
						for _, hintIP := range ans.Hints {
							cache.Put(clientIP, hintIP, owner, ans.TTL)
							stats.httpsRRHints.Add(1)
						}
					}
				}
			}
		}
		if outbound && pkt.Proto == 6 && pkt.DstPort == 443 && len(pkt.TransportPayload) > 0 {
			key := tcpFlowKey{source: source.spec.Name, clientIP: clientIP, remoteIP: remoteIP, clientPort: pkt.SrcPort, remotePort: pkt.DstPort}
			if sni, reassembled := tlsAsm.Feed(key, pkt.TCPSeq, pkt.TransportPayload, now); sni != "" {
				if reassembled {
					stats.tlsReassembled.Add(1)
				}
				cache.Put(clientIP, remoteIP, sni, 3600)
				_ = tlsLog.Write(TLSRecord{
					TS: now, Interface: source.spec.Name, Client: clientName,
					ClientIP: clientIP, RemoteIP: remoteIP, RemotePort: pkt.DstPort,
					ServerName: sni, Protocol: "tls",
				})
				stats.tlsRecords.Add(1)
			}
		}
		if outbound && pkt.Proto == 6 && pkt.DstPort == 80 && len(pkt.TransportPayload) > 0 {
			if host := parseHTTPHost(pkt.TransportPayload); host != "" {
				key := tcpFlowKey{source: source.spec.Name, clientIP: clientIP, remoteIP: remoteIP, clientPort: pkt.SrcPort, remotePort: pkt.DstPort}
				// One record per flow per minute: keep-alive connections
				// repeat Host on every request, unlike a TLS ClientHello.
				if httpDedup.Allow(key, now) {
					cache.Put(clientIP, remoteIP, host, 3600)
					_ = tlsLog.Write(TLSRecord{
						TS: now, Interface: source.spec.Name, Client: clientName,
						ClientIP: clientIP, RemoteIP: remoteIP, RemotePort: pkt.DstPort,
						ServerName: host, Protocol: "http",
					})
					stats.tlsRecords.Add(1)
					stats.httpHostRecords.Add(1)
				}
			}
		}
		if outbound && pkt.Proto == 17 && pkt.DstPort == 443 {
			if sni, reassembled := parseQUICSNIAsm(pkt.TransportPayload, quicAsm, now); sni != "" {
				if reassembled {
					stats.quicReassembled.Add(1)
				}
				cache.Put(clientIP, remoteIP, sni, 3600)
				_ = tlsLog.Write(TLSRecord{
					TS: now, Interface: source.spec.Name, Client: clientName,
					ClientIP: clientIP, RemoteIP: remoteIP, RemotePort: pkt.DstPort,
					ServerName: sni, Protocol: "quic",
				})
				stats.tlsRecords.Add(1)
			}
		}
	}

	captureErrCh := make(chan error, len(sources)*2)
	reportCaptureError := func(err error) {
		select {
		case captureErrCh <- err:
		default:
		}
	}
	var captureWG sync.WaitGroup
	for _, source := range sources {
		source := source
		captureWG.Add(1)
		go func() {
			defer captureWG.Done()
			fd := source.fd
			buf := make([]byte, 65535)
			for {
				n, _, err := syscall.Recvfrom(fd, buf, 0)
				if err != nil {
					if captureStopped.Load() {
						return
					}
					if errors.Is(err, syscall.EINTR) {
						continue
					}
					if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
						continue
					}
					reportCaptureError(fmt.Errorf("capture source %s recvfrom: %w", source.spec.Name, err))
					return
				}
				if n > 0 {
					handlePacket(source, buf[:n])
				}
			}
		}()
		if source.netNSInfo != nil {
			captureWG.Add(1)
			go func() {
				defer captureWG.Done()
				ticker := time.NewTicker(10 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-captureStopCh:
						return
					case <-ticker.C:
						info, err := os.Stat(source.spec.NetNSPath)
						if err != nil {
							reportCaptureError(fmt.Errorf("capture source %s netns disappeared: %w", source.spec.Name, err))
							return
						}
						if !os.SameFile(source.netNSInfo, info) {
							reportCaptureError(fmt.Errorf("capture source %s netns changed", source.spec.Name))
							return
						}
					}
				}
			}()
		}
	}

	flushFlows := func(now time.Time) {
		flowMu.Lock()
		batch := flows
		flows = make(map[FlowKey]*FlowStats)
		start := intervalStart
		intervalStart = now
		flowMu.Unlock()
		records := make([]FlowRecord, 0, len(batch))
		for _, st := range batch {
			rec := FlowRecord{
				TSStart: start, TSEnd: now, Interface: st.Interface,
				Client: st.Client, ClientIP: st.ClientIP, RemoteIP: st.RemoteIP,
				RemotePort: st.RemotePort, Proto: st.Proto,
				Domain:            cache.Lookup(st.ClientIP, st.RemoteIP),
				ClientUploadBytes: st.UploadBytes, ClientDownloadBytes: st.DownloadBytes,
				ClientUploadPackets: st.UploadPackets, ClientDownloadPackets: st.DownloadPackets,
			}
			_ = flowLog.Write(rec)
			records = append(records, rec)
		}
		cache.PruneExpired(now)
		if len(records) > 0 {
			pendingRollup = append(pendingRollup, records...)
		}
		// If bbolt is permanently unavailable the retry queue must not grow
		// without bound; drop the oldest records and account for the loss.
		var dropped int
		pendingRollup, dropped = capPendingRollup(pendingRollup, maxPendingRollupRecords)
		if dropped > 0 {
			stats.rollupDropped.Add(uint64(dropped))
			log.Printf("rollup pending queue full; dropped %d oldest records", dropped)
		}
		if len(pendingRollup) > 0 {
			if err := rollup.Add(pendingRollup); err != nil {
				log.Printf("rollup write failed: %v pending_records=%d", err, len(pendingRollup))
			} else {
				pendingRollup = nil
			}
		}
		stats.rollupPending.Store(uint64(len(pendingRollup)))
		stats.tlsAsmFlows.Store(uint64(tlsAsm.Size()))
		stats.quicAsmDCIDs.Store(uint64(quicAsm.Size()))
		stats.flowRecords.Add(uint64(len(records)))
		stats.lastFlushRecords.Store(uint64(len(records)))
		stats.currentFlowKeys.Store(0)
		stats.lastFlushNS.Store(now.UnixNano())
		var socketPackets, socketDrops uint64
		for _, source := range sources {
			if source.fd < 0 {
				continue
			}
			if pkts, drops, err := packetSocketStats(source.fd); err == nil {
				socketPackets += pkts
				socketDrops += drops
			}
		}
		if socketPackets > 0 || socketDrops > 0 {
			stats.kernelPackets.Add(socketPackets)
			stats.kernelDrops.Add(socketDrops)
			stats.lastDropsDelta.Store(socketDrops)
		}
		_ = stats.Write()
	}
	reloadSources := func(force bool) {
		reloaded := false
		for _, source := range sources {
			nextSig, err := fileSig(source.spec.WGConfigPath)
			if err != nil {
				log.Printf("capture source %s config stat failed: %v", source.spec.Name, err)
				continue
			}
			if !force && nextSig == source.configSig {
				continue
			}
			if err := source.clients.Load(source.spec.WGConfigPath, source.spec.VPNCIDRs); err != nil {
				log.Printf("capture source %s config reload failed: %v", source.spec.Name, err)
				continue
			}
			source.configSig = nextSig
			reloaded = true
			log.Printf("capture source %s config reloaded path=%s clients=%d", source.spec.Name, source.spec.WGConfigPath, source.clients.Count())
		}
		if reloaded {
			stats.clientCount.Store(uint64(captureClientCount(sources)))
			stats.configReloads.Add(1)
			stats.SetConfigLoaded(latestCaptureConfigMod(sources))
		}
	}
	shutdown := func() {
		// Stop every capture loop and wait for it to release the shared flow map
		// before the final flush. This preserves the last partial interval without
		// racing an in-flight packet from another source.
		closeCapture()
		captureWG.Wait()
		flushFlows(time.Now())
		saveDomainCache()
	}

	for {
		select {
		case sig := <-sigCh:
			if sig == syscall.SIGHUP {
				reloadSources(true)
				continue
			}
			log.Printf("stopping on %s", sig)
			shutdown()
			return nil
		case err := <-captureErrCh:
			log.Printf("capture failed: %v", err)
			shutdown()
			return err
		case <-reloadTicker.C:
			reloadSources(false)
		case now := <-flushTicker.C:
			flushFlows(now)
		case <-statsTicker.C:
			flowMu.Lock()
			stats.currentFlowKeys.Store(uint64(len(flows)))
			flowMu.Unlock()
			tlsAsm.Prune(time.Now())
			quicAsm.Prune(time.Now())
			httpDedup.Prune(time.Now())
			stats.tlsAsmFlows.Store(uint64(tlsAsm.Size()))
			stats.quicAsmDCIDs.Store(uint64(quicAsm.Size()))
			_ = stats.Write()
		case <-pruneTicker.C:
			runPrune()
		case <-domainSaveTicker.C:
			saveDomainCache()
		}
	}
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func parseExtraCaptureSource(raw string) (CaptureSourceSpec, error) {
	values := map[string]string{}
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		key, value, ok := strings.Cut(field, "=")
		if !ok || strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			return CaptureSourceSpec{}, fmt.Errorf("invalid field %q (want key=value)", field)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch key {
		case "name", "iface", "wg-config", "cidrs", "netns":
		default:
			return CaptureSourceSpec{}, fmt.Errorf("unknown field %q", key)
		}
		if _, exists := values[key]; exists {
			return CaptureSourceSpec{}, fmt.Errorf("duplicate field %q", key)
		}
		values[key] = value
	}
	for _, required := range []string{"name", "iface", "wg-config", "cidrs"} {
		if values[required] == "" {
			return CaptureSourceSpec{}, fmt.Errorf("missing field %q", required)
		}
	}
	cidrs := strings.Split(values["cidrs"], "|")
	for i := range cidrs {
		cidrs[i] = strings.TrimSpace(cidrs[i])
		if cidrs[i] == "" {
			return CaptureSourceSpec{}, errors.New("cidrs contains an empty entry")
		}
		if _, _, err := net.ParseCIDR(cidrs[i]); err != nil {
			return CaptureSourceSpec{}, fmt.Errorf("parse cidr %q: %w", cidrs[i], err)
		}
	}
	return CaptureSourceSpec{
		Name:         values["name"],
		Iface:        values["iface"],
		WGConfigPath: values["wg-config"],
		VPNCIDRs:     cidrs,
		NetNSPath:    values["netns"],
	}, nil
}

func captureClientCount(sources []*captureSource) int {
	total := 0
	for _, source := range sources {
		total += source.clients.Count()
	}
	return total
}

func captureSourceNames(sources []*captureSource) string {
	names := make([]string, 0, len(sources))
	for _, source := range sources {
		names = append(names, source.spec.Name)
	}
	return strings.Join(names, ",")
}

func captureSourceConfigPaths(sources []*captureSource) string {
	paths := make([]string, 0, len(sources))
	for _, source := range sources {
		paths = append(paths, source.spec.WGConfigPath)
	}
	return strings.Join(paths, ",")
}

func latestCaptureConfigMod(sources []*captureSource) time.Time {
	var latest time.Time
	for _, source := range sources {
		if mod := source.configSig.ModTime(); mod.After(latest) {
			latest = mod
		}
	}
	return latest
}

func NewJSONLogger(path string) (*JSONLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &JSONLogger{f: f, enc: json.NewEncoder(f), path: path}, nil
}

func (l *JSONLogger) Write(v any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.enc.Encode(v)
	if err != nil {
		// Callers on the hot path ignore the return value, so account for the
		// failure here. Log at most once a minute per logger: a full disk
		// would otherwise flood the journal at packet rate.
		total := logWriteErrors.Add(1)
		if now := time.Now().UnixNano(); now-l.lastErrLogNS >= int64(time.Minute) {
			l.lastErrLogNS = now
			log.Printf("log write failed path=%s err=%v total_write_errors=%d", l.path, err, total)
		}
	}
	return err
}

func (l *JSONLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

func NewDomainCache() *DomainCache {
	return &DomainCache{
		byClientIP: map[string]domainEntry{},
		byIP:       map[string]domainEntry{},
		maxEntries: domainCacheMaxEntries,
	}
}

func (d *DomainCache) Put(clientIP, ip, domain string, ttl uint32) {
	if ip == "" || domain == "" {
		return
	}
	if ttl == 0 {
		ttl = 300
	}
	now := time.Now()
	ent := domainEntry{Domain: strings.TrimSuffix(domain, "."), Expires: now.Add(time.Duration(ttl) * time.Second)}
	d.mu.Lock()
	if len(d.byClientIP) >= d.maxEntries {
		evictDomainEntries(d.byClientIP, d.maxEntries, now)
	}
	if len(d.byIP) >= d.maxEntries {
		evictDomainEntries(d.byIP, d.maxEntries, now)
	}
	d.byClientIP[clientIP+"|"+ip] = ent
	d.byIP[ip] = ent
	d.mu.Unlock()
}

// evictDomainEntries makes room in a full map: expired entries go first, and
// if everything is still live it drops arbitrary entries (map iteration
// order) — losing a domain hint only degrades flow labels, never counting.
func evictDomainEntries(m map[string]domainEntry, max int, now time.Time) {
	for k, ent := range m {
		if !ent.Expires.After(now) {
			delete(m, k)
		}
	}
	for k := range m {
		if len(m) < max {
			break
		}
		delete(m, k)
	}
}

// Domain cache persistence. The cache used to die with the process, so after
// every restart all established connections (which never resend a
// ClientHello) went nameless until their next DNS lookup. A periodic snapshot
// survives restarts; losing one save interval costs only a few labels.

// domainCacheFileVersion guards the on-disk format; bump on breaking changes
// so an old binary never misreads a new file (and vice versa).
const domainCacheFileVersion = 1

type domainCacheFileEntry struct {
	Domain  string    `json:"domain"`
	Expires time.Time `json:"expires"`
}

type domainCacheFile struct {
	Version    int                             `json:"version"`
	SavedAt    time.Time                       `json:"saved_at"`
	ByClientIP map[string]domainCacheFileEntry `json:"by_client_ip"`
	ByIP       map[string]domainCacheFileEntry `json:"by_ip"`
}

// SaveTo atomically dumps all non-expired entries (tmp + rename, same
// protocol as stats.json) so a crash mid-write never corrupts the file.
func (d *DomainCache) SaveTo(path string) error {
	now := time.Now()
	dump := domainCacheFile{
		Version:    domainCacheFileVersion,
		SavedAt:    now,
		ByClientIP: map[string]domainCacheFileEntry{},
		ByIP:       map[string]domainCacheFileEntry{},
	}
	d.mu.RLock()
	for k, ent := range d.byClientIP {
		if ent.Expires.After(now) {
			dump.ByClientIP[k] = domainCacheFileEntry{Domain: ent.Domain, Expires: ent.Expires}
		}
	}
	for k, ent := range d.byIP {
		if ent.Expires.After(now) {
			dump.ByIP[k] = domainCacheFileEntry{Domain: ent.Domain, Expires: ent.Expires}
		}
	}
	d.mu.RUnlock()
	raw, err := json.Marshal(dump)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadFrom restores a snapshot, dropping entries that expired while the
// process was down and respecting the cache cap. It returns the number of
// entries restored; a missing file surfaces as os.ErrNotExist for the caller
// to treat as a normal first start.
func (d *DomainCache) LoadFrom(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var dump domainCacheFile
	if err := json.Unmarshal(raw, &dump); err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	if dump.Version != domainCacheFileVersion {
		return 0, fmt.Errorf("%s: unsupported version %d", path, dump.Version)
	}
	now := time.Now()
	loaded := 0
	d.mu.Lock()
	for k, ent := range dump.ByClientIP {
		if len(d.byClientIP) >= d.maxEntries {
			break
		}
		if ent.Domain != "" && ent.Expires.After(now) {
			d.byClientIP[k] = domainEntry{Domain: ent.Domain, Expires: ent.Expires}
			loaded++
		}
	}
	for k, ent := range dump.ByIP {
		if len(d.byIP) >= d.maxEntries {
			break
		}
		if ent.Domain != "" && ent.Expires.After(now) {
			d.byIP[k] = domainEntry{Domain: ent.Domain, Expires: ent.Expires}
			loaded++
		}
	}
	d.mu.Unlock()
	return loaded, nil
}

// PruneExpired drops entries past their TTL; called on every flow flush so an
// idle cache does not hold expired mappings for hours.
func (d *DomainCache) PruneExpired(now time.Time) {
	d.mu.Lock()
	for k, ent := range d.byClientIP {
		if !ent.Expires.After(now) {
			delete(d.byClientIP, k)
		}
	}
	for k, ent := range d.byIP {
		if !ent.Expires.After(now) {
			delete(d.byIP, k)
		}
	}
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
		if name := clientNameFromConfigComment(line); name != "" {
			currentName = name
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

// clientNameFromConfigComment understands both the wireguard-install style
// used by the host config and wg-easy's generated comments. wg-easy appends a
// numeric database id in parentheses; it is metadata, not part of the client
// name shown in the dashboard.
func clientNameFromConfigComment(line string) string {
	if strings.HasPrefix(line, "### Client ") {
		return strings.TrimSpace(strings.TrimPrefix(line, "### Client "))
	}
	if !strings.HasPrefix(line, "# Client:") {
		return ""
	}
	name := strings.TrimSpace(strings.TrimPrefix(line, "# Client:"))
	if i := strings.LastIndex(name, " ("); i > 0 && strings.HasSuffix(name, ")") {
		id := name[i+2 : len(name)-1]
		allDigits := id != ""
		for _, r := range id {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			name = strings.TrimSpace(name[:i])
		}
	}
	return name
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
