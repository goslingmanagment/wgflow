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

// maxFlowKeysPerFlush caps the per-interval flows map; overflow traffic is
// aggregated under overflowRemoteIP with port 0 per client so byte counts
// survive even a port scan that would otherwise mint millions of keys.
const maxFlowKeysPerFlush = 200_000

// overflowRemoteIP is the synthetic remote for flows folded by the cap.
const overflowRemoteIP = "other"

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
	retentionStr := fs.String("rollup-retention", "0", "delete rollup minute buckets older than this, e.g. 90d (0 = keep forever)")
	var cidrList multiFlag
	cidrList = append(cidrList, "10.66.66.0/24", "fd42:42:42::/64")
	fs.Var(&cidrList, "vpn-cidr", "VPN client CIDR; can be repeated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg.VPNCIDRs = cidrList
	retention, err := parseRetention(*retentionStr)
	if err != nil {
		return fmt.Errorf("--rollup-retention: %w", err)
	}
	cfg.RollupRetention = retention

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
	stats.SetConfigLoaded(configSig.ModTime())
	defer stats.Write()

	fd, err := openPacketSocket(cfg.Iface)
	if err != nil {
		return err
	}
	// The capture goroutine blocks in Recvfrom with no way to interrupt it
	// directly. Shutdown sets the flag and closes the fd; the goroutine treats
	// any recv error while the flag is set as the exit signal, so it never
	// spins on a closed (or worse, reused) descriptor.
	var captureStopped atomic.Bool
	var closeCaptureOnce sync.Once
	closeCapture := func() {
		captureStopped.Store(true)
		closeCaptureOnce.Do(func() { syscall.Close(fd) })
	}
	defer closeCapture()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	cache := NewDomainCache()
	tlsAsm := newTLSReassembler()
	quicAsm := newQUICReassembler()
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
	var pendingRollup []FlowRecord

	// Prune runs in its own goroutine: opening bbolt blocks on the file lock,
	// and stalling the main select loop would delay flushes and even SIGTERM
	// handling. One prune at a time; bbolt's flock serializes it against the
	// flush-path openings, which already retry via pendingRollup.
	var pruneRunning atomic.Bool
	runPrune := func() {
		if cfg.RollupRetention <= 0 {
			return
		}
		if !pruneRunning.CompareAndSwap(false, true) {
			return
		}
		go func() {
			defer pruneRunning.Store(false)
			if n, err := pruneRollup(cfg.RollupPath, time.Now().Add(-cfg.RollupRetention)); err != nil {
				log.Printf("rollup prune failed: %v", err)
			} else if n > 0 {
				log.Printf("rollup prune: deleted %d keys older than %s", n, cfg.RollupRetention)
			}
		}()
	}
	runPrune()

	log.Printf("wgflow capture started iface=%s log_dir=%s rollup=%s flush=%s clients=%d", cfg.Iface, cfg.LogDir, cfg.RollupPath, cfg.FlushInterval, clients.Count())

	go func() {
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
			if st == nil && len(flows) >= maxFlowKeysPerFlush {
				// A port scan can mint millions of distinct keys within one
				// flush interval. Past the cap, fold new flows into a
				// per-client overflow bucket so the bytes are still counted.
				key = FlowKey{ClientIP: clientIP, RemoteIP: overflowRemoteIP, Proto: proto}
				st = flows[key]
			}
			if st == nil {
				st = &FlowStats{
					Client: clientName, ClientIP: clientIP, RemoteIP: key.RemoteIP,
					Proto: proto, RemotePort: key.RemotePort,
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
			if outbound && pkt.Proto == 6 && pkt.DstPort == 443 && len(pkt.TransportPayload) > 0 {
				key := tcpFlowKey{clientIP: clientIP, remoteIP: remoteIP, clientPort: pkt.SrcPort, remotePort: pkt.DstPort}
				if sni, _ := tlsAsm.Feed(key, pkt.TCPSeq, pkt.TransportPayload, time.Now()); sni != "" {
					cache.Put(clientIP, remoteIP, sni, 3600)
					_ = tlsLog.Write(TLSRecord{
						TS: time.Now(), Interface: cfg.Iface, Client: clientName,
						ClientIP: clientIP, RemoteIP: remoteIP, RemotePort: pkt.DstPort,
						ServerName: sni, Protocol: "tls",
					})
					stats.tlsRecords.Add(1)
				}
			}
			if outbound && pkt.Proto == 17 && pkt.DstPort == 443 {
				if sni, _ := parseQUICSNIAsm(pkt.TransportPayload, quicAsm, time.Now()); sni != "" {
					cache.Put(clientIP, remoteIP, sni, 3600)
					_ = tlsLog.Write(TLSRecord{
						TS: time.Now(), Interface: cfg.Iface, Client: clientName,
						ClientIP: clientIP, RemoteIP: remoteIP, RemotePort: pkt.DstPort,
						ServerName: sni, Protocol: "quic",
					})
					stats.tlsRecords.Add(1)
				}
			}
		}
	}()

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
	}

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
					stats.SetConfigLoaded(configSig.ModTime())
					log.Printf("reloaded %s clients=%d", cfg.WGConfigPath, clients.Count())
				}
				continue
			}
			log.Printf("stopping on %s", sig)
			// Stop capture first so the final flush sees a stable flows map,
			// then write out everything accumulated since the last tick —
			// otherwise up to a full flush interval of traffic is lost.
			closeCapture()
			flushFlows(time.Now())
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
				stats.SetConfigLoaded(configSig.ModTime())
				log.Printf("config changed; reloaded %s clients=%d", cfg.WGConfigPath, clients.Count())
			}
		case now := <-flushTicker.C:
			flushFlows(now)
		case <-statsTicker.C:
			flowMu.Lock()
			stats.currentFlowKeys.Store(uint64(len(flows)))
			flowMu.Unlock()
			tlsAsm.Prune(time.Now())
			quicAsm.Prune(time.Now())
			_ = stats.Write()
		case <-pruneTicker.C:
			runPrune()
		}
	}
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
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
