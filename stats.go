package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

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
	LogWriteErrors             uint64    `json:"log_write_errors"`
	KernelPacketSocketPackets  uint64    `json:"kernel_packet_socket_packets"`
	KernelPacketSocketDrops    uint64    `json:"kernel_packet_socket_drops"`
	LastKernelDropsDelta       uint64    `json:"last_kernel_drops_delta"`
	LastFlushRecords           uint64    `json:"last_flush_records"`
	LastFlushAt                time.Time `json:"last_flush_at"`
	CurrentFlowKeys            int       `json:"current_flow_keys"`
	FlowQueueKeys              int       `json:"flow_queue_keys"`
	RollupPendingRecords       uint64    `json:"rollup_pending_records"`
	RollupDroppedRecords       uint64    `json:"rollup_dropped_records"`
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
	rollupDropped      atomic.Uint64
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
		LogWriteErrors:             logWriteErrors.Load(),
		KernelPacketSocketPackets:  s.kernelPackets.Load(),
		KernelPacketSocketDrops:    s.kernelDrops.Load(),
		LastKernelDropsDelta:       s.lastDropsDelta.Load(),
		LastFlushRecords:           s.lastFlushRecords.Load(),
		LastFlushAt:                time.Unix(0, s.lastFlushNS.Load()),
		CurrentFlowKeys:            flowKeys,
		FlowQueueKeys:              flowKeys,
		RollupPendingRecords:       s.rollupPending.Load(),
		RollupDroppedRecords:       s.rollupDropped.Load(),
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

// FileSig identifies a config file version. ModTime is stored as UnixNano so
// the != comparison in the reload loop is exact: comparing time.Time structs
// with != is fragile (wall/monotonic clock and location are part of the value).
type FileSig struct {
	ModTimeNS int64
	Size      int64
}

func (s FileSig) ModTime() time.Time {
	return time.Unix(0, s.ModTimeNS)
}

func fileSig(path string) (FileSig, error) {
	st, err := os.Stat(path)
	if err != nil {
		return FileSig{}, err
	}
	return FileSig{ModTimeNS: st.ModTime().UnixNano(), Size: st.Size()}, nil
}
