package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

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

// parseRetention accepts Go durations plus "d" (days) and "w" (weeks), so the
// retention flags can read naturally as "30d" / "12w".
func parseRetention(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	for suffix, unit := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if strings.HasSuffix(s, suffix) {
			n, err := strconv.ParseFloat(strings.TrimSuffix(s, suffix), 64)
			if err != nil {
				return 0, fmt.Errorf("invalid duration %q: %w", s, err)
			}
			return time.Duration(n * float64(unit)), nil
		}
	}
	return time.ParseDuration(s)
}

func rollupPrune(args []string) error {
	fs := flag.NewFlagSet("rollup-prune", flag.ExitOnError)
	rollupPath := fs.String("rollup", "/var/lib/wgflow/rollup.db", "rollup DB path")
	keepStr := fs.String("keep", "31d", "compact-summary retention window (e.g. 31d, 12w, 744h)")
	detailKeepStr := fs.String("detail-keep", "", "per-target detail retention window (default: same as --keep)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	keep, err := parseRetention(*keepStr)
	if err != nil {
		return err
	}
	if keep <= 0 {
		return fmt.Errorf("--keep must be positive")
	}
	detailKeep := keep
	if strings.TrimSpace(*detailKeepStr) != "" {
		detailKeep, err = parseRetention(*detailKeepStr)
		if err != nil {
			return fmt.Errorf("--detail-keep: %w", err)
		}
		if detailKeep <= 0 {
			return fmt.Errorf("--detail-keep must be positive")
		}
	}
	if detailKeep > keep {
		return fmt.Errorf("--detail-keep must not exceed --keep")
	}
	now := time.Now()
	summaryCutoff := now.Add(-keep)
	detailCutoff := now.Add(-detailKeep)
	detailDeleted, summaryDeleted, err := pruneRollupTiers(*rollupPath, summaryCutoff, detailCutoff)
	if err != nil {
		return err
	}
	fmt.Printf("pruned_detail_keys=%d pruned_summary_keys=%d rollup=%s detail_keep=%s summary_keep=%s detail_cutoff=%s summary_cutoff=%s\n",
		detailDeleted, summaryDeleted, *rollupPath, detailKeep, keep,
		detailCutoff.Format(time.RFC3339), summaryCutoff.Format(time.RFC3339))
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

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
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
