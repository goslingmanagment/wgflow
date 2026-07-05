package main

import (
	"fmt"
	"testing"
	"time"
)

func TestParseTLSSNI(t *testing.T) {
	record, handshake := testTLSClientHello("upload.example.com")
	if got := parseTLSSNI(record); got != "upload.example.com" {
		t.Fatalf("parseTLSSNI = %q, want upload.example.com", got)
	}
	if got := parseTLSHandshakeSNI(handshake); got != "upload.example.com" {
		t.Fatalf("parseTLSHandshakeSNI = %q, want upload.example.com", got)
	}
}

func testTLSClientHello(host string) (record []byte, handshake []byte) {
	return testTLSClientHelloPadded(host, 0)
}

// testTLSClientHelloPadded builds a ClientHello inflated with a padding
// extension (type 21) of pad bytes, mimicking post-quantum hellos that exceed
// the tunnel MTU. The SNI extension goes last so a truncated prefix cannot
// accidentally contain it.
func testTLSClientHelloPadded(host string, pad int) (record []byte, handshake []byte) {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)                   // session_id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites
	body = append(body, 0x01, 0x00)             // compression_methods
	var ext []byte
	if pad > 0 {
		ext = append(ext, 0x00, 0x15, byte(pad>>8), byte(pad)) // padding extension
		ext = append(ext, make([]byte, pad)...)
	}
	serverName := []byte{0x00, byte(len(host) >> 8), byte(len(host))}
	serverName = append(serverName, []byte(host)...)
	sniData := []byte{byte(len(serverName) >> 8), byte(len(serverName))}
	sniData = append(sniData, serverName...)
	ext = append(ext, 0x00, 0x00, byte(len(sniData)>>8), byte(len(sniData)))
	ext = append(ext, sniData...)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	handshake = []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record = []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	record = append(record, handshake...)
	return record, handshake
}

func feedSegments(t *testing.T, r *tlsReassembler, key tcpFlowKey, record []byte, cuts ...int) (string, bool) {
	t.Helper()
	now := time.Now()
	var sni string
	var reassembled bool
	seq := uint32(1000)
	prev := 0
	bounds := append(append([]int(nil), cuts...), len(record))
	for _, end := range bounds {
		seg := record[prev:end]
		sni, reassembled = r.Feed(key, seq, seg, now)
		if sni != "" && end != len(record) {
			t.Fatalf("SNI %q extracted before all segments were fed", sni)
		}
		seq += uint32(len(seg))
		prev = end
	}
	return sni, reassembled
}

func TestTLSReassemblyTwoSegments(t *testing.T) {
	// Real-world post-quantum ClientHello size: ~1800 bytes, above the ~1420
	// tunnel MTU, so it arrives as 1420 + tail.
	record, _ := testTLSClientHelloPadded("pq.example.com", 1700)
	if len(record) < 1700 {
		t.Fatalf("test CH too small: %d", len(record))
	}
	r := newTLSReassembler()
	key := tcpFlowKey{clientIP: "10.66.66.2", remoteIP: "192.0.2.1", clientPort: 50000, remotePort: 443}
	sni, reassembled := feedSegments(t, r, key, record, 1420)
	if sni != "pq.example.com" || !reassembled {
		t.Fatalf("sni=%q reassembled=%v, want pq.example.com via reassembly", sni, reassembled)
	}
	if r.Size() != 0 {
		t.Fatalf("buffer not freed after success: %d flows", r.Size())
	}
}

func TestTLSReassemblyThreeSegments(t *testing.T) {
	record, _ := testTLSClientHelloPadded("big.example.com", 3300)
	r := newTLSReassembler()
	key := tcpFlowKey{clientIP: "10.66.66.2", remoteIP: "192.0.2.1", clientPort: 50001, remotePort: 443}
	sni, reassembled := feedSegments(t, r, key, record, 1420, 2840)
	if sni != "big.example.com" || !reassembled {
		t.Fatalf("sni=%q reassembled=%v, want big.example.com via reassembly", sni, reassembled)
	}
	if r.Size() != 0 {
		t.Fatalf("buffer not freed after success: %d flows", r.Size())
	}
}

func TestTLSReassemblySingleSegmentFastPath(t *testing.T) {
	record, _ := testTLSClientHello("one.example.com")
	r := newTLSReassembler()
	key := tcpFlowKey{clientIP: "10.66.66.2", remoteIP: "192.0.2.1", clientPort: 50002, remotePort: 443}
	sni, reassembled := r.Feed(key, 1, record, time.Now())
	if sni != "one.example.com" || reassembled {
		t.Fatalf("sni=%q reassembled=%v, want one.example.com without reassembly", sni, reassembled)
	}
	if r.Size() != 0 {
		t.Fatalf("fast path must not buffer, got %d flows", r.Size())
	}
}

func TestTLSReassemblyGarbageContinuationResets(t *testing.T) {
	record, _ := testTLSClientHelloPadded("pq.example.com", 1700)
	r := newTLSReassembler()
	key := tcpFlowKey{clientIP: "10.66.66.2", remoteIP: "192.0.2.1", clientPort: 50003, remotePort: 443}
	now := time.Now()
	first := record[:1420]
	if sni, _ := r.Feed(key, 1000, first, now); sni != "" {
		t.Fatalf("unexpected SNI from first segment: %q", sni)
	}
	if r.Size() != 1 {
		t.Fatalf("first segment must start a buffer, got %d flows", r.Size())
	}
	// In-order continuation whose bytes complete the claimed handshake length
	// but do not parse as a ClientHello body: the parse is definitive, the
	// buffer must be freed.
	garbage := make([]byte, len(record)-1420)
	for i := range garbage {
		garbage[i] = 0xff
	}
	sni, _ := r.Feed(key, 1000+uint32(len(first)), garbage, now)
	if sni != "" {
		t.Fatalf("garbage continuation produced SNI %q", sni)
	}
	if r.Size() != 0 {
		t.Fatalf("buffer must be freed after definitive parse failure, got %d flows", r.Size())
	}
}

func TestTLSReassemblySeqMismatchResets(t *testing.T) {
	record, _ := testTLSClientHelloPadded("pq.example.com", 1700)
	r := newTLSReassembler()
	key := tcpFlowKey{clientIP: "10.66.66.2", remoteIP: "192.0.2.1", clientPort: 50004, remotePort: 443}
	now := time.Now()
	r.Feed(key, 1000, record[:1420], now)
	// A hole (seq jumps past the expected continuation) must reset the
	// buffer rather than corrupt the assembly.
	sni, _ := r.Feed(key, 5000, record[1420:], now)
	if sni != "" {
		t.Fatalf("mismatched continuation produced SNI %q", sni)
	}
	if r.Size() != 0 {
		t.Fatalf("buffer must be dropped on seq mismatch, got %d flows", r.Size())
	}
}

func TestTLSReassemblySegmentCap(t *testing.T) {
	record, _ := testTLSClientHelloPadded("pq.example.com", 7000)
	r := newTLSReassembler()
	key := tcpFlowKey{clientIP: "10.66.66.2", remoteIP: "192.0.2.1", clientPort: 50005, remotePort: 443}
	now := time.Now()
	seq := uint32(1)
	// Five 100-byte segments never complete the CH and exceed the 4-segment
	// cap; the buffer must be gone afterwards.
	for i := 0; i < 5; i++ {
		seg := record[i*100 : (i+1)*100]
		r.Feed(key, seq, seg, now)
		seq += uint32(len(seg))
	}
	if r.Size() != 0 {
		t.Fatalf("segment cap did not free the buffer, got %d flows", r.Size())
	}
}

func TestTLSReassemblyFlowCapEviction(t *testing.T) {
	record, _ := testTLSClientHelloPadded("pq.example.com", 1700)
	first := record[:1420]
	r := newTLSReassembler()
	now := time.Now()
	for i := 0; i < tlsAsmMaxFlows+10; i++ {
		key := tcpFlowKey{
			clientIP:   fmt.Sprintf("10.66.66.%d", i%250),
			remoteIP:   "192.0.2.1",
			clientPort: uint16(10000 + i),
			remotePort: 443,
		}
		r.Feed(key, 1, first, now)
	}
	if r.Size() > tlsAsmMaxFlows {
		t.Fatalf("flow map exceeded cap: %d > %d", r.Size(), tlsAsmMaxFlows)
	}
}

func TestParseHTTPHost(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    string
	}{
		{"simple GET", "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl\r\n\r\n", "example.com"},
		{"host with port stripped", "GET / HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n", "api.example.com"},
		{"lowercase header name", "POST /submit HTTP/1.0\r\nhost: upload.example.org\r\n\r\n", "upload.example.org"},
		{"uppercased value lowered", "GET / HTTP/1.1\r\nHost: CDN.Example.COM\r\n\r\n", "cdn.example.com"},
		{"host not first header", "GET / HTTP/1.1\r\nAccept: */*\r\nHost: two.example.com\r\n\r\n", "two.example.com"},
		{"no host header", "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", ""},
		{"not http at all", "\x16\x03\x01\x00\x50garbagegarbage", ""},
		{"method but no version", "GET some random bytes without crlf", ""},
		{"method without http marker", "GET /path FTP/9\r\nHost: example.com\r\n\r\n", ""},
		{"empty payload", "", ""},
		{"host without dot rejected", "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", ""},
		{"host with slash rejected", "GET / HTTP/1.1\r\nHost: bad/host.example.com\r\n\r\n", ""},
		{"ipv6 literal rejected", "GET / HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n", ""},
		{"non-numeric port rejected", "GET / HTTP/1.1\r\nHost: example.com:8o8o\r\n\r\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseHTTPHost([]byte(tc.payload)); got != tc.want {
				t.Fatalf("parseHTTPHost = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHTTPHostDeduperRateLimits(t *testing.T) {
	d := newHTTPHostDeduper()
	key := tcpFlowKey{clientIP: "10.66.66.2", remoteIP: "192.0.2.1", clientPort: 50100, remotePort: 80}
	now := time.Now()
	if !d.Allow(key, now) {
		t.Fatal("first record must pass")
	}
	if d.Allow(key, now.Add(10*time.Second)) {
		t.Fatal("second record within a minute must be suppressed")
	}
	if !d.Allow(key, now.Add(httpLogInterval+time.Second)) {
		t.Fatal("record after the interval must pass")
	}
	other := key
	other.clientPort = 50101
	if !d.Allow(other, now) {
		t.Fatal("different flow key must not be affected")
	}
}

func TestHTTPHostDeduperCap(t *testing.T) {
	d := newHTTPHostDeduper()
	now := time.Now()
	for i := 0; i < httpDedupMaxKeys+16; i++ {
		key := tcpFlowKey{clientIP: "10.66.66.2", remoteIP: "192.0.2.1", clientPort: uint16(i), remotePort: 80}
		d.Allow(key, now)
	}
	d.mu.Lock()
	n := len(d.seen)
	d.mu.Unlock()
	if n > httpDedupMaxKeys {
		t.Fatalf("dedup map exceeded cap: %d > %d", n, httpDedupMaxKeys)
	}
}

func TestTLSReassemblyTTLExpiry(t *testing.T) {
	record, _ := testTLSClientHelloPadded("pq.example.com", 1700)
	r := newTLSReassembler()
	key := tcpFlowKey{clientIP: "10.66.66.2", remoteIP: "192.0.2.1", clientPort: 50006, remotePort: 443}
	now := time.Now()
	r.Feed(key, 1000, record[:1420], now)
	// The continuation arrives after the TTL: the stale buffer must not be
	// used, and since the tail alone is not a handshake start, no SNI.
	late := now.Add(tlsAsmTTL + time.Second)
	sni, _ := r.Feed(key, 1000+1420, record[1420:], late)
	if sni != "" {
		t.Fatalf("expired buffer still produced SNI %q", sni)
	}
	r.Prune(late)
	if r.Size() != 0 {
		t.Fatalf("expired flow survived prune, got %d flows", r.Size())
	}
}
