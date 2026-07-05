package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"sync"
	"time"
)

type TLSRecord struct {
	TS         time.Time `json:"ts"`
	Interface  string    `json:"interface"`
	Client     string    `json:"client"`
	ClientIP   string    `json:"client_ip"`
	RemoteIP   string    `json:"remote_ip"`
	RemotePort uint16    `json:"remote_port"`
	ServerName string    `json:"server_name"`
	Protocol   string    `json:"protocol,omitempty"`
}

// tlsParseStatus tells the caller whether a parse result is final or whether
// the input is a valid prefix of a ClientHello that continues in bytes we
// have not seen yet. Only the latter justifies paying for reassembly.
type tlsParseStatus int

const (
	// tlsComplete: definitive answer — either an SNI was extracted or the
	// input can never become a parsable ClientHello no matter how many more
	// bytes arrive.
	tlsComplete tlsParseStatus = iota
	// tlsNeedMore: the input is a well-formed proper prefix of a TLS
	// handshake; appending the next in-order segment may finish the parse.
	tlsNeedMore
)

// maxTLSRecordLen rejects absurd record lengths early: TLSPlaintext caps
// fragments at 2^14, and we allow a little slack for non-compliant stacks.
const maxTLSRecordLen = 1<<14 + 256

func parseTLSSNI(payload []byte) string {
	sni, _ := parseTLSSNIStatus(payload)
	return sni
}

// parseTLSSNIStatus parses a TLS record stream (one or more handshake records
// back to back, as seen on a TCP connection) and extracts the ClientHello
// SNI. Unlike the old single-record parser it supports a ClientHello that
// spans several records and reports tlsNeedMore when the stream is cut short,
// which is what post-quantum ClientHellos (>1700 bytes, above the ~1420
// tunnel MTU) look like in the first TCP segment.
func parseTLSSNIStatus(buf []byte) (string, tlsParseStatus) {
	var hs []byte   // handshake bytes assembled from record fragments
	copied := false // hs owns its backing array and may be appended to
	need := -1      // total handshake bytes required; -1 until header seen
	for off := 0; ; {
		if off >= len(buf) {
			// Ended exactly on a record boundary with the ClientHello still
			// incomplete: the next record lives in a later segment.
			return "", tlsNeedMore
		}
		if buf[off] != 22 {
			return "", tlsComplete
		}
		if len(buf)-off < 5 {
			return "", tlsNeedMore
		}
		recLen := int(binary.BigEndian.Uint16(buf[off+3 : off+5]))
		if recLen <= 0 || recLen > maxTLSRecordLen {
			return "", tlsComplete
		}
		frag := buf[off+5:]
		if len(frag) > recLen {
			frag = frag[:recLen]
		}
		if hs == nil {
			// Common case: the whole ClientHello sits in one record — alias
			// the input instead of copying.
			hs = frag
		} else if !copied {
			hs = append(append(make([]byte, 0, len(hs)+len(frag)), hs...), frag...)
			copied = true
		} else {
			hs = append(hs, frag...)
		}
		// Validate the handshake header as soon as 4 bytes exist so garbage
		// is rejected without waiting for more segments.
		if need < 0 && len(hs) >= 4 {
			if hs[0] != 1 {
				return "", tlsComplete
			}
			hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if hsLen <= 0 || 4+hsLen > tlsAsmMaxBytes {
				// A ClientHello above the reassembly cap can never be
				// assembled, so give up now rather than buffer for nothing.
				return "", tlsComplete
			}
			need = 4 + hsLen
		}
		if need > 0 && len(hs) >= need {
			return parseTLSClientHelloSNI(hs[4:need]), tlsComplete
		}
		if len(frag) < recLen {
			return "", tlsNeedMore // record continues in the next segment
		}
		off += 5 + recLen
	}
}

func parseTLSHandshakeSNI(data []byte) string {
	sni, _ := parseTLSHandshakeSNIStatus(data)
	return sni
}

// parseTLSHandshakeSNIStatus parses raw handshake bytes (no record layer, as
// in QUIC CRYPTO streams) and distinguishes "not a ClientHello" from "valid
// prefix, need more bytes".
func parseTLSHandshakeSNIStatus(data []byte) (string, tlsParseStatus) {
	if len(data) < 4 {
		if len(data) > 0 && data[0] != 1 {
			return "", tlsComplete
		}
		return "", tlsNeedMore
	}
	if data[0] != 1 {
		return "", tlsComplete
	}
	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if hsLen <= 0 || 4+hsLen > tlsAsmMaxBytes {
		return "", tlsComplete
	}
	if 4+hsLen > len(data) {
		return "", tlsNeedMore
	}
	return parseTLSClientHelloSNI(data[4 : 4+hsLen]), tlsComplete
}

func parseTLSClientHelloSNI(body []byte) string {
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

// TCP ClientHello reassembly. Roughly 27-30% of port-443 bytes in production
// carry no domain; a big part of that is ClientHellos (post-quantum ones are
// >1700 bytes) that do not fit into one ~1420-byte tunnel segment, so the
// single-packet parser never sees the SNI. The reassembler buffers the first
// segment of a handshake and appends strictly in-order continuations until
// the ClientHello parses or a cap fires.
const (
	tlsAsmMaxBytes    = 8192             // per-flow buffer cap
	tlsAsmMaxSegments = 4                // segments per flow, first included
	tlsAsmTTL         = 10 * time.Second // a CH split over longer than this is dead
	tlsAsmMaxFlows    = 4096             // map cap; evicts expired first
)

// tcpFlowKey identifies one TCP connection attempt. The client port matters:
// two parallel connections from the same client to the same server must not
// share a reassembly buffer.
type tcpFlowKey struct {
	clientIP   string
	remoteIP   string
	clientPort uint16
	remotePort uint16
}

type tlsAsmFlow struct {
	buf      []byte
	segments int
	nextSeq  uint32 // TCP seq the next in-order segment must start at
	expires  time.Time
}

type tlsReassembler struct {
	mu    sync.Mutex
	flows map[tcpFlowKey]*tlsAsmFlow
}

func newTLSReassembler() *tlsReassembler {
	return &tlsReassembler{flows: map[tcpFlowKey]*tlsAsmFlow{}}
}

// Feed processes one outbound tcp/443 payload and returns the SNI once known.
// The common case (complete ClientHello in a single segment) never touches
// the flow map's contents and allocates nothing beyond the returned string;
// buffering starts only when the parser reports a valid-but-incomplete CH.
// reassembled is true when the SNI required more than one segment.
func (r *tlsReassembler) Feed(key tcpFlowKey, seq uint32, payload []byte, now time.Time) (sni string, reassembled bool) {
	if len(payload) == 0 {
		return "", false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if flow, ok := r.flows[key]; ok {
		if now.After(flow.expires) {
			delete(r.flows, key)
			// Fall through: this payload may start a fresh handshake.
		} else if seq != flow.nextSeq {
			// Out-of-order, retransmit, or a hole we cannot fill without real
			// TCP tracking: a corrupt assembly would parse garbage, so drop
			// the buffer instead. The payload itself may still start a new
			// handshake (e.g. after a retry), so keep going below.
			delete(r.flows, key)
		} else {
			if len(flow.buf)+len(payload) > tlsAsmMaxBytes {
				delete(r.flows, key)
				return "", false
			}
			flow.buf = append(flow.buf, payload...)
			flow.segments++
			flow.nextSeq = seq + uint32(len(payload))
			s, status := parseTLSSNIStatus(flow.buf)
			if status == tlsComplete {
				delete(r.flows, key)
				return s, s != ""
			}
			if flow.segments >= tlsAsmMaxSegments {
				delete(r.flows, key)
			}
			return "", false
		}
	}
	s, status := parseTLSSNIStatus(payload)
	if status == tlsComplete {
		return s, false
	}
	if len(r.flows) >= tlsAsmMaxFlows {
		r.evictLocked(now)
	}
	r.flows[key] = &tlsAsmFlow{
		buf:      append(make([]byte, 0, len(payload)), payload...),
		segments: 1,
		nextSeq:  seq + uint32(len(payload)),
		expires:  now.Add(tlsAsmTTL),
	}
	return "", false
}

// evictLocked makes room in a full map: expired flows go first; if everything
// is still live, drop arbitrary entries (map iteration order). Losing a
// buffer only costs a potential domain label, never byte accounting.
func (r *tlsReassembler) evictLocked(now time.Time) {
	for k, f := range r.flows {
		if now.After(f.expires) {
			delete(r.flows, k)
		}
	}
	for k := range r.flows {
		if len(r.flows) < tlsAsmMaxFlows {
			break
		}
		delete(r.flows, k)
	}
}

// Prune drops expired buffers; called periodically so an idle capture does
// not sit on up to 32 MB of dead handshake fragments.
func (r *tlsReassembler) Prune(now time.Time) {
	r.mu.Lock()
	for k, f := range r.flows {
		if now.After(f.expires) {
			delete(r.flows, k)
		}
	}
	r.mu.Unlock()
}

func (r *tlsReassembler) Size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.flows)
}

// Plaintext HTTP Host extraction. Production still moves ~0.7 GB on tcp/80
// with the hostname sitting in cleartext; a request's Host header names those
// flows for free. Records go to the tls log with protocol "http" (the field's
// third value, agreed with the UI), so the existing site views pick them up.

// httpHeaderScanLimit bounds how far into a payload we look for the Host
// header. It lives in the first ~hundred bytes of real requests; scanning a
// whole 64 KB GSO buffer would be wasted work on garbage.
const httpHeaderScanLimit = 2048

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
	[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "),
	[]byte("CONNECT "), []byte("TRACE "),
}

var httpVersionMark = []byte(" HTTP/1.")

// parseHTTPHost pulls the Host header from the first packet of a plaintext
// HTTP request. No cross-segment reassembly: Host is practically always in
// the first segment, and a miss only costs a label. Runs on every outbound
// tcp/80 payload, so the negative path must not allocate.
func parseHTTPHost(payload []byte) string {
	if len(payload) > httpHeaderScanLimit {
		payload = payload[:httpHeaderScanLimit]
	}
	method := false
	for _, m := range httpMethods {
		if bytes.HasPrefix(payload, m) {
			method = true
			break
		}
	}
	if !method {
		return ""
	}
	// Require a real request line before trusting header parsing: random
	// binary payloads occasionally start with method-like bytes.
	lineEnd := indexCRLF(payload, 0)
	if lineEnd < 0 || !bytes.Contains(payload[:lineEnd], httpVersionMark) {
		return ""
	}
	for pos := lineEnd + 2; pos < len(payload); {
		end := indexCRLF(payload, pos)
		if end < 0 {
			return ""
		}
		if end == pos {
			return "" // blank line: headers over, no Host seen
		}
		line := payload[pos:end]
		pos = end + 2
		if !hasHostPrefix(line) {
			continue
		}
		host := strings.TrimSpace(string(line[5:]))
		if host == "" || host[0] == '[' {
			return "" // bracketed IPv6 literal is never a hostname
		}
		// Strip an explicit port (Host: example.com:8080).
		if i := strings.LastIndexByte(host, ':'); i >= 0 {
			port := host[i+1:]
			if port == "" || !allDigits(port) {
				return ""
			}
			host = host[:i]
		}
		host = strings.ToLower(host)
		if validHostname(host) {
			return host
		}
		return ""
	}
	return ""
}

// indexCRLF finds the next CRLF at or after pos.
func indexCRLF(b []byte, pos int) int {
	for i := pos; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i
		}
	}
	return -1
}

// hasHostPrefix reports whether the header line starts with "host:" in any
// case, without converting to string (this runs per header line of every
// plaintext request).
func hasHostPrefix(line []byte) bool {
	return len(line) >= 5 &&
		line[0]|0x20 == 'h' && line[1]|0x20 == 'o' &&
		line[2]|0x20 == 's' && line[3]|0x20 == 't' && line[4] == ':'
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// httpHostDeduper rate-limits http host records to one per flow key per
// minute: unlike TLS (one ClientHello per connection), a keep-alive HTTP
// connection repeats the Host header on every request.
const (
	httpLogInterval  = time.Minute
	httpDedupMaxKeys = 4096
)

type httpHostDeduper struct {
	mu   sync.Mutex
	seen map[tcpFlowKey]time.Time // last time a record was written
}

func newHTTPHostDeduper() *httpHostDeduper {
	return &httpHostDeduper{seen: map[tcpFlowKey]time.Time{}}
}

func (d *httpHostDeduper) Allow(key tcpFlowKey, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if last, ok := d.seen[key]; ok && now.Sub(last) < httpLogInterval {
		return false
	}
	if len(d.seen) >= httpDedupMaxKeys {
		for k, last := range d.seen {
			if now.Sub(last) >= httpLogInterval {
				delete(d.seen, k)
			}
		}
		for k := range d.seen {
			if len(d.seen) < httpDedupMaxKeys {
				break
			}
			delete(d.seen, k)
		}
	}
	d.seen[key] = now
	return true
}

// Prune drops stale keys so an idle capture does not pin dead flows.
func (d *httpHostDeduper) Prune(now time.Time) {
	d.mu.Lock()
	for k, last := range d.seen {
		if now.Sub(last) >= httpLogInterval {
			delete(d.seen, k)
		}
	}
	d.mu.Unlock()
}

func validHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, " \t\r\n/") {
		return false
	}
	return strings.Contains(s, ".")
}
