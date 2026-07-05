package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"sync"
	"time"
)

var (
	quicV1InitialSalt = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
	}
	quicDraft29InitialSalt = []byte{
		0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
		0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
	}
)

func parseQUICSNI(datagram []byte) string {
	sni, _ := parseQUICSNIAsm(datagram, nil, time.Time{})
	return sni
}

// parseQUICSNIAsm walks every long-header packet coalesced into the datagram,
// decrypts Initials, and extracts the ClientHello SNI. With a non-nil asm,
// CRYPTO frames that do not yield a complete ClientHello on their own are fed
// into the per-DCID reassembler, so a hello split across several Initial
// packets (or CRYPTO frames) still resolves. reassembled reports whether the
// SNI needed cross-packet state.
func parseQUICSNIAsm(datagram []byte, asm *quicReassembler, now time.Time) (sni string, reassembled bool) {
	for off := 0; off < len(datagram); {
		if len(datagram)-off < 7 || datagram[off]&0x80 == 0 {
			return "", false
		}
		first := datagram[off]
		version := binary.BigEndian.Uint32(datagram[off+1 : off+5])
		pos := off + 5
		dcidLen := int(datagram[pos])
		pos++
		if dcidLen == 0 || pos+dcidLen > len(datagram) {
			return "", false
		}
		dcid := datagram[pos : pos+dcidLen]
		pos += dcidLen
		if pos >= len(datagram) {
			return "", false
		}
		scidLen := int(datagram[pos])
		pos++
		if pos+scidLen > len(datagram) {
			return "", false
		}
		pos += scidLen
		tokenLen, next, ok := readQUICVarInt(datagram, pos)
		if !ok || tokenLen > uint64(len(datagram)-next) {
			return "", false
		}
		pos = next + int(tokenLen)
		packetLen, next, ok := readQUICVarInt(datagram, pos)
		if !ok || packetLen > uint64(len(datagram)-next) {
			return "", false
		}
		pnOffset := next
		packetEnd := pnOffset + int(packetLen)
		if first&0x30 == 0x00 {
			if plaintext, ok := decryptQUICInitial(datagram, off, pnOffset, packetEnd, version, dcid); ok {
				sni, done, segs := walkQUICCryptoFrames(plaintext, asm != nil)
				if sni != "" {
					return sni, false
				}
				// done means an offset-0 frame held a complete ClientHello
				// with no usable SNI — more packets cannot change that.
				if asm != nil && !done && len(segs) > 0 {
					if s := asm.Add(dcid, segs, now); s != "" {
						return s, true
					}
				}
			}
		}
		off = packetEnd
	}
	return "", false
}

func decryptQUICInitial(datagram []byte, packetStart, pnOffset, packetEnd int, version uint32, dcid []byte) ([]byte, bool) {
	key, iv, hp, ok := quicInitialKeys(version, dcid)
	if !ok || pnOffset+4+aes.BlockSize > packetEnd {
		return nil, false
	}
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, false
	}
	var mask [aes.BlockSize]byte
	hpBlock.Encrypt(mask[:], datagram[pnOffset+4:pnOffset+4+aes.BlockSize])
	first := datagram[packetStart] ^ (mask[0] & 0x0f)
	pnLen := int(first&0x03) + 1
	if pnLen < 1 || pnLen > 4 || pnOffset+pnLen > packetEnd {
		return nil, false
	}
	packetNumber := uint64(0)
	header := make([]byte, pnOffset+pnLen-packetStart)
	copy(header, datagram[packetStart:pnOffset+pnLen])
	header[0] = first
	for i := 0; i < pnLen; i++ {
		b := datagram[pnOffset+i] ^ mask[1+i]
		header[pnOffset-packetStart+i] = b
		packetNumber = (packetNumber << 8) | uint64(b)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(packetNumber >> (8 * i))
	}
	plain, err := aead.Open(nil, nonce, datagram[pnOffset+pnLen:packetEnd], header)
	if err != nil {
		return nil, false
	}
	return plain, true
}

// quicCryptoSeg is one CRYPTO frame's slice of the handshake byte stream.
type quicCryptoSeg struct {
	off  uint64
	data []byte
}

// walkQUICCryptoFrames scans the frames of a decrypted Initial payload. The
// common case — one offset-0 CRYPTO frame holding the whole ClientHello —
// returns the SNI directly with no allocation. done reports a definitive
// negative (a complete hello parsed but yielded nothing), which tells the
// caller reassembly cannot help. When collect is set, CRYPTO segments that
// might still combine into a hello are returned for cross-packet reassembly.
func walkQUICCryptoFrames(plain []byte, collect bool) (sni string, done bool, segs []quicCryptoSeg) {
	for off := 0; off < len(plain); {
		typ, next, ok := readQUICVarInt(plain, off)
		if !ok {
			return "", false, segs
		}
		off = next
		switch typ {
		case 0x00, 0x01: // PADDING, PING
			continue
		case 0x02, 0x03: // ACK, ACK_ECN
			var ok bool
			off, ok = skipQUICAckFrame(plain, off, typ == 0x03)
			if !ok {
				return "", false, segs
			}
		case 0x06: // CRYPTO
			cryptoOff, next, ok := readQUICVarInt(plain, off)
			if !ok {
				return "", false, segs
			}
			ln, next, ok := readQUICVarInt(plain, next)
			if !ok || ln > uint64(len(plain)-next) {
				return "", false, segs
			}
			data := plain[next : next+int(ln)]
			off = next + int(ln)
			if cryptoOff == 0 {
				s, status := parseTLSHandshakeSNIStatus(data)
				if status == tlsComplete {
					if s != "" {
						return s, true, nil
					}
					// Some stacks wrap the hello in a record layer even
					// inside CRYPTO; historical behavior, keep it.
					if s := parseTLSSNI(data); s != "" {
						return s, true, nil
					}
					return "", true, nil
				}
			}
			if collect && len(data) > 0 {
				segs = append(segs, quicCryptoSeg{off: cryptoOff, data: data})
			}
		default:
			return "", false, segs
		}
	}
	return "", false, segs
}

// QUIC CRYPTO reassembly. Chromium and friends split the Initial flight's
// CRYPTO stream across several Initial packets (each under the MTU), so the
// offset-0 frame alone rarely holds the whole post-quantum ClientHello.
// Segments are keyed by DCID: all Initials of one connection attempt carry
// the same client-chosen DCID, and the decryption keys derive from it too.
const (
	quicAsmMaxBytes   = 8192             // per-DCID buffered handshake bytes
	quicAsmMaxPackets = 3                // Initial packets per DCID
	quicAsmTTL        = 10 * time.Second // handshakes spread longer are dead
	quicAsmMaxDCIDs   = 1024             // map cap; evicts expired first
)

type quicAsmState struct {
	segs    []quicCryptoSeg // sorted by offset, non-overlapping, owned copies
	bytes   int
	packets int
	expires time.Time
}

type quicReassembler struct {
	mu    sync.Mutex
	dcids map[string]*quicAsmState
}

func newQUICReassembler() *quicReassembler {
	return &quicReassembler{dcids: map[string]*quicAsmState{}}
}

// Add merges the CRYPTO segments decrypted from one Initial packet into the
// DCID's buffer and re-attempts the ClientHello parse over the contiguous
// prefix. The buffer is freed on success, on a definitive parse failure, and
// when any cap fires.
func (r *quicReassembler) Add(dcid []byte, segs []quicCryptoSeg, now time.Time) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.dcids[string(dcid)]
	if st != nil && now.After(st.expires) {
		delete(r.dcids, string(dcid))
		st = nil
	}
	if st == nil {
		if len(r.dcids) >= quicAsmMaxDCIDs {
			r.evictLocked(now)
		}
		st = &quicAsmState{expires: now.Add(quicAsmTTL)}
		r.dcids[string(dcid)] = st
	}
	st.packets++
	for _, s := range segs {
		st.insert(s)
	}
	if st.bytes > quicAsmMaxBytes {
		delete(r.dcids, string(dcid))
		return ""
	}
	// Only a contiguous prefix starting at stream offset 0 can be parsed.
	if len(st.segs) == 0 || st.segs[0].off != 0 {
		if st.packets >= quicAsmMaxPackets {
			delete(r.dcids, string(dcid))
		}
		return ""
	}
	prefix := st.segs[0].data
	sni, status := parseTLSHandshakeSNIStatus(prefix)
	if status == tlsComplete {
		delete(r.dcids, string(dcid))
		return sni
	}
	if st.packets >= quicAsmMaxPackets {
		delete(r.dcids, string(dcid))
	}
	return ""
}

// insert adds an owned copy of one segment, keeping segs sorted and merged.
// Overlaps (retransmitted Initials) collapse instead of double-counting.
func (st *quicAsmState) insert(seg quicCryptoSeg) {
	if seg.off >= quicAsmMaxBytes || len(seg.data) == 0 {
		return
	}
	data := seg.data
	if seg.off+uint64(len(data)) > quicAsmMaxBytes {
		data = data[:quicAsmMaxBytes-seg.off]
	}
	// Copy: seg.data aliases the decrypted packet buffer, which must not be
	// pinned in the map for the buffer's lifetime.
	st.segs = append(st.segs, quicCryptoSeg{off: seg.off, data: append([]byte(nil), data...)})
	sort.Slice(st.segs, func(i, j int) bool { return st.segs[i].off < st.segs[j].off })
	merged := st.segs[:1]
	for _, s := range st.segs[1:] {
		last := &merged[len(merged)-1]
		lastEnd := last.off + uint64(len(last.data))
		if s.off <= lastEnd {
			if end := s.off + uint64(len(s.data)); end > lastEnd {
				last.data = append(last.data, s.data[lastEnd-s.off:]...)
			}
		} else {
			merged = append(merged, s)
		}
	}
	st.segs = merged
	st.bytes = 0
	for _, s := range st.segs {
		st.bytes += len(s.data)
	}
}

// evictLocked frees room in a full DCID map, expired entries first, then
// arbitrary ones. Losing a buffer costs at most one domain label.
func (r *quicReassembler) evictLocked(now time.Time) {
	for k, st := range r.dcids {
		if now.After(st.expires) {
			delete(r.dcids, k)
		}
	}
	for k := range r.dcids {
		if len(r.dcids) < quicAsmMaxDCIDs {
			break
		}
		delete(r.dcids, k)
	}
}

// Prune drops expired buffers; called periodically from the capture loop.
func (r *quicReassembler) Prune(now time.Time) {
	r.mu.Lock()
	for k, st := range r.dcids {
		if now.After(st.expires) {
			delete(r.dcids, k)
		}
	}
	r.mu.Unlock()
}

func (r *quicReassembler) Size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.dcids)
}

func skipQUICAckFrame(b []byte, off int, withECN bool) (int, bool) {
	var ok bool
	if _, off, ok = readQUICVarInt(b, off); !ok { // largest acknowledged
		return 0, false
	}
	if _, off, ok = readQUICVarInt(b, off); !ok { // ack delay
		return 0, false
	}
	rangeCount, off, ok := readQUICVarInt(b, off)
	if !ok {
		return 0, false
	}
	if _, off, ok = readQUICVarInt(b, off); !ok { // first ack range
		return 0, false
	}
	for i := uint64(0); i < rangeCount; i++ {
		if _, off, ok = readQUICVarInt(b, off); !ok { // gap
			return 0, false
		}
		if _, off, ok = readQUICVarInt(b, off); !ok { // ack range length
			return 0, false
		}
	}
	if withECN {
		for i := 0; i < 3; i++ {
			if _, off, ok = readQUICVarInt(b, off); !ok {
				return 0, false
			}
		}
	}
	return off, true
}

func readQUICVarInt(b []byte, off int) (uint64, int, bool) {
	if off >= len(b) {
		return 0, 0, false
	}
	prefix := b[off] >> 6
	ln := 1 << prefix
	if off+ln > len(b) {
		return 0, 0, false
	}
	switch ln {
	case 1:
		return uint64(b[off] & 0x3f), off + 1, true
	case 2:
		return uint64(binary.BigEndian.Uint16(b[off:off+2]) & 0x3fff), off + 2, true
	case 4:
		return uint64(binary.BigEndian.Uint32(b[off:off+4]) & 0x3fffffff), off + 4, true
	case 8:
		return binary.BigEndian.Uint64(b[off:off+8]) & 0x3fffffffffffffff, off + 8, true
	default:
		return 0, 0, false
	}
}

func quicInitialKeys(version uint32, dcid []byte) (key, iv, hp []byte, ok bool) {
	salt := quicInitialSalt(version)
	if salt == nil {
		return nil, nil, nil, false
	}
	initialSecret := hkdfExtract(salt, dcid)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", nil, sha256.Size)
	return hkdfExpandLabel(clientSecret, "quic key", nil, 16),
		hkdfExpandLabel(clientSecret, "quic iv", nil, 12),
		hkdfExpandLabel(clientSecret, "quic hp", nil, 16),
		true
}

func quicInitialSalt(version uint32) []byte {
	switch version {
	case 0x00000001:
		return quicV1InitialSalt
	case 0xff00001d:
		return quicDraft29InitialSalt
	default:
		return nil
	}
}

func hkdfExtract(salt, secret []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(secret)
	return mac.Sum(nil)
}

func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	fullLabel := []byte("tls13 " + label)
	info := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	return hkdfExpand(secret, info, length)
}

func hkdfExpand(secret, info []byte, length int) []byte {
	if length <= 0 || length > 255*sha256.Size {
		return nil
	}
	var out, prev []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(sha256.New, secret)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{counter})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}
