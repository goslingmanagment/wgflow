package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
	"time"
)

// The parsers below consume raw bytes from untrusted VPN clients; none of
// them may ever panic. Seeds cover the valid formats plus known regressions
// (e.g. IPv4 total_length < header length) and truncations.

func FuzzParsePacket(f *testing.F) {
	f.Add(mkIPv4Packet(17, 0, mkUDPPayload(1234, 53, []byte("payload"))))
	f.Add(mkIPv4Packet(6, 0, mkTCPPayload(51000, 443, []byte("hello"))))
	f.Add(mkIPv4Packet(17, 0x2000|5, []byte{0x01, 0xbb, 0x00, 0x35})) // non-first fragment
	f.Add(mkIPv6FragmentPacket(17, 3, []byte{0x01, 0xbb, 0x00, 0x35}))
	f.Add(mkIPv6FragmentPacket(6, 0, mkTCPPayload(51000, 443, nil)))
	// Regression: total_length smaller than the IPv4 header used to panic.
	short := mkIPv4Packet(17, 0, mkUDPPayload(1234, 53, []byte("x")))
	binary.BigEndian.PutUint16(short[2:4], 10)
	f.Add(short)
	full := mkIPv4Packet(6, 0, mkTCPPayload(51000, 443, []byte("data")))
	f.Add(full[:21])
	f.Add(full[:1])
	f.Add([]byte{0x60}) // IPv6 nibble, truncated header
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return // the capture read buffer is 65535 bytes
		}
		parsePacket(b)
	})
}

func FuzzParseDNSMessage(f *testing.F) {
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	msg = appendDNSNameTest(msg, "photos.example.com")
	msg = append(msg, 0x00, 0x01, 0x00, 0x01)
	msg = append(msg, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 192, 0, 2, 55)
	f.Add(msg)
	f.Add(msg[:14])
	// CNAME answer with a compression pointer.
	cname := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	cname = appendDNSNameTest(cname, "a.example.com")
	cname = append(cname, 0x00, 0x05, 0x00, 0x01)
	cname = append(cname, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x06, 0x03, 'c', 'd', 'n', 0xc0, 0x0c)
	f.Add(cname)
	// Self-referencing compression pointer (depth limit must hold).
	loop := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01}
	f.Add(loop)
	// HTTPS answer with ipv4hint + ipv6hint SvcParams.
	httpsRdata := []byte{0x00, 0x01, 0x00} // ServiceMode, target "."
	httpsRdata = append(httpsRdata, 0x00, 0x04, 0x00, 0x04, 192, 0, 2, 10)
	httpsRdata = append(httpsRdata, 0x00, 0x06, 0x00, 0x10)
	httpsRdata = append(httpsRdata, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
	https := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	https = appendDNSNameTest(https, "api.example.com")
	https = append(https, 0x00, 0x41, 0x00, 0x01)
	https = append(https, 0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, byte(len(httpsRdata)))
	https = append(https, httpsRdata...)
	f.Add(https)
	f.Add(https[:len(https)-9]) // SvcParam cut mid-value
	// SVCB AliasMode answer with an uncompressed target name.
	svcbRdata := []byte{0x00, 0x00}
	svcbRdata = appendDNSNameTest(svcbRdata, "alias.example.org")
	svcb := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	svcb = appendDNSNameTest(svcb, "www.example.com")
	svcb = append(svcb, 0x00, 0x40, 0x00, 0x01)
	svcb = append(svcb, 0xc0, 0x0c, 0x00, 0x40, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, byte(len(svcbRdata)))
	svcb = append(svcb, svcbRdata...)
	f.Add(svcb)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		parseDNSMessage(b)
	})
}

func FuzzParseTLSSNI(f *testing.F) {
	record, handshake := testTLSClientHello("upload.example.com")
	f.Add(record)
	f.Add(handshake)
	f.Add(record[:7])
	f.Add(record[:len(record)-3])
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		parseTLSSNI(b)
		parseTLSHandshakeSNI(b)
	})
}

func FuzzParseQUICSNI(f *testing.F) {
	pkt := buildQUICInitialFuzzSeed("firebaseappcheck.googleapis.com")
	f.Add(pkt)
	f.Add(pkt[:20])
	f.Add(pkt[:len(pkt)-5])
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		parseQUICSNI(b)
		// Run the reassembling variant too so mutated datagrams reach the
		// CRYPTO segment collection and merge paths.
		parseQUICSNIAsm(b, newQUICReassembler(), time.Now())
	})
}

// FuzzTLSReassembly drives the per-flow reassembler with an arbitrary
// sequence of three segments, including seq gaps, so the stateful append /
// reset / cap logic can never panic on hostile input.
func FuzzTLSReassembly(f *testing.F) {
	record, _ := testTLSClientHelloPadded("pq.example.com", 1700)
	f.Add(record[:1420], append([]byte(nil), record[1420:]...), []byte{}, uint32(0))
	f.Add(record[:600], append([]byte(nil), record[600:1200]...), append([]byte(nil), record[1200:]...), uint32(0))
	f.Add(record[:1420], []byte{0xff, 0xff, 0xff}, []byte{0x16, 0x03, 0x01}, uint32(7)) // garbage continuation + seq gap
	f.Add([]byte{0x16, 0x03, 0x01, 0x40, 0x00}, []byte{0x01, 0x00, 0x40}, []byte{}, uint32(0))
	f.Fuzz(func(t *testing.T, s1, s2, s3 []byte, gap uint32) {
		if len(s1)+len(s2)+len(s3) > 65535 {
			return
		}
		r := newTLSReassembler()
		key := tcpFlowKey{clientIP: "10.66.66.2", remoteIP: "192.0.2.1", clientPort: 50000, remotePort: 443}
		now := time.Now()
		seq := uint32(1)
		r.Feed(key, seq, s1, now)
		seq += uint32(len(s1))
		r.Feed(key, seq, s2, now)
		// The third segment lands with a fuzzer-chosen offset to hit both
		// the in-order append and the mismatch-reset paths.
		r.Feed(key, seq+uint32(len(s2))+gap%16, s3, now)
	})
}

// FuzzQUICCryptoReassembly feeds raw segments with arbitrary offsets straight
// into the per-DCID merge logic (bypassing decryption, which the fuzzer
// cannot forge) to exercise sorting, overlap trimming, and cap handling.
func FuzzQUICCryptoReassembly(f *testing.F) {
	_, handshake := testTLSClientHelloPadded("pq.quic.example.com", 1700)
	f.Add(append([]byte(nil), handshake[:900]...), uint32(0), append([]byte(nil), handshake[900:]...), uint32(900))
	f.Add(append([]byte(nil), handshake[900:]...), uint32(900), append([]byte(nil), handshake[:900]...), uint32(0))
	f.Add([]byte{0x01, 0x00, 0x00}, uint32(0), []byte{0xff}, uint32(9000))
	f.Fuzz(func(t *testing.T, d1 []byte, o1 uint32, d2 []byte, o2 uint32) {
		if len(d1)+len(d2) > 65535 {
			return
		}
		asm := newQUICReassembler()
		dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
		now := time.Now()
		asm.Add(dcid, []quicCryptoSeg{{off: uint64(o1), data: d1}}, now)
		asm.Add(dcid, []quicCryptoSeg{{off: uint64(o2), data: d2}, {off: uint64(o1) / 2, data: d1}}, now)
	})
}

func FuzzParseHTTPHost(f *testing.F) {
	f.Add([]byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("POST / HTTP/1.0\r\nAccept: */*\r\nhost: api.example.com:8080\r\n\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost:"))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x50})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		parseHTTPHost(b)
	})
}

func mkTCPPayload(src, dst uint16, data []byte) []byte {
	p := make([]byte, 20+len(data))
	binary.BigEndian.PutUint16(p[0:2], src)
	binary.BigEndian.PutUint16(p[2:4], dst)
	p[12] = 5 << 4 // data offset: 20 bytes
	copy(p[20:], data)
	return p
}

// buildQUICInitialFuzzSeed mirrors testQUICInitialPacket but without a
// *testing.T so it can run during fuzz seeding; failures here mean the
// crypto stack is broken, so panicking is fine.
func buildQUICInitialFuzzSeed(host string) []byte {
	_, handshake := testTLSClientHello(host)
	plain := []byte{0x06, 0x00} // CRYPTO frame, offset 0
	plain = append(plain, encodeQUICVarIntTest(uint64(len(handshake)))...)
	plain = append(plain, handshake...)
	for len(plain) < 160 {
		plain = append(plain, 0x00)
	}

	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	key, iv, hp, ok := quicInitialKeys(0x00000001, dcid)
	if !ok {
		panic("missing quic v1 keys")
	}
	header := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, byte(len(dcid))}
	header = append(header, dcid...)
	header = append(header, 0x00) // scid len
	header = append(header, 0x00) // token len
	pn := []byte{0x01}
	header = append(header, encodeQUICVarIntTest(uint64(len(pn)+len(plain)+16))...)
	pnOffset := len(header)
	headerWithPN := append(append([]byte(nil), header...), pn...)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := append([]byte(nil), iv...)
	nonce[len(nonce)-1] ^= 0x01
	packet := append(headerWithPN, aead.Seal(nil, nonce, plain, headerWithPN)...)

	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		panic(err)
	}
	var mask [aes.BlockSize]byte
	hpBlock.Encrypt(mask[:], packet[pnOffset+4:pnOffset+4+aes.BlockSize])
	packet[0] ^= mask[0] & 0x0f
	packet[pnOffset] ^= mask[1]
	return packet
}
