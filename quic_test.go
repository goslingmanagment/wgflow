package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

func TestParseQUICSNI(t *testing.T) {
	packet := testQUICInitialPacket(t, "firebaseappcheck.googleapis.com")
	if got := parseQUICSNI(packet); got != "firebaseappcheck.googleapis.com" {
		t.Fatalf("parseQUICSNI = %q, want firebaseappcheck.googleapis.com", got)
	}
}

var testQUICDCID = []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

func testQUICInitialPacket(t *testing.T, host string) []byte {
	t.Helper()
	_, handshake := testTLSClientHello(host)
	return testQUICInitialFrames(t, testQUICDCID, 0x01, []quicCryptoSeg{{off: 0, data: handshake}})
}

// testQUICInitialFrames builds a genuinely encrypted QUIC v1 Initial packet
// carrying the given CRYPTO segments, so reassembly tests exercise the real
// header-protection and AEAD path rather than synthetic plaintext.
func testQUICInitialFrames(t *testing.T, dcid []byte, pn byte, frames []quicCryptoSeg) []byte {
	t.Helper()
	var plain []byte
	for _, fr := range frames {
		plain = append(plain, 0x06) // CRYPTO
		plain = append(plain, encodeQUICVarIntTest(fr.off)...)
		plain = append(plain, encodeQUICVarIntTest(uint64(len(fr.data)))...)
		plain = append(plain, fr.data...)
	}
	for len(plain) < 160 {
		plain = append(plain, 0x00)
	}

	key, iv, hp, ok := quicInitialKeys(0x00000001, dcid)
	if !ok {
		t.Fatal("missing quic v1 keys")
	}
	header := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, byte(len(dcid))}
	header = append(header, dcid...)
	header = append(header, 0x00) // scid len
	header = append(header, 0x00) // token len
	pnBytes := []byte{pn}
	header = append(header, encodeQUICVarIntTest(uint64(len(pnBytes)+len(plain)+16))...)
	pnOffset := len(header)
	headerWithPN := append(append([]byte(nil), header...), pnBytes...)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := append([]byte(nil), iv...)
	nonce[len(nonce)-1] ^= pn
	packet := append(headerWithPN, aead.Seal(nil, nonce, plain, headerWithPN)...)

	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		t.Fatal(err)
	}
	var mask [aes.BlockSize]byte
	hpBlock.Encrypt(mask[:], packet[pnOffset+4:pnOffset+4+aes.BlockSize])
	packet[0] ^= mask[0] & 0x0f
	packet[pnOffset] ^= mask[1]
	return packet
}

func TestQUICReassemblyTwoInitials(t *testing.T) {
	// A post-quantum-sized ClientHello split across two Initial packets, the
	// way Chromium fragments its CRYPTO flight.
	_, handshake := testTLSClientHelloPadded("pq.quic.example.com", 1700)
	cut := 900
	pkt1 := testQUICInitialFrames(t, testQUICDCID, 0x01, []quicCryptoSeg{{off: 0, data: handshake[:cut]}})
	pkt2 := testQUICInitialFrames(t, testQUICDCID, 0x02, []quicCryptoSeg{{off: uint64(cut), data: handshake[cut:]}})
	asm := newQUICReassembler()
	now := time.Now()
	if sni, _ := parseQUICSNIAsm(pkt1, asm, now); sni != "" {
		t.Fatalf("first fragment alone produced SNI %q", sni)
	}
	sni, reassembled := parseQUICSNIAsm(pkt2, asm, now)
	if sni != "pq.quic.example.com" || !reassembled {
		t.Fatalf("sni=%q reassembled=%v, want pq.quic.example.com via reassembly", sni, reassembled)
	}
	if asm.Size() != 0 {
		t.Fatalf("buffer not freed after success: %d DCIDs", asm.Size())
	}
}

func TestQUICReassemblyOutOfOrder(t *testing.T) {
	_, handshake := testTLSClientHelloPadded("ooo.quic.example.com", 1700)
	cut := 900
	pkt1 := testQUICInitialFrames(t, testQUICDCID, 0x01, []quicCryptoSeg{{off: 0, data: handshake[:cut]}})
	pkt2 := testQUICInitialFrames(t, testQUICDCID, 0x02, []quicCryptoSeg{{off: uint64(cut), data: handshake[cut:]}})
	asm := newQUICReassembler()
	now := time.Now()
	// Tail first: nothing contiguous at offset 0 yet.
	if sni, _ := parseQUICSNIAsm(pkt2, asm, now); sni != "" {
		t.Fatalf("tail fragment alone produced SNI %q", sni)
	}
	sni, reassembled := parseQUICSNIAsm(pkt1, asm, now)
	if sni != "ooo.quic.example.com" || !reassembled {
		t.Fatalf("sni=%q reassembled=%v, want ooo.quic.example.com via reassembly", sni, reassembled)
	}
	if asm.Size() != 0 {
		t.Fatalf("buffer not freed after success: %d DCIDs", asm.Size())
	}
}

func TestQUICReassemblyCoalescedDatagram(t *testing.T) {
	// Both Initials coalesced into a single UDP datagram must resolve in one
	// call: the packet loop feeds each into the reassembler.
	_, handshake := testTLSClientHelloPadded("coalesced.example.com", 1700)
	cut := 900
	pkt1 := testQUICInitialFrames(t, testQUICDCID, 0x01, []quicCryptoSeg{{off: 0, data: handshake[:cut]}})
	pkt2 := testQUICInitialFrames(t, testQUICDCID, 0x02, []quicCryptoSeg{{off: uint64(cut), data: handshake[cut:]}})
	datagram := append(append([]byte(nil), pkt1...), pkt2...)
	asm := newQUICReassembler()
	sni, reassembled := parseQUICSNIAsm(datagram, asm, time.Now())
	if sni != "coalesced.example.com" || !reassembled {
		t.Fatalf("sni=%q reassembled=%v, want coalesced.example.com via reassembly", sni, reassembled)
	}
}

func TestQUICReassemblyPacketCap(t *testing.T) {
	_, handshake := testTLSClientHelloPadded("cap.quic.example.com", 6000)
	asm := newQUICReassembler()
	now := time.Now()
	// Three Initials that never complete the hello (a hole stays at the
	// front) must exhaust the packet cap and free the buffer.
	for i := 0; i < quicAsmMaxPackets; i++ {
		off := uint64(1000 + i*100)
		pkt := testQUICInitialFrames(t, testQUICDCID, byte(i+1), []quicCryptoSeg{{off: off, data: handshake[off : off+100]}})
		if sni, _ := parseQUICSNIAsm(pkt, asm, now); sni != "" {
			t.Fatalf("incomplete fragments produced SNI %q", sni)
		}
	}
	if asm.Size() != 0 {
		t.Fatalf("packet cap did not free the buffer, got %d DCIDs", asm.Size())
	}
}

func TestQUICReassemblyDCIDCap(t *testing.T) {
	_, handshake := testTLSClientHelloPadded("dcid.quic.example.com", 1700)
	asm := newQUICReassembler()
	now := time.Now()
	for i := 0; i < quicAsmMaxDCIDs+8; i++ {
		dcid := []byte(fmt.Sprintf("dcid%04d", i))
		pkt := testQUICInitialFrames(t, dcid, 0x01, []quicCryptoSeg{{off: 0, data: handshake[:600]}})
		parseQUICSNIAsm(pkt, asm, now)
	}
	if asm.Size() > quicAsmMaxDCIDs {
		t.Fatalf("DCID map exceeded cap: %d > %d", asm.Size(), quicAsmMaxDCIDs)
	}
}

func TestQUICReassemblyTTL(t *testing.T) {
	_, handshake := testTLSClientHelloPadded("ttl.quic.example.com", 1700)
	cut := 900
	pkt1 := testQUICInitialFrames(t, testQUICDCID, 0x01, []quicCryptoSeg{{off: 0, data: handshake[:cut]}})
	pkt2 := testQUICInitialFrames(t, testQUICDCID, 0x02, []quicCryptoSeg{{off: uint64(cut), data: handshake[cut:]}})
	asm := newQUICReassembler()
	now := time.Now()
	parseQUICSNIAsm(pkt1, asm, now)
	// The continuation lands after the TTL: stale state must not combine
	// with it. The tail alone starts a fresh (incomplete) buffer.
	late := now.Add(quicAsmTTL + time.Second)
	if sni, _ := parseQUICSNIAsm(pkt2, asm, late); sni != "" {
		t.Fatalf("expired buffer still produced SNI %q", sni)
	}
	asm.Prune(late.Add(quicAsmTTL + time.Second))
	if asm.Size() != 0 {
		t.Fatalf("expired state survived prune, got %d DCIDs", asm.Size())
	}
}

func encodeQUICVarIntTest(v uint64) []byte {
	switch {
	case v < 64:
		return []byte{byte(v)}
	case v < 16384:
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(v)|0x4000)
		return b[:]
	case v < 1073741824:
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(v)|0x80000000)
		return b[:]
	default:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v|0xc000000000000000)
		return b[:]
	}
}
