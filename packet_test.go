package main

import (
	"encoding/binary"
	"testing"
)

// mkIPv4Packet builds a minimal IPv4 packet. fragField is the raw flags+offset
// field (bytes 6-7): top 3 bits flags, lower 13 bits offset in 8-byte units.
func mkIPv4Packet(proto byte, fragField uint16, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45 // version 4, ihl 20
	binary.BigEndian.PutUint16(b[2:4], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(b[6:8], fragField)
	b[8] = 64
	b[9] = proto
	copy(b[12:16], []byte{10, 66, 66, 6})
	copy(b[16:20], []byte{93, 184, 216, 34})
	copy(b[20:], payload)
	return b
}

// mkIPv6FragmentPacket builds an IPv6 packet with a fragment extension header.
// fragOff is the fragment offset in 8-byte units.
func mkIPv6FragmentPacket(next byte, fragOff uint16, payload []byte) []byte {
	b := make([]byte, 40+8+len(payload))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(8+len(payload)))
	b[6] = 44 // next header: fragment
	b[7] = 64
	b[8+15] = 1  // src ::1
	b[24+15] = 2 // dst ::2
	b[40] = next // transport proto carried by the fragment chain
	binary.BigEndian.PutUint16(b[42:44], fragOff<<3)
	copy(b[48:], payload)
	return b
}

func mkUDPPayload(src, dst uint16, data []byte) []byte {
	p := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(p[0:2], src)
	binary.BigEndian.PutUint16(p[2:4], dst)
	binary.BigEndian.PutUint16(p[4:6], uint16(8+len(data)))
	copy(p[8:], data)
	return p
}

// Regression: a crafted total_length smaller than the header length used to
// slice b[ihl:total] with an inverted range and panic, killing the daemon.
func TestParseIPv4ShortTotalLengthNoPanic(t *testing.T) {
	pkt := mkIPv4Packet(17, 0, mkUDPPayload(1234, 53, []byte("x")))
	binary.BigEndian.PutUint16(pkt[2:4], 10) // total_length 10 < ihl 20
	if _, ok := parsePacket(pkt); ok {
		t.Fatal("malformed packet (total < ihl) must be rejected")
	}
}

func TestParseIPv4NonFirstFragmentHasNoPorts(t *testing.T) {
	// Payload starts with bytes that would decode as ports 443->53 if the
	// parser wrongly treated a mid-flight fragment as a transport header.
	payload := []byte{0x01, 0xbb, 0x00, 0x35, 0x00, 0x10, 0x00, 0x00, 0xde, 0xad}
	pkt := mkIPv4Packet(17, 0x2000|5, payload) // MF set, offset 5*8 bytes
	p, ok := parsePacket(pkt)
	if !ok {
		t.Fatal("non-first fragment must still be counted")
	}
	if p.SrcPort != 0 || p.DstPort != 0 {
		t.Fatalf("fragment ports = %d->%d, want 0->0", p.SrcPort, p.DstPort)
	}
	if p.Proto != 17 {
		t.Fatalf("proto = %d, want 17", p.Proto)
	}
	if p.Length != len(pkt) {
		t.Fatalf("length = %d, want %d (fragment bytes must not be lost)", p.Length, len(pkt))
	}
}

func TestParseIPv4FirstFragmentParsesPorts(t *testing.T) {
	pkt := mkIPv4Packet(17, 0x2000, mkUDPPayload(3478, 443, []byte("hello"))) // MF set, offset 0
	p, ok := parsePacket(pkt)
	if !ok {
		t.Fatal("first fragment carries the transport header and must parse")
	}
	if p.SrcPort != 3478 || p.DstPort != 443 {
		t.Fatalf("ports = %d->%d, want 3478->443", p.SrcPort, p.DstPort)
	}
}

func TestParseIPv6NonFirstFragmentHasNoPorts(t *testing.T) {
	payload := []byte{0x01, 0xbb, 0x00, 0x35, 0x00, 0x10, 0x00, 0x00}
	pkt := mkIPv6FragmentPacket(17, 3, payload)
	p, ok := parsePacket(pkt)
	if !ok {
		t.Fatal("IPv6 non-first fragment must still be counted")
	}
	if p.SrcPort != 0 || p.DstPort != 0 {
		t.Fatalf("fragment ports = %d->%d, want 0->0", p.SrcPort, p.DstPort)
	}
	if p.Proto != 17 {
		t.Fatalf("proto = %d, want 17", p.Proto)
	}
}

func TestParseIPv6FirstFragmentParsesPorts(t *testing.T) {
	pkt := mkIPv6FragmentPacket(17, 0, mkUDPPayload(1234, 53, []byte("q")))
	p, ok := parsePacket(pkt)
	if !ok {
		t.Fatal("IPv6 first fragment must parse")
	}
	if p.SrcPort != 1234 || p.DstPort != 53 {
		t.Fatalf("ports = %d->%d, want 1234->53", p.SrcPort, p.DstPort)
	}
}
