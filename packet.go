package main

import (
	"encoding/binary"
	"net"
	"strconv"
)

type packetInfo struct {
	SrcIP, DstIP     net.IP
	Proto            uint8
	SrcPort, DstPort uint16
	// TCPSeq is the raw TCP sequence number (proto 6 only). The ClientHello
	// reassembler uses it to accept only segments that strictly continue the
	// buffered stream — without it, retransmits and reordering would silently
	// corrupt the assembled handshake.
	TCPSeq           uint32
	TransportPayload []byte
	Length           int
}

func parsePacket(b []byte) (packetInfo, bool) {
	if len(b) < 1 {
		return packetInfo{}, false
	}
	switch b[0] >> 4 {
	case 4:
		return parseIPv4(b)
	case 6:
		return parseIPv6(b)
	default:
		return packetInfo{}, false
	}
}

func parseIPv4(b []byte) (packetInfo, bool) {
	if len(b) < 20 {
		return packetInfo{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return packetInfo{}, false
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total <= 0 || total > len(b) {
		total = len(b)
	}
	// A crafted total_length smaller than the header would make b[ihl:total]
	// panic with an inverted slice range and take the daemon down.
	if total < ihl {
		return packetInfo{}, false
	}
	proto := b[9]
	p := packetInfo{
		SrcIP:  append(net.IP(nil), b[12:16]...),
		DstIP:  append(net.IP(nil), b[16:20]...),
		Proto:  proto,
		Length: total,
	}
	// Non-first fragments carry no transport header; parsing their payload as
	// ports would fabricate phantom flows. Keep the packet (bytes must still
	// be accounted) but leave ports zero.
	if fragOffset := binary.BigEndian.Uint16(b[6:8]) & 0x1fff; fragOffset != 0 {
		return p, true
	}
	payload := b[ihl:total]
	if !parsePorts(&p, payload) {
		return packetInfo{}, false
	}
	return p, true
}

func parseIPv6(b []byte) (packetInfo, bool) {
	if len(b) < 40 {
		return packetInfo{}, false
	}
	payloadLen := int(binary.BigEndian.Uint16(b[4:6]))
	end := 40 + payloadLen
	if end > len(b) {
		end = len(b)
	}
	next := b[6]
	off := 40
	fragmented := false
	for {
		switch next {
		case 0, 43, 60:
			if off+2 > end {
				return packetInfo{}, false
			}
			next = b[off]
			off += (int(b[off+1]) + 1) * 8
		case 44:
			if off+8 > end {
				return packetInfo{}, false
			}
			next = b[off]
			// Fragment offset lives in the upper 13 bits of bytes 2-3; a
			// non-zero offset means the transport header is in another packet.
			if binary.BigEndian.Uint16(b[off+2:off+4])>>3 != 0 {
				fragmented = true
			}
			off += 8
		default:
			goto done
		}
		if off > end {
			return packetInfo{}, false
		}
	}
done:
	p := packetInfo{
		SrcIP:  append(net.IP(nil), b[8:24]...),
		DstIP:  append(net.IP(nil), b[24:40]...),
		Proto:  next,
		Length: end,
	}
	// Same as IPv4: count non-first fragments but never guess ports from
	// payload bytes that are not a transport header.
	if fragmented {
		return p, true
	}
	if !parsePorts(&p, b[off:end]) {
		return packetInfo{}, false
	}
	return p, true
}

func parsePorts(p *packetInfo, payload []byte) bool {
	switch p.Proto {
	case 6:
		if len(payload) < 20 {
			return false
		}
		p.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		p.DstPort = binary.BigEndian.Uint16(payload[2:4])
		p.TCPSeq = binary.BigEndian.Uint32(payload[4:8])
		off := int(payload[12]>>4) * 4
		if off < 20 || off > len(payload) {
			return false
		}
		p.TransportPayload = payload[off:]
		return true
	case 17:
		if len(payload) < 8 {
			return false
		}
		p.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		p.DstPort = binary.BigEndian.Uint16(payload[2:4])
		p.TransportPayload = payload[8:]
		return true
	default:
		return false
	}
}

func protoName(p uint8) string {
	if p == 6 {
		return "tcp"
	}
	if p == 17 {
		return "udp"
	}
	return strconv.Itoa(int(p))
}
