package main

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"time"
)

type DNSAnswer struct {
	Name  string `json:"name,omitempty"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
	// Hints are the ipv4hint/ipv6hint addresses of an HTTPS/SVCB answer.
	// Clients connect straight to these IPs without a separate A/AAAA round
	// trip, so they feed the DomainCache exactly like A/AAAA values do.
	Hints []string `json:"hints,omitempty"`
}

type DNSRecord struct {
	TS        time.Time   `json:"ts"`
	Interface string      `json:"interface"`
	Client    string      `json:"client"`
	ClientIP  string      `json:"client_ip"`
	ServerIP  string      `json:"server_ip"`
	Proto     string      `json:"proto"`
	Query     string      `json:"query"`
	QType     string      `json:"qtype"`
	RCode     int         `json:"rcode"`
	Response  bool        `json:"response"`
	Answers   []DNSAnswer `json:"answers,omitempty"`
}

func parseDNSPacket(ts time.Time, iface, client, clientIP, serverIP, proto string, outbound bool, pkt packetInfo) (*DNSRecord, []DNSAnswer) {
	msg := pkt.TransportPayload
	if proto == "tcp" {
		if len(msg) < 2 {
			return nil, nil
		}
		l := int(binary.BigEndian.Uint16(msg[:2]))
		if l <= 0 || l > len(msg)-2 {
			return nil, nil
		}
		msg = msg[2 : 2+l]
	}
	parsed, ok := parseDNSMessage(msg)
	if !ok || parsed.Query == "" {
		return nil, nil
	}
	rec := &DNSRecord{
		TS: ts, Interface: iface, Client: client, ClientIP: clientIP,
		ServerIP: serverIP, Proto: proto, Query: parsed.Query, QType: parsed.QType,
		RCode: parsed.RCode, Response: parsed.Response, Answers: parsed.Answers,
	}
	return rec, parsed.Answers
}

type dnsParsed struct {
	Query    string
	QType    string
	RCode    int
	Response bool
	Answers  []DNSAnswer
}

func parseDNSMessage(msg []byte) (dnsParsed, bool) {
	if len(msg) < 12 {
		return dnsParsed{}, false
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	var qname string
	var qtype uint16
	for i := 0; i < qd; i++ {
		name, next, ok := parseDNSName(msg, off, 0)
		if !ok || next+4 > len(msg) {
			return dnsParsed{}, false
		}
		qname = name
		qtype = binary.BigEndian.Uint16(msg[next : next+2])
		off = next + 4
	}
	var answers []DNSAnswer
	for i := 0; i < an && off < len(msg); i++ {
		name, next, ok := parseDNSName(msg, off, 0)
		if !ok || next+10 > len(msg) {
			return dnsParsed{}, false
		}
		typ := binary.BigEndian.Uint16(msg[next : next+2])
		ttl := binary.BigEndian.Uint32(msg[next+4 : next+8])
		rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rdataOff := next + 10
		if rdataOff+rdLen > len(msg) {
			return dnsParsed{}, false
		}
		if ans, ok := parseDNSAnswer(msg, name, typ, ttl, rdataOff, rdLen); ok {
			answers = append(answers, ans)
		}
		off = rdataOff + rdLen
	}
	return dnsParsed{
		Query:    strings.TrimSuffix(qname, "."),
		QType:    dnsType(qtype),
		RCode:    int(flags & 0x000f),
		Response: flags&0x8000 != 0,
		Answers:  answers,
	}, true
}

func parseDNSAnswer(msg []byte, name string, typ uint16, ttl uint32, off, ln int) (DNSAnswer, bool) {
	owner := strings.TrimSuffix(name, ".")
	switch typ {
	case 1:
		if ln == 4 {
			return DNSAnswer{Name: owner, Type: "A", Value: net.IP(msg[off : off+4]).String(), TTL: ttl}, true
		}
	case 28:
		if ln == 16 {
			return DNSAnswer{Name: owner, Type: "AAAA", Value: net.IP(msg[off : off+16]).String(), TTL: ttl}, true
		}
	case 5:
		// Bound the name at the end of this record's RDATA so a truncated or
		// crafted CNAME cannot read label bytes from the following record.
		// Compression pointers only reference earlier offsets, so they keep
		// working against the shortened slice.
		target, _, ok := parseDNSName(msg[:off+ln], off, 0)
		if ok {
			return DNSAnswer{Name: owner, Type: "CNAME", Value: strings.TrimSuffix(target, "."), TTL: ttl}, true
		}
	case 64, 65:
		return parseSVCBAnswer(msg, owner, typ, ttl, off, ln)
	}
	return DNSAnswer{}, false
}

// maxSvcParamHints caps address hints taken from one HTTPS/SVCB record. Real
// answers carry a handful; a crafted 64 KB RDATA could otherwise drive
// thousands of DomainCache insertions from a single packet.
const maxSvcParamHints = 32

// parseSVCBAnswer decodes SVCB (64) and HTTPS (65) RDATA per RFC 9460:
// SvcPriority, TargetName, then SvcParams. Only ipv4hint/ipv6hint params are
// extracted; everything else is skipped by length. All reads stay strictly
// inside [off, off+ln) — the input is attacker-controlled.
func parseSVCBAnswer(msg []byte, owner string, typ uint16, ttl uint32, off, ln int) (DNSAnswer, bool) {
	end := off + ln
	if ln < 3 { // priority (2) + at least a root label (1)
		return DNSAnswer{}, false
	}
	priority := binary.BigEndian.Uint16(msg[off : off+2])
	// Same RDATA bounding trick as CNAME above. RFC 9460 forbids compression
	// in TargetName, but tolerating (earlier-offset) pointers costs nothing.
	target, next, ok := parseDNSName(msg[:end], off+2, 0)
	if !ok {
		return DNSAnswer{}, false
	}
	target = strings.TrimSuffix(target, ".")
	if target == "" && priority != 0 {
		// In ServiceMode the root target means "the owner itself".
		target = owner
	}
	ans := DNSAnswer{Name: owner, Type: dnsType(typ), Value: target, TTL: ttl}
	if priority == 0 {
		// AliasMode: SvcParams are forbidden; ignore whatever follows.
		return ans, true
	}
	for next+4 <= end {
		key := binary.BigEndian.Uint16(msg[next : next+2])
		vlen := int(binary.BigEndian.Uint16(msg[next+2 : next+4]))
		if next+4+vlen > end {
			// Truncated param: keep what parsed cleanly, stop here.
			break
		}
		val := msg[next+4 : next+4+vlen]
		next += 4 + vlen
		switch key {
		case 4: // ipv4hint
			for i := 0; i+4 <= len(val) && len(ans.Hints) < maxSvcParamHints; i += 4 {
				ans.Hints = append(ans.Hints, net.IP(val[i:i+4]).String())
			}
		case 6: // ipv6hint
			for i := 0; i+16 <= len(val) && len(ans.Hints) < maxSvcParamHints; i += 16 {
				ans.Hints = append(ans.Hints, net.IP(val[i:i+16]).String())
			}
		}
	}
	return ans, true
}

func parseDNSName(msg []byte, off int, depth int) (string, int, bool) {
	if depth > 12 {
		return "", 0, false
	}
	var labels []string
	next := off
	for {
		if off >= len(msg) {
			return "", 0, false
		}
		l := int(msg[off])
		if l == 0 {
			off++
			next = off
			break
		}
		if l&0xc0 == 0xc0 {
			if off+1 >= len(msg) {
				return "", 0, false
			}
			pointerNext := off + 2
			ptr := ((l & 0x3f) << 8) | int(msg[off+1])
			name, _, ok := parseDNSName(msg, ptr, depth+1)
			if !ok {
				return "", 0, false
			}
			if name != "" {
				labels = append(labels, strings.Split(name, ".")...)
			}
			off += 2
			next = pointerNext
			break
		}
		off++
		if off+l > len(msg) {
			return "", 0, false
		}
		labels = append(labels, sanitizeDNSLabel(msg[off:off+l]))
		off += l
	}
	return strings.Join(labels, "."), next, true
}

// sanitizeDNSLabel copies a raw DNS label, replacing control bytes with '?'.
// Label bytes come straight off the wire from untrusted clients: a crafted
// query could otherwise inject terminal escapes into `top`/`report` output or
// a tab into the tab-separated rollup key.
func sanitizeDNSLabel(raw []byte) string {
	clean := make([]byte, len(raw))
	for i, c := range raw {
		if c < 0x20 || c == 0x7f {
			c = '?'
		}
		clean[i] = c
	}
	return string(clean)
}

func dnsType(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 28:
		return "AAAA"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	default:
		return strconv.Itoa(int(t))
	}
}
