package main

import (
	"encoding/binary"
	"strings"
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

func parseTLSSNI(payload []byte) string {
	if len(payload) < 9 || payload[0] != 22 {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if recLen <= 0 || 5+recLen > len(payload) {
		return ""
	}
	hs := payload[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 1 {
		return ""
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if hsLen <= 0 || 4+hsLen > len(hs) {
		return ""
	}
	return parseTLSClientHelloSNI(hs[4 : 4+hsLen])
}

func parseTLSHandshakeSNI(data []byte) string {
	if len(data) < 4 || data[0] != 1 {
		return ""
	}
	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if hsLen <= 0 || 4+hsLen > len(data) {
		return ""
	}
	return parseTLSClientHelloSNI(data[4 : 4+hsLen])
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

func validHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, " \t\r\n/") {
		return false
	}
	return strings.Contains(s, ".")
}
