package main

import "testing"

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
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)                   // session_id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites
	body = append(body, 0x01, 0x00)             // compression_methods
	serverName := []byte{0x00, byte(len(host) >> 8), byte(len(host))}
	serverName = append(serverName, []byte(host)...)
	sniData := []byte{byte(len(serverName) >> 8), byte(len(serverName))}
	sniData = append(sniData, serverName...)
	ext := []byte{0x00, 0x00, byte(len(sniData) >> 8), byte(len(sniData))}
	ext = append(ext, sniData...)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	handshake = []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record = []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	record = append(record, handshake...)
	return record, handshake
}
