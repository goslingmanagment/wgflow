package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

func TestParseQUICSNI(t *testing.T) {
	packet := testQUICInitialPacket(t, "firebaseappcheck.googleapis.com")
	if got := parseQUICSNI(packet); got != "firebaseappcheck.googleapis.com" {
		t.Fatalf("parseQUICSNI = %q, want firebaseappcheck.googleapis.com", got)
	}
}

func testQUICInitialPacket(t *testing.T, host string) []byte {
	t.Helper()
	_, handshake := testTLSClientHello(host)
	plain := []byte{0x06, 0x00} // CRYPTO, offset=0
	plain = append(plain, encodeQUICVarIntTest(uint64(len(handshake)))...)
	plain = append(plain, handshake...)
	for len(plain) < 160 {
		plain = append(plain, 0x00)
	}

	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	key, iv, hp, ok := quicInitialKeys(0x00000001, dcid)
	if !ok {
		t.Fatal("missing quic v1 keys")
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
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := append([]byte(nil), iv...)
	nonce[len(nonce)-1] ^= 0x01
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
