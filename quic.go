package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
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
	for off := 0; off < len(datagram); {
		if len(datagram)-off < 7 || datagram[off]&0x80 == 0 {
			return ""
		}
		first := datagram[off]
		version := binary.BigEndian.Uint32(datagram[off+1 : off+5])
		pos := off + 5
		dcidLen := int(datagram[pos])
		pos++
		if dcidLen == 0 || pos+dcidLen > len(datagram) {
			return ""
		}
		dcid := datagram[pos : pos+dcidLen]
		pos += dcidLen
		if pos >= len(datagram) {
			return ""
		}
		scidLen := int(datagram[pos])
		pos++
		if pos+scidLen > len(datagram) {
			return ""
		}
		pos += scidLen
		tokenLen, next, ok := readQUICVarInt(datagram, pos)
		if !ok || tokenLen > uint64(len(datagram)-next) {
			return ""
		}
		pos = next + int(tokenLen)
		packetLen, next, ok := readQUICVarInt(datagram, pos)
		if !ok || packetLen > uint64(len(datagram)-next) {
			return ""
		}
		pnOffset := next
		packetEnd := pnOffset + int(packetLen)
		if first&0x30 == 0x00 {
			if plaintext, ok := decryptQUICInitial(datagram, off, pnOffset, packetEnd, version, dcid); ok {
				if sni := parseQUICCryptoSNI(plaintext); sni != "" {
					return sni
				}
			}
		}
		off = packetEnd
	}
	return ""
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

func parseQUICCryptoSNI(plain []byte) string {
	for off := 0; off < len(plain); {
		typ, next, ok := readQUICVarInt(plain, off)
		if !ok {
			return ""
		}
		off = next
		switch typ {
		case 0x00, 0x01: // PADDING, PING
			continue
		case 0x02, 0x03: // ACK, ACK_ECN
			var ok bool
			off, ok = skipQUICAckFrame(plain, off, typ == 0x03)
			if !ok {
				return ""
			}
		case 0x06: // CRYPTO
			cryptoOff, next, ok := readQUICVarInt(plain, off)
			if !ok {
				return ""
			}
			ln, next, ok := readQUICVarInt(plain, next)
			if !ok || ln > uint64(len(plain)-next) {
				return ""
			}
			data := plain[next : next+int(ln)]
			off = next + int(ln)
			if cryptoOff != 0 {
				continue
			}
			if sni := parseTLSHandshakeSNI(data); sni != "" {
				return sni
			}
			if sni := parseTLSSNI(data); sni != "" {
				return sni
			}
		default:
			return ""
		}
	}
	return ""
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
