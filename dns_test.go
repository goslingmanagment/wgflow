package main

import (
	"strings"
	"testing"
)

// Regression: a CNAME whose RDATA is truncated mid-label used to be parsed
// against the whole message, so the name "leaked" into bytes belonging to the
// next record.
func TestParseDNSAnswerCNAMEBoundedByRData(t *testing.T) {
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	msg = appendDNSNameTest(msg, "a.example.com")
	msg = append(msg, 0x00, 0x05, 0x00, 0x01) // question CNAME IN
	msg = append(msg,
		0xc0, 0x0c, // answer owner -> question name
		0x00, 0x05, // CNAME
		0x00, 0x01, // IN
		0x00, 0x00, 0x01, 0x2c, // TTL 300
		0x00, 0x03, // rdlength 3: label header + only 2 of 6 label bytes
		0x06, 'l', 'e',
	)
	// Bytes past the RDATA that the old parser consumed as the rest of the label.
	msg = append(msg, 'a', 'k', 'e', 'd', 0x00)
	parsed, ok := parseDNSMessage(msg)
	if !ok {
		t.Fatal("message with one broken answer should still parse")
	}
	for _, ans := range parsed.Answers {
		if strings.Contains(ans.Value, "leaked") {
			t.Fatalf("CNAME leaked past RDATA: %+v", ans)
		}
	}
	if len(parsed.Answers) != 0 {
		t.Fatalf("truncated CNAME must be dropped, got %+v", parsed.Answers)
	}
}

// A CNAME that legitimately compresses back into the question must keep working
// with the RDATA bound in place.
func TestParseDNSAnswerCNAMECompressionStillWorks(t *testing.T) {
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	msg = appendDNSNameTest(msg, "a.example.com")
	msg = append(msg, 0x00, 0x05, 0x00, 0x01)
	msg = append(msg,
		0xc0, 0x0c,
		0x00, 0x05,
		0x00, 0x01,
		0x00, 0x00, 0x01, 0x2c,
		0x00, 0x06, // rdlength: "cdn" label + pointer to question name
		0x03, 'c', 'd', 'n', 0xc0, 0x0c,
	)
	parsed, ok := parseDNSMessage(msg)
	if !ok || len(parsed.Answers) != 1 {
		t.Fatalf("parse = %+v ok=%v, want one answer", parsed.Answers, ok)
	}
	if parsed.Answers[0].Value != "cdn.a.example.com" {
		t.Fatalf("CNAME value = %q, want cdn.a.example.com", parsed.Answers[0].Value)
	}
}

// Control bytes in labels must never reach top/report output or the
// tab-separated rollup key.
func TestParseDNSNameSanitizesControlBytes(t *testing.T) {
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	msg = append(msg, 0x07, 'a', 0x09, 0x1b, '[', '3', '1', 'm') // label with TAB and ESC
	msg = appendDNSNameTest(msg, "example.com")                  // remaining labels + root
	msg = append(msg, 0x00, 0x01, 0x00, 0x01)
	parsed, ok := parseDNSMessage(msg)
	if !ok {
		t.Fatal("parseDNSMessage failed")
	}
	if parsed.Query != "a??[31m.example.com" {
		t.Fatalf("query = %q, want control bytes replaced with '?'", parsed.Query)
	}
	if strings.ContainsAny(parsed.Query, "\t\x1b") {
		t.Fatalf("query still contains control bytes: %q", parsed.Query)
	}
}

func TestParseDNSMessageAnswerNames(t *testing.T) {
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	msg = appendDNSNameTest(msg, "photos.example.com")
	msg = append(msg, 0x00, 0x01, 0x00, 0x01) // question A IN
	msg = append(msg,
		0xc0, 0x0c, // answer owner -> question name
		0x00, 0x01, // A
		0x00, 0x01, // IN
		0x00, 0x00, 0x01, 0x2c, // TTL 300
		0x00, 0x04,
		192, 0, 2, 55,
	)
	parsed, ok := parseDNSMessage(msg)
	if !ok {
		t.Fatal("parseDNSMessage failed")
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(parsed.Answers))
	}
	ans := parsed.Answers[0]
	if ans.Name != "photos.example.com" || ans.Type != "A" || ans.Value != "192.0.2.55" || ans.TTL != 300 {
		t.Fatalf("answer = %+v", ans)
	}
}

func appendDNSNameTest(dst []byte, name string) []byte {
	for _, label := range strings.Split(name, ".") {
		dst = append(dst, byte(len(label)))
		dst = append(dst, label...)
	}
	return append(dst, 0x00)
}
