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

// testHTTPSAnswerMsg builds a response with one HTTPS (or SVCB) answer whose
// RDATA is provided raw, so tests control priority/target/params precisely.
func testHTTPSAnswerMsg(qname string, typ uint16, rdata []byte) []byte {
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	msg = appendDNSNameTest(msg, qname)
	msg = append(msg, byte(typ>>8), byte(typ), 0x00, 0x01) // question
	msg = append(msg,
		0xc0, 0x0c, // answer owner -> question name
		byte(typ>>8), byte(typ),
		0x00, 0x01, // IN
		0x00, 0x00, 0x0e, 0x10, // TTL 3600
		byte(len(rdata)>>8), byte(len(rdata)),
	)
	return append(msg, rdata...)
}

func TestParseDNSAnswerHTTPSWithHints(t *testing.T) {
	rdata := []byte{0x00, 0x01} // ServiceMode, priority 1
	rdata = append(rdata, 0x00) // TargetName "." = owner
	rdata = append(rdata,
		0x00, 0x01, 0x00, 0x03, 'h', '2', 0x02, // alpn (skipped by length... key=1 len=3)
	)
	rdata = append(rdata,
		0x00, 0x04, 0x00, 0x08, // ipv4hint, two addresses
		192, 0, 2, 10,
		192, 0, 2, 11,
	)
	rdata = append(rdata,
		0x00, 0x06, 0x00, 0x10, // ipv6hint, one address
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99,
	)
	msg := testHTTPSAnswerMsg("api.example.com", 65, rdata)
	parsed, ok := parseDNSMessage(msg)
	if !ok || len(parsed.Answers) != 1 {
		t.Fatalf("parse = %+v ok=%v, want one answer", parsed.Answers, ok)
	}
	ans := parsed.Answers[0]
	if ans.Type != "HTTPS" || ans.Name != "api.example.com" || ans.TTL != 3600 {
		t.Fatalf("answer = %+v", ans)
	}
	if ans.Value != "api.example.com" {
		t.Fatalf("ServiceMode root target must resolve to owner, got %q", ans.Value)
	}
	want := []string{"192.0.2.10", "192.0.2.11", "2001:db8::99"}
	if len(ans.Hints) != len(want) {
		t.Fatalf("hints = %v, want %v", ans.Hints, want)
	}
	for i := range want {
		if ans.Hints[i] != want[i] {
			t.Fatalf("hints[%d] = %q, want %q", i, ans.Hints[i], want[i])
		}
	}
}

func TestParseDNSAnswerSVCBTargetName(t *testing.T) {
	rdata := []byte{0x00, 0x02} // ServiceMode, priority 2
	rdata = appendDNSNameTest(rdata, "svc.cdn.example.net")
	rdata = append(rdata,
		0x00, 0x04, 0x00, 0x04,
		198, 51, 100, 7,
	)
	msg := testHTTPSAnswerMsg("_dns.example.com", 64, rdata)
	parsed, ok := parseDNSMessage(msg)
	if !ok || len(parsed.Answers) != 1 {
		t.Fatalf("parse = %+v ok=%v, want one answer", parsed.Answers, ok)
	}
	ans := parsed.Answers[0]
	if ans.Type != "SVCB" || ans.Value != "svc.cdn.example.net" {
		t.Fatalf("answer = %+v", ans)
	}
	if len(ans.Hints) != 1 || ans.Hints[0] != "198.51.100.7" {
		t.Fatalf("hints = %v, want [198.51.100.7]", ans.Hints)
	}
}

func TestParseDNSAnswerHTTPSAliasMode(t *testing.T) {
	rdata := []byte{0x00, 0x00} // AliasMode
	rdata = appendDNSNameTest(rdata, "alias.example.org")
	// SvcParams are forbidden in AliasMode; anything trailing is ignored.
	rdata = append(rdata, 0x00, 0x04, 0x00, 0x04, 203, 0, 113, 5)
	msg := testHTTPSAnswerMsg("www.example.com", 65, rdata)
	parsed, ok := parseDNSMessage(msg)
	if !ok || len(parsed.Answers) != 1 {
		t.Fatalf("parse = %+v ok=%v, want one answer", parsed.Answers, ok)
	}
	ans := parsed.Answers[0]
	if ans.Value != "alias.example.org" {
		t.Fatalf("alias target = %q, want alias.example.org", ans.Value)
	}
	if len(ans.Hints) != 0 {
		t.Fatalf("AliasMode must not yield hints, got %v", ans.Hints)
	}
}

func TestParseDNSAnswerHTTPSTruncatedParams(t *testing.T) {
	rdata := []byte{0x00, 0x01}
	rdata = append(rdata, 0x00) // target "."
	rdata = append(rdata,
		0x00, 0x04, 0x00, 0x08, // claims 8 bytes of ipv4hint...
		192, 0, 2, 44, // ...but only 4 are present
	)
	msg := testHTTPSAnswerMsg("cut.example.com", 65, rdata)
	parsed, ok := parseDNSMessage(msg)
	if !ok || len(parsed.Answers) != 1 {
		t.Fatalf("parse = %+v ok=%v, want one answer", parsed.Answers, ok)
	}
	if hints := parsed.Answers[0].Hints; len(hints) != 0 {
		t.Fatalf("truncated ipv4hint must be discarded, got %v", hints)
	}
}

// A SvcParam whose declared length runs past the RDATA end must never read
// the following record's bytes as hint addresses.
func TestParseDNSAnswerHTTPSParamMustNotLeakPastRData(t *testing.T) {
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00}
	msg = appendDNSNameTest(msg, "cut.example.com")
	msg = append(msg, 0x00, 0x41, 0x00, 0x01) // question HTTPS IN
	// Answer 1: HTTPS whose ipv4hint claims 8 bytes but RDATA ends after the
	// param header — the "value" would be the next record's bytes.
	rdata := []byte{0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x08}
	msg = append(msg, 0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, byte(len(rdata)))
	msg = append(msg, rdata...)
	// Answer 2: A 10.0.0.1, immediately after.
	msg = append(msg, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 10, 0, 0, 1)
	parsed, ok := parseDNSMessage(msg)
	if !ok || len(parsed.Answers) != 2 {
		t.Fatalf("parse = %+v ok=%v, want two answers", parsed.Answers, ok)
	}
	for _, ans := range parsed.Answers {
		for _, h := range ans.Hints {
			if h == "10.0.0.1" {
				t.Fatalf("hint leaked past RDATA boundary: %+v", ans)
			}
		}
	}
	if parsed.Answers[1].Type != "A" || parsed.Answers[1].Value != "10.0.0.1" {
		t.Fatalf("trailing A answer damaged: %+v", parsed.Answers[1])
	}
}

func TestParseDNSAnswerHTTPSHintCap(t *testing.T) {
	rdata := []byte{0x00, 0x01, 0x00} // priority 1, target "."
	count := maxSvcParamHints + 8
	rdata = append(rdata, 0x00, 0x04, byte(count*4>>8), byte(count*4))
	for i := 0; i < count; i++ {
		rdata = append(rdata, 10, 0, byte(i>>8), byte(i))
	}
	msg := testHTTPSAnswerMsg("many.example.com", 65, rdata)
	parsed, ok := parseDNSMessage(msg)
	if !ok || len(parsed.Answers) != 1 {
		t.Fatalf("parse = %+v ok=%v, want one answer", parsed.Answers, ok)
	}
	if got := len(parsed.Answers[0].Hints); got != maxSvcParamHints {
		t.Fatalf("hints = %d, want capped at %d", got, maxSvcParamHints)
	}
}

func appendDNSNameTest(dst []byte, name string) []byte {
	for _, label := range strings.Split(name, ".") {
		dst = append(dst, byte(len(label)))
		dst = append(dst, label...)
	}
	return append(dst, 0x00)
}
