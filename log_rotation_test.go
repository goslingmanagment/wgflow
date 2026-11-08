package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func logLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))
}

// A logrotate rename must not swallow records: before the reopen they follow
// the renamed file, after it they go to a fresh file at the original path.
func TestJSONLoggerFollowsRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tls.jsonl")
	l, err := NewJSONLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if err := l.ReopenIfRotated(); err != nil { // not rotated: keeps the file
		t.Fatal(err)
	}
	l.Write(1)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	l.Write(2)                                             // between the rename and the next flush
	if err := os.WriteFile(path, nil, 0o644); err != nil { // logrotate "create"
		t.Fatal(err)
	}
	if err := l.ReopenIfRotated(); err != nil {
		t.Fatal(err)
	}
	l.Write(3)

	if got := logLines(t, path+".1"); strings.Join(got, ",") != "1,2" {
		t.Fatalf("rotated file = %v, want [1 2]", got)
	}
	if got := logLines(t, path); strings.Join(got, ",") != "3" {
		t.Fatalf("new file = %v, want [3]", got)
	}

	// Deleted outright (no "create"): the logger recreates the path.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := l.ReopenIfRotated(); err != nil {
		t.Fatal(err)
	}
	l.Write(4)
	if got := logLines(t, path); strings.Join(got, ",") != "4" {
		t.Fatalf("recreated file = %v, want [4]", got)
	}
}

// A window that crosses the rotation reads on into <log>.1; one that ends
// inside the current file never touches it.
func TestScanLogReverseContinuesIntoRotated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dns.jsonl")
	if err := os.WriteFile(path+".1", []byte("1\n2\n3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("4\n5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	scan := func(stopAt string) []string {
		var seen []string
		if err := scanLogReverseContext(context.Background(), path, func(line []byte) bool {
			if string(line) == stopAt {
				return false
			}
			seen = append(seen, string(line))
			return true
		}); err != nil {
			t.Fatal(err)
		}
		return seen
	}
	if got := strings.Join(scan("1"), ","); got != "5,4,3,2" {
		t.Fatalf("crossing the rotation: %s, want 5,4,3,2", got)
	}
	if got := strings.Join(scan("4"), ","); got != "5" {
		t.Fatalf("inside the current file: %s, want 5", got)
	}
	if got := strings.Join(scan("none"), ","); got != "5,4,3,2,1" {
		t.Fatalf("whole history: %s, want 5,4,3,2,1", got)
	}
	// No rotated file yet (first day, or copytruncate's .1.gz): current only.
	if err := os.Remove(path + ".1"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(scan("none"), ","); got != "5,4" {
		t.Fatalf("without .1: %s, want 5,4", got)
	}
}
