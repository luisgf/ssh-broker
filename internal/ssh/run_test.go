package ssh

import (
	"io"
	"strings"
	"testing"
)

// TestLimitedWriterConsumesAllBytes verifies the io.Writer contract: every
// Write must report the full slice as consumed (n == len(p), nil error) even
// past the cap, otherwise io.Copy inside x/crypto/ssh aborts with
// ErrShortWrite instead of delivering truncated output.
func TestLimitedWriterConsumesAllBytes(t *testing.T) {
	t.Parallel()

	lw := &limitedWriter{max: 8}
	writes := []struct {
		name string
		p    string
	}{
		{"under cap", "abc"},
		{"crosses cap", "defghij"}, // 3 already buffered, only 5 fit
		{"past cap", "klmno"},
		{"empty past cap", ""},
	}
	for _, w := range writes {
		n, err := lw.Write([]byte(w.p))
		if err != nil {
			t.Fatalf("%s: Write returned error: %v", w.name, err)
		}
		if n != len(w.p) {
			t.Fatalf("%s: Write consumed %d bytes, want %d", w.name, n, len(w.p))
		}
	}
	if got := lw.buf.String(); got != "abcdefgh" {
		t.Errorf("buffered = %q, want %q", got, "abcdefgh")
	}
	if !lw.truncated {
		t.Error("truncated flag must be set after writing past the cap")
	}
}

// TestLimitedWriterIOCopy verifies that io.Copy over a limitedWriter never
// fails (the original bug: n < len(p) with nil error made io.Copy return
// ErrShortWrite at the cap).
func TestLimitedWriterIOCopy(t *testing.T) {
	t.Parallel()

	lw := &limitedWriter{max: 16}
	src := strings.Repeat("x", 1024)
	n, err := io.Copy(lw, strings.NewReader(src))
	if err != nil {
		t.Fatalf("io.Copy must not fail at the cap: %v", err)
	}
	if n != int64(len(src)) {
		t.Errorf("io.Copy copied %d bytes, want %d", n, len(src))
	}
	if lw.buf.Len() != 16 {
		t.Errorf("buffer holds %d bytes, want %d (the cap)", lw.buf.Len(), 16)
	}
	if !lw.truncated {
		t.Error("truncated flag must be set")
	}
}

// TestLimitedWriterOutputMarker verifies the truncation marker in output().
func TestLimitedWriterOutputMarker(t *testing.T) {
	t.Parallel()

	// Not truncated: output is exactly what was written.
	lw := &limitedWriter{max: 8}
	_, _ = lw.Write([]byte("hi"))
	if got := lw.output(); got != "hi" {
		t.Errorf("output() = %q, want %q", got, "hi")
	}

	// Truncated: output carries the captured prefix plus an explicit marker.
	_, _ = lw.Write([]byte("0123456789"))
	got := lw.output()
	if !strings.HasPrefix(got, "hi012345") {
		t.Errorf("output() = %q, want prefix %q", got, "hi012345")
	}
	if !strings.Contains(got, "output truncated") {
		t.Errorf("output() = %q, want a truncation marker", got)
	}
}
