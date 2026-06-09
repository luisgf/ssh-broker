// Package recording writes interactive session output in ASCIIcast v2 format.
// One .cast file is produced per session, named <session_id>.cast inside the
// configured recording directory.
//
// ASCIIcast v2 spec: https://docs.asciinema.org/manual/asciicast/v2/
// The header includes a private "ssh_broker" extension field with session
// metadata, so the file is self-describing without the audit log.
package recording

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Meta holds the session metadata written to the ASCIIcast header.
type Meta struct {
	SessionID string
	Caller    string
	Host      string
	Serial    uint64
	PTY       bool
	Term      string // terminal type, e.g. "xterm-256color"
	Width     int    // terminal columns
	Height    int    // terminal rows
	StartedAt time.Time
}

// header is the ASCIIcast v2 header (first line of the file).
type header struct {
	Version   int            `json:"version"`
	Width     int            `json:"width"`
	Height    int            `json:"height"`
	Timestamp int64          `json:"timestamp"`
	Title     string         `json:"title"`
	Env       map[string]any `json:"env,omitempty"`
	SSHBroker brokerMeta     `json:"ssh_broker"`
}

type brokerMeta struct {
	SessionID string `json:"session_id"`
	Caller    string `json:"caller"`
	Host      string `json:"host"`
	Serial    uint64 `json:"serial"`
	StartedAt string `json:"started_at"`
}

// Recorder writes an ASCIIcast v2 recording file for a single session.
// All methods are safe for concurrent use.
type Recorder struct {
	mu      sync.Mutex
	f       *os.File
	started time.Time
}

// Open creates a new recording file at path and writes the ASCIIcast header.
func Open(path string, m Meta) (*Recorder, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("recording: open %s: %w", path, err)
	}

	width := m.Width
	if width <= 0 {
		width = 220
	}
	height := m.Height
	if height <= 0 {
		height = 40
	}
	term := m.Term
	if term == "" {
		term = "xterm-256color"
	}

	now := m.StartedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	h := header{
		Version:   2,
		Width:     width,
		Height:    height,
		Timestamp: now.Unix(),
		Title:     fmt.Sprintf("session %s — %s@%s", m.SessionID, m.Caller, m.Host),
		Env:       map[string]any{"TERM": term},
		SSHBroker: brokerMeta{
			SessionID: m.SessionID,
			Caller:    m.Caller,
			Host:      m.Host,
			Serial:    m.Serial,
			StartedAt: now.Format(time.RFC3339),
		},
	}

	hLine, err := json.Marshal(h)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("recording: marshal header: %w", err)
	}
	if _, err := fmt.Fprintf(f, "%s\n", hLine); err != nil {
		f.Close()
		return nil, fmt.Errorf("recording: write header: %w", err)
	}

	// Deltas are relative to the actual wall-clock start, not the header
	// timestamp (which may be a fixed value in tests or a replayed session).
	return &Recorder{f: f, started: time.Now()}, nil
}

// WriteOutput records a chunk of stdout (or merged PTY output) as type "o".
func (r *Recorder) WriteOutput(data string) error {
	return r.write("o", data)
}

// WriteInput records a chunk of stdin as type "i".
func (r *Recorder) WriteInput(data string) error {
	return r.write("i", data)
}

// WriteStderr records a chunk of stderr as type "e".
func (r *Recorder) WriteStderr(data string) error {
	return r.write("e", data)
}

// Close flushes and closes the recording file.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// write appends one ASCIIcast event line: [delta, type, data].
// Delta is in seconds relative to session start, with millisecond precision.
func (r *Recorder) write(eventType, data string) error {
	if data == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	delta := time.Since(r.started).Seconds()
	line, err := json.Marshal([]any{delta, eventType, data})
	if err != nil {
		return fmt.Errorf("recording: marshal event: %w", err)
	}
	_, err = fmt.Fprintf(r.f, "%s\n", line)
	return err
}
