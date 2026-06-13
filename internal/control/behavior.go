package control

import (
	"strings"
	"sync"
	"time"
)

// Behaviour guardrail modes.
const (
	BehaviorOff     = "off"     // disabled (also the empty value)
	BehaviorObserve = "observe" // audits anomalies only; does not block
	BehaviorEnforce = "enforce" // anomalies escalate to approval; rate exceeded is denied
)

// BehaviorConfig configures per-agent behaviour guardrails.
type BehaviorConfig struct {
	// Mode: "off"|"observe"|"enforce".
	Mode string `json:"mode,omitempty"`
	// RateLimitPerMin: maximum requests per subject per minute (0 = no limit).
	RateLimitPerMin int `json:"rate_limit_per_min,omitempty"`
}

// BehaviorTracker detects deviations from each agent's normal behaviour: rate
// spikes, previously unseen hosts, and commands outside its history. It is
// rule/statistics-based (no ML). State lives in memory (warmed at runtime);
// restarting the control plane resets the baseline.
type BehaviorTracker struct {
	mu       sync.Mutex
	cfg      BehaviorConfig
	subjects map[string]*subjectState
}

type subjectState struct {
	events []time.Time         // sliding window of request timestamps (for rate)
	hosts  map[string]struct{} // seen hosts
	cmds   map[string]struct{} // seen command fingerprints (first token)
}

// NewBehaviorTracker creates a tracker with the given configuration.
func NewBehaviorTracker(cfg BehaviorConfig) *BehaviorTracker {
	return &BehaviorTracker{cfg: cfg, subjects: make(map[string]*subjectState)}
}

// Enabled reports whether guardrails are active (observe or enforce).
func (t *BehaviorTracker) Enabled() bool {
	return t.cfg.Mode == BehaviorObserve || t.cfg.Mode == BehaviorEnforce
}

// Enforcing reports whether the mode is enforce (blocks/escalates instead of
// only auditing).
func (t *BehaviorTracker) Enforcing() bool { return t.cfg.Mode == BehaviorEnforce }

// Check records a request from the subject (the authenticated broker CN,
// optionally qualified with a trusted end user — see the control plane's
// guardrailSubject) and returns detected anomalies and whether the rate limit
// has been exceeded. The first
// request from a subject establishes the baseline: new-host/new-command are
// not flagged (only on subsequent requests with novel host/command).
func (t *BehaviorTracker) Check(subject, host, command string) (anomalies []string, exceeded bool) {
	if !t.Enabled() {
		return nil, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	st, seen := t.subjects[subject]
	if !seen {
		st = &subjectState{hosts: map[string]struct{}{}, cmds: map[string]struct{}{}}
		t.subjects[subject] = st
	}
	now := time.Now()

	// Rate limit (1-minute sliding window). Blocked attempts are also counted
	// to prevent rate-limit evasion.
	if t.cfg.RateLimitPerMin > 0 {
		cutoff := now.Add(-time.Minute)
		kept := st.events[:0]
		for _, e := range st.events {
			if e.After(cutoff) {
				kept = append(kept, e)
			}
		}
		st.events = append(kept, now)
		if len(st.events) > t.cfg.RateLimitPerMin {
			exceeded = true
			anomalies = append(anomalies, "rate-exceeded")
		}
	}

	// Novel host/command: only after the baseline is established (subject already
	// seen).
	fp := firstToken(command)
	if seen {
		if _, ok := st.hosts[host]; !ok {
			anomalies = append(anomalies, "new-host:"+host)
		}
		if fp != "" {
			if _, ok := st.cmds[fp]; !ok {
				anomalies = append(anomalies, "new-command:"+fp)
			}
		}
	}
	st.hosts[host] = struct{}{}
	if fp != "" {
		st.cmds[fp] = struct{}{}
	}
	return anomalies, exceeded
}

// firstToken returns the first token (the program name) of a command, used as
// a fingerprint. E.g. "systemctl restart nginx" → "systemctl".
func firstToken(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
