// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package journal writes the JSON-lines spotter log.
// The environment is never written. Callers redact argv first.
package journal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gtwy/spotter-sh"
	"github.com/gtwy/spotter-sh/internal/redact"
)

// Event is one log line.
type Event struct {
	Ts        string   `json:"ts"`
	Event     string   `json:"event"`
	Level     string   `json:"level,omitempty"`
	Cmd       string   `json:"cmd,omitempty"`
	Argv      []string `json:"argv,omitempty"`
	Cwd       string   `json:"cwd,omitempty"`
	Case      string   `json:"case,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	Targets   int      `json:"targets,omitempty"`
	Top       []string `json:"top,omitempty"`
	Decision  string   `json:"decision,omitempty"`
	Mode      string   `json:"mode,omitempty"`
	DecidedBy string   `json:"decided_by,omitempty"`
	Host      string   `json:"host,omitempty"`
	V         string   `json:"v"`
}

// Logger appends events when the level allows it.
type Logger struct {
	Path  string
	Level string // catch, all, off
	MaxMB int
}

var logMu sync.Mutex

// Write appends one event. Level "catch" skips plain allows.
func (l Logger) Write(ev Event, near bool) error {
	if l.Level == "off" || l.Path == "" {
		return nil
	}
	if l.Level != "all" && ev.Event == "allow" && !near {
		return nil
	}
	if ev.Ts == "" {
		ev.Ts = time.Now().Format(time.RFC3339)
	}
	if ev.V == "" {
		ev.V = spottersh.Version
	}
	ev = redactEvent(ev)
	buf, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	logMu.Lock()
	defer logMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o700); err != nil {
		return err
	}
	l.rotate()
	f, err := os.OpenFile(l.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(buf, '\n'))
	return err
}

func redactEvent(ev Event) Event {
	red := redact.New(nil)
	ev.Cmd = red.Apply(ev.Cmd)
	ev.Reason = red.Apply(ev.Reason)
	ev.Case = red.Apply(ev.Case)
	ev.Decision = red.Apply(ev.Decision)
	ev.DecidedBy = red.Apply(ev.DecidedBy)
	ev.Argv = red.Argv(ev.Argv)
	ev.Top = red.Argv(ev.Top)
	return ev
}

func (l Logger) rotate() {
	if l.MaxMB <= 0 {
		return
	}
	st, err := os.Stat(l.Path)
	if err != nil || st.Size() < int64(l.MaxMB)*1<<20 {
		return
	}
	_ = os.Rename(l.Path, l.Path+".1")
}

// Summary counts events. since may be zero.
func Summary(path string, since time.Time) (map[string]int, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]int{}, nil
		}
		return nil, err
	}
	counts := map[string]int{}
	for _, line := range splitLines(string(buf)) {
		if line == "" {
			continue
		}
		var ev Event
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		if !since.IsZero() && ev.Ts != "" {
			t, err := time.Parse(time.RFC3339, ev.Ts)
			if err == nil && t.Before(since) {
				continue
			}
		}
		counts[ev.Event]++
		if ev.Cmd != "" {
			counts["cmd:"+ev.Cmd]++
		}
	}
	return counts, nil
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
