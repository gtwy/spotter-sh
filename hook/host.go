// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package hook

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/gtwy/spotter-sh/internal/envx"
	"os"
	"path/filepath"
	"time"

	"github.com/gtwy/spotter-sh/internal/config"
	"github.com/gtwy/spotter-sh/internal/precheck"
	"github.com/gtwy/spotter-sh/internal/rollout"
	"github.com/gtwy/spotter-sh/internal/silentlog"
)

// Note is the identity and text for one silent-mode script log.
type Note struct {
	SessionID string
	TurnID    string
	Surface   string
	Sender    string
	Trust     string
	Cwd       string
	Script    string
}

// SealHost seals the rollout mode on this process from the config at cwd.
// The result is silent or enforce. A later call returns the same seal.
func SealHost(cwd string) string {
	mode := ""
	if cfg, err := config.Load(config.DefaultLocations(cwd)); err == nil {
		mode = cfg.Mode
	}
	return rollout.Capture(mode)
}

// NoteScript logs the Layer-1 verdict that would have applied. It returns
// immediately. The exit code is read from exitc when the command finishes.
// A missing code after 30 minutes is recorded as unknown. A log failure
// does not affect the command.
func NoteScript(n Note, exitc <-chan int) {
	go noteScript(n, exitc)
}

func noteScript(n Note, exitc <-chan int) {
	rec := silentlog.Record{
		SessionID: n.SessionID,
		TurnID:    n.TurnID,
		Surface:   n.Surface,
		Sender:    n.Sender,
		Trust:     n.Trust,
		Cwd:       n.Cwd,
		Raw:       n.Script,
		Layer:     "precheck",
		Verdict:   "pass",
	}
	r := precheck.ScanAt(n.Script, n.Cwd, os.Getenv("HOME"))
	switch r.Action {
	case "hardblock", "catch":
		rec.Verdict = "catch"
		if r.Action == "hardblock" {
			rec.Verdict = "hardblock"
		}
		rec.Rule = r.Case
		rec.Reason = r.Message
		rec.CatchID = "would-" + randHex(8)
	}
	timer := time.NewTimer(30 * time.Minute)
	defer timer.Stop()
	select {
	case code := <-exitc:
		rec.ExitCode = &code
	case <-timer.C:
		rec.Error = "exit unknown"
	}
	_ = silentlog.Write(rec, silentOptions(n.Cwd))
}

func silentOptions(cwd string) silentlog.Options {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	home, _ := os.UserHomeDir()
	cfg, _ := config.Load(config.DefaultLocations(cwd))
	path := envx.Get("SILENT_LOG")
	if path == "" {
		path = cfg.Log.SilentPath
	}
	if path == "" && home != "" {
		path = filepath.Join(home, ".local", "state", "spotter-sh", "silent.jsonl")
	}
	maxBytes := int64(cfg.Log.SilentMaxMB) << 20
	if maxBytes <= 0 {
		maxBytes = 32 << 20
	}
	age := cfg.Log.SilentMaxAge
	if age <= 0 {
		age = 14 * 24 * time.Hour
	}
	return silentlog.Options{Path: path, MaxBytes: maxBytes, MaxAge: age}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
