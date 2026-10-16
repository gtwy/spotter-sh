// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"path/filepath"
	"testing"

	"github.com/gtwy/spotter-sh/internal/config"
)

func TestRound16SystemdAndIf(t *testing.T) {
	home := t.TempDir()
	in := func(argv ...string) Outcome {
		return Decide(Input{Argv: argv, Cwd: home, Home: home, Config: config.Defaults(), StdinKind: "null"})
	}
	notes := filepath.Join(home, "notes")
	ssh := filepath.Join(home, ".ssh")
	catches := [][]string{
		{"systemd-run", "--user", "rm", "-rf", "~/.ssh"},
		{"systemd-run", "--user", "--scope", "rm", "-rf", "~/.appdata"},
		{"systemd-run", "--user", "--on-active=1min", "rm", "-rf", "~/notes"},
		{"systemd-run", "--scope", "rm", "-rf", "~/.ssh"},
		{"systemd-run", "--user", "rm", "-rf", ssh},
		{"systemd-run", "--scope", "rm", "-rf", notes},
		{"systemd-run", "--user", "--scope", "rm", "-rf", filepath.Join(home, ".appdata")},
	}
	for _, argv := range catches {
		o := in(argv...)
		if o.Action != "catch" || !o.Approve || o.Exit != 120 {
			t.Errorf("catch %v -> %s approve %v exit %d %s", argv, o.Action, o.Approve, o.Exit, o.Consequence)
		}
	}
	bare := in("rm", "-rf", notes)
	if bare.Action != "allow" {
		t.Fatalf("bare home notes %s %s", bare.Action, bare.Consequence)
	}
	blocks := [][]string{
		{"systemd-run", "--user", "rm", "-rf", "/"},
		{"systemd-run", "--scope", "rm", "-rf", "/"},
		{"systemd-run", "--user", "--scope", "rm", "-rf", "/"},
		{"systemd-run", "--user", "--on-active=1min", "rm", "-rf", "/"},
		{"bash", "-c", "if true; then :|:& fi"},
		{"bash", "-c", "if :; then :|:& fi"},
		{"bash", "-c", "if true; then :|:&; fi"},
		{"bash", "-c", "if false; then :; else :|:&; fi"},
		{"bash", "-c", "f(){ :|:& }; f"},
		{"bash", "-c", "while true; do :|:& done"},
	}
	for _, argv := range blocks {
		o := in(argv...)
		if o.Action != "hardblock" || o.Approve || o.Exit != 121 {
			t.Errorf("hard %v -> %s approve %v exit %d %s", argv, o.Action, o.Approve, o.Exit, o.Consequence)
		}
	}
	allows := [][]string{
		{"systemd-run", "--user", "sleep", "1"},
		{"systemd-run", "--user", "--scope", "make"},
		{"systemd-run", "--scope", "go", "build"},
		{"systemd-run", "--user", "--scope", "cargo", "build"},
		{"bash", "-c", "while false; do :|:& done"},
		{"bash", "-c", "f(){ if true; then :|:& fi }"},
		{"bash", "-c", "if true; then echo hi; fi"},
	}
	for _, argv := range allows {
		o := in(argv...)
		if o.Action != "allow" {
			t.Errorf("allow %v -> %s %s", argv, o.Action, o.Consequence)
		}
	}
}
