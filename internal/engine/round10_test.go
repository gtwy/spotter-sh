// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gtwy/spotter-sh/internal/config"
)

func TestRound10BulkDirsAndSystem(t *testing.T) {
	home := t.TempDir()
	work := filepath.Join(home, "ws", "big")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	var argv []string
	argv = append(argv, "rm", "-rf")
	for i := 1; i <= 11; i++ {
		p := filepath.Join(work, "d"+itoa(i))
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		argv = append(argv, p)
	}
	o := Decide(Input{Argv: argv, Cwd: home, Home: home, Config: config.Defaults(), StdinKind: "null"})
	if o.Action != "catch" || o.Exit != 120 {
		t.Fatalf("11 dirs %s %s exit %d", o.Action, o.Level, o.Exit)
	}
	two := []string{"rm", "-rf", filepath.Join(work, "d1"), filepath.Join(work, "d2")}
	o = Decide(Input{Argv: two, Cwd: home, Home: home, Config: config.Defaults(), StdinKind: "null"})
	if o.Action != "allow" {
		t.Fatalf("two dirs %s %s", o.Action, o.Consequence)
	}
	one := []string{"rm", "-rf", filepath.Join(work, "d1")}
	o = Decide(Input{Argv: one, Cwd: home, Home: home, Config: config.Defaults(), StdinKind: "null"})
	if o.Action != "allow" {
		t.Fatalf("one dir %s %s", o.Action, o.Consequence)
	}
	sys := Decide(Input{
		Argv:      []string{"env", "-i", "PATH=/usr/bin:/bin", "rm", "-rf", "/usr/bin"},
		Cwd:       home,
		Home:      home,
		Config:    config.Defaults(),
		StdinKind: "null",
	})
	if sys.Action != "catch" || sys.Exit != 120 {
		t.Fatalf("env rm /usr/bin %s %s exit %d", sys.Action, sys.Level, sys.Exit)
	}
	wrapped := [][]string{
		{"nice", "rm", "-rf", "/bin"},
		{"nohup", "rm", "-rf", "/usr"},
		{"timeout", "5", "rm", "-rf", "/etc"},
		{"command", "rm", "-rf", "/usr/lib"},
	}
	for _, argv := range wrapped {
		o = Decide(Input{Argv: argv, Cwd: home, Home: home, Config: config.Defaults(), StdinKind: "null"})
		if o.Action != "catch" || o.Exit != 120 {
			t.Errorf("%v -> %s %s exit %d", argv, o.Action, o.Level, o.Exit)
		}
	}
}

func TestRound10ScopedFindNotHardblock(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "a.log"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := Decide(Input{
		Argv:      []string{"find", home, "-maxdepth", "1", "-name", "*.log", "-delete"},
		Cwd:       home,
		Home:      home,
		Config:    config.Defaults(),
		StdinKind: "null",
	})
	if o.Action == "hardblock" {
		t.Fatalf("scoped find hardblocked: %s", o.Consequence)
	}
	bare := Decide(Input{
		Argv:      []string{"find", home, "-delete"},
		Cwd:       home,
		Home:      home,
		Config:    config.Defaults(),
		StdinKind: "null",
	})
	if bare.Action != "hardblock" || bare.Exit != 121 || bare.Approve {
		t.Fatalf("unfiltered home find %s approve %v exit %d", bare.Action, bare.Approve, bare.Exit)
	}
}
