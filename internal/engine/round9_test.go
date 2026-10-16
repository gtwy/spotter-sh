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

func TestRound9LiteralTilde(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	allow := func(argv ...string) {
		t.Helper()
		o := Decide(Input{Argv: argv, Cwd: dir, Home: home, Config: config.Defaults(), StdinKind: "null"})
		if o.Action != "allow" {
			t.Errorf("%v -> %s %s", argv, o.Action, o.Consequence)
		}
	}
	allow("rm", "-rf", "~")
	allow("rm", "-rf", "~/")
	allow("rm", "-rf", `\~`)
	allow("chmod", "-R", "700", "~")
	allow("chmod", "-R", "700", "~/")
	allow("rm", "-rf", "$HOME")
	allow("rm", "-rf", "${HOME}")
	o := Decide(Input{Argv: []string{"rm", "-rf", home}, Cwd: dir, Home: home, Config: config.Defaults(), StdinKind: "null"})
	if o.Action != "hardblock" || o.Approve || o.Exit != 121 {
		t.Fatalf("real home %s approve %v exit %d", o.Action, o.Approve, o.Exit)
	}
}

func TestRound9GlobBulk(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	var few []string
	few = append(few, "rm", "-rf")
	for i := 0; i < 3; i++ {
		p := filepath.Join(dir, "few"+itoa(i))
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		few = append(few, p)
	}
	o := Decide(Input{Argv: few, Cwd: dir, Home: home, Config: config.Defaults(), StdinKind: "null"})
	if o.Action != "allow" {
		t.Fatalf("few rm -rf %s %s", o.Action, o.Consequence)
	}
	var many []string
	many = append(many, "rm", "-rf")
	for i := 0; i < 150; i++ {
		p := filepath.Join(dir, "g"+itoa(i))
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		many = append(many, p)
	}
	o = Decide(Input{Argv: many, Cwd: dir, Home: home, Config: config.Defaults(), StdinKind: "null"})
	if o.Action != "catch" || o.Level != "bulk" || o.Exit != 120 {
		t.Fatalf("glob rm -rf %s %s exit %d", o.Action, o.Level, o.Exit)
	}
	one := filepath.Join(dir, "tree")
	if err := os.MkdirAll(one, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(one, "a"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	o = Decide(Input{Argv: []string{"rm", "-rf", one}, Cwd: dir, Home: home, Config: config.Defaults(), StdinKind: "null"})
	if o.Action != "allow" {
		t.Fatalf("one directory %s %s", o.Action, o.Consequence)
	}
}

func TestRound9ShellScript(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	bomb := `:(){ :|:& };:`
	o := Decide(Input{
		Argv:      []string{"sh", "-c", `printf "` + bomb + `\n" | sh`},
		Cwd:       dir,
		Home:      home,
		Config:    config.Defaults(),
		StdinKind: "null",
	})
	if o.Action != "hardblock" || o.Approve || o.Exit != 121 {
		t.Fatalf("sh -c bomb %s approve %v exit %d", o.Action, o.Approve, o.Exit)
	}
	mutual := `x(){ y|y& };y(){ x; };x`
	o = Decide(Input{
		Argv:      []string{"bash", "-c", mutual},
		Cwd:       dir,
		Home:      home,
		Config:    config.Defaults(),
		StdinKind: "null",
	})
	if o.Action != "hardblock" || o.Approve {
		t.Fatalf("bash -c mutual %s approve %v", o.Action, o.Approve)
	}
	o = Decide(Input{
		Argv:      []string{"sh", "-c", "echo hi"},
		Cwd:       dir,
		Home:      home,
		Config:    config.Defaults(),
		StdinKind: "null",
	})
	if o.Action != "allow" {
		t.Fatalf("echo %s %s", o.Action, o.Consequence)
	}
}
