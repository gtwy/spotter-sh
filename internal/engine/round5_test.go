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

func roundIn(cwd, home string, argv ...string) Outcome {
	return Decide(Input{
		Argv: argv, Cwd: cwd, Home: home, Config: config.Defaults(), StdinKind: "null",
	})
}

func TestTrailingSlashSymlinks(t *testing.T) {
	home := t.TempDir()
	dir := t.TempDir()
	mk := func(name, target string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	mk("homelink", home)
	mk("rootlink", "/")
	mk("etclink", "/etc")
	mk("biglink", "/usr")
	in := func(argv ...string) Outcome { return roundIn(dir, home, argv...) }
	if o := in("rm", "-rf", "homelink"); o.Action != "allow" {
		t.Fatalf("bare homelink %s %s", o.Action, o.Consequence)
	}
	for _, op := range []string{"homelink/", "homelink/.", "./rootlink/", "etclink/", "biglink/"} {
		o := in("rm", "-rf", op)
		if o.Action != "catch" && o.Action != "hardblock" {
			t.Errorf("rm -rf %s -> %s", op, o.Action)
		}
	}
	if o := in("env", "-i", "PATH=/usr/bin:/bin", "rm", "-rf", "etclink/"); o.Action != "catch" && o.Action != "hardblock" {
		t.Fatalf("env -i etclink/ %s", o.Action)
	}
	if o := in("mv", "homelink", filepath.Join(dir, "moved")); o.Action != "allow" {
		t.Fatalf("mv homelink %s %s", o.Action, o.Consequence)
	}
	if o := in("chown", "-h", "nobody", "homelink"); o.Action != "allow" {
		t.Fatalf("chown -h homelink %s %s", o.Action, o.Consequence)
	}
	if o := in("mv", "homelink/", filepath.Join(dir, "moved")); o.Action != "catch" {
		t.Fatalf("mv homelink/ %s", o.Action)
	}
}

func TestLibcFileProtection(t *testing.T) {
	libc := ""
	for _, p := range []string{
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/libc.so.6",
		"/usr/lib/libc.so.6",
	} {
		if _, err := os.Lstat(p); err == nil {
			libc = p
			break
		}
	}
	if libc == "" {
		t.Skip("libc")
	}
	dir := t.TempDir()
	home := t.TempDir()
	for _, argv := range [][]string{
		{"rm", "-f", libc},
		{"chmod", "644", libc},
		{"mv", libc, filepath.Join(dir, "stolen")},
		{"cp", filepath.Join(dir, "x"), libc},
	} {
		o := roundIn(dir, home, argv...)
		if o.Action != "catch" {
			t.Errorf("%v -> %s %s", argv, o.Action, o.Consequence)
		}
	}
}

func TestFindNameFilterAndBulkDelete(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config")
	brain := filepath.Join(home, "agent-notes")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil || os.MkdirAll(brain, 0o755) != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(brain, "n41.md"), []byte("n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPOTTER_SH_BRAIN", brain)
	if err := os.WriteFile(filepath.Join(cfgDir, "app.log"), []byte("l"), 0o644); err != nil {
		t.Fatal(err)
	}
	in := func(argv ...string) Outcome { return roundIn(home, home, argv...) }
	if o := in("find", ".", "-name", "*.pyc", "-exec", "rm", "-f", "{}", "+"); o.Action != "allow" {
		t.Fatalf("pyc filter %s %s", o.Action, o.Consequence)
	}
	if o := in("find", brain, "-name", "n41.md", "-delete"); o.Action != "allow" {
		t.Fatalf("one brain note %s %s", o.Action, o.Consequence)
	}
	if o := in("find", cfgDir, "-name", "*.log", "-delete"); o.Action != "allow" {
		t.Fatalf("config log %s %s", o.Action, o.Consequence)
	}
	if o := in("find", cfgDir, "-name", "no-such-name", "-delete"); o.Action != "allow" {
		t.Fatalf("empty config name %s %s", o.Action, o.Consequence)
	}
	small := t.TempDir()
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(filepath.Join(small, "f"+string(rune('a'+i))), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if o := roundIn(small, small, "find", small, "-maxdepth", "1", "-type", "f", "-delete"); o.Action != "allow" {
		t.Fatalf("three files %s %s", o.Action, o.Consequence)
	}
	many := t.TempDir()
	for i := 0; i < 101; i++ {
		name := filepath.Join(many, "f"+itoa(i))
		if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	o := roundIn(many, many, "find", many, "-maxdepth", "1", "-type", "f", "-delete")
	if o.Action != "catch" {
		t.Fatalf("101 files %s", o.Action)
	}
}

func TestFindMvChmodAndRootHardBlock(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	marked := filepath.Join(dir, "keep")
	if err := os.MkdirAll(marked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(marked, ".spotter-sh-protect"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(marked, "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := roundIn(dir, home, "find", marked, "-exec", "mv", "{}", filepath.Join(dir, "out"), ";")
	if o.Action != "catch" {
		t.Fatalf("find -exec mv %s %s", o.Action, o.Consequence)
	}
	o = roundIn(dir, home, "sudo", "find", "/", "-exec", "chmod", "777", "{}", ";")
	if o.Action != "hardblock" || o.Exit != 121 {
		t.Fatalf("sudo find chmod / %s %d", o.Action, o.Exit)
	}
	o = roundIn(dir, home, "chmod", "755", "/")
	if o.Action != "hardblock" || o.Exit != 121 {
		t.Fatalf("chmod / %s %d", o.Action, o.Exit)
	}
	o = roundIn(dir, home, "mv", filepath.Join(dir, "a.txt"), "/")
	if o.Action != "hardblock" || o.Exit != 121 {
		t.Fatalf("mv onto / %s %d", o.Action, o.Exit)
	}
	o = roundIn(dir, home, "mv", "/", filepath.Join(dir, "rootcopy"))
	if o.Action != "hardblock" || o.Exit != 121 {
		t.Fatalf("mv / %s %d", o.Action, o.Exit)
	}
}

func TestIncludeRelativeAndQuotedRead(t *testing.T) {
	dir := t.TempDir()
	drop := filepath.Join(dir, "drop.sql")
	if err := os.WriteFile(drop, []byte("DROP TABLE t;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := roundIn(dir, dir, "psql", "-c", `\include_relative drop.sql`)
	if o.Action != "catch" {
		t.Fatalf("include_relative %s %s", o.Action, o.Consequence)
	}
	o = roundIn(dir, dir, "sqlite3", "app.db", "-cmd", `.read 'drop.sql'`)
	if o.Action != "catch" {
		t.Fatalf("quoted .read %s %s", o.Action, o.Consequence)
	}
	o = roundIn(dir, dir, "sqlite3", "app.db", "-cmd", `.read "drop.sql"`)
	if o.Action != "catch" {
		t.Fatalf("double quoted .read %s %s", o.Action, o.Consequence)
	}
}
