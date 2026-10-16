// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gtwy/spotter-sh/internal/config"
)

func TestExpandedRootNotApprovable(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	check := func(argv ...string) {
		t.Helper()
		o := roundIn(dir, home, argv...)
		if o.Action != "hardblock" || o.Exit != 121 || o.Approve {
			t.Errorf("%v -> %s %s exit %d approve %v", argv, o.Action, o.Level, o.Exit, o.Approve)
		}
	}
	check("rm", "-rf", "/")
	check("rm", "-rf", "/*")
	check("chmod", "-R", "777", "/")
	check("chmod", "755", "/")
	check("chown", "-R", "root", "/")
	check("find", "/", "-delete")
	check("find", "/", "-name", "x", "-delete")
	check("rm", "-rf", home)
	check("chmod", "-R", "755", home)
	check("find", home, "-delete")
	check("rm", "-rf", "/bin", "/etc", "/usr", "/home", "/var", "/lib", "/sbin", "/opt", "/root", "/boot")
	// A name filter under the home directory still deletes that file, not the home node.
	o := roundIn(home, home, "find", home, "-maxdepth", "1", "-name", ".bashrc", "-delete")
	if o.Action == "hardblock" {
		t.Fatalf("named bashrc became %s", o.Consequence)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if o := roundIn(dir, home, "rm", "-rf", sub); o.Action != "allow" {
		t.Fatalf("ordinary tree %s %s", o.Action, o.Consequence)
	}
	if o := roundIn(dir, home, "rm", "-rf", "/var/log"); o.Action == "hardblock" {
		t.Fatalf("/var/log hardblocked %s", o.Consequence)
	}
}

func TestFindBareDeleteBulk(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	few := filepath.Join(dir, "few")
	if err := os.MkdirAll(few, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(filepath.Join(few, "f"+itoa(i)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if o := roundIn(dir, home, "find", few, "-delete"); o.Action != "allow" {
		t.Fatalf("few %s %s", o.Action, o.Consequence)
	}
	many := filepath.Join(dir, "perm600")
	if err := os.MkdirAll(many, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 101; i++ {
		if err := os.WriteFile(filepath.Join(many, "f"+itoa(i)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	o := roundIn(dir, home, "find", many, "-delete")
	if o.Action != "catch" {
		t.Fatalf("perm600 %s %s", o.Action, o.Consequence)
	}
}

func TestFindNameMtimeAllows(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "old.tmp")
	if err := os.WriteFile(old, []byte("o"), 0o644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-30 * 24 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.tmp"), []byte("n"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := roundIn(dir, home, "find", ".", "-name", "*.tmp", "-mtime", "+7", "-delete")
	if o.Action != "allow" {
		t.Fatalf("tmp mtime %s %s", o.Action, o.Consequence)
	}
	// A name filter that times out before it fills the bulk threshold is not a wipe.
	late := Decide(Input{
		Argv: []string{"find", ".", "-name", "*.tmp", "-mtime", "+7", "-delete"},
		Cwd:  "/usr", Home: home, Config: config.Defaults(), StdinKind: "null",
		Deadline: time.Now().Add(-time.Second),
	})
	if late.Action != "allow" {
		t.Fatalf("timed name filter %s %s", late.Action, late.Consequence)
	}
}

func TestFindExecRedirect(t *testing.T) {
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ssh, "id_ed25519"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := roundIn(home, home, "find", ssh, "-exec", "sh", "-c", `cat /dev/null > "$1"`, "_", "{}", ";")
	if o.Action != "catch" && o.Action != "hardblock" {
		t.Fatalf("redirect exec %s %s", o.Action, o.Consequence)
	}
}

func TestCopyIntoSystemLib(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	src := filepath.Join(dir, "payload")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	lib := "/usr/lib"
	st, err := os.Lstat(lib)
	if err != nil || !st.IsDir() {
		t.Skip("/usr/lib")
	}
	for _, argv := range [][]string{
		{"cp", "-t", lib, src},
		{"install", "-t", lib, src},
		{"cp", src, lib + "/"},
	} {
		o := roundIn(dir, home, argv...)
		if o.Action != "catch" && o.Action != "hardblock" {
			t.Errorf("%v -> %s %s", argv, o.Action, o.Consequence)
		}
	}
	if o := roundIn(dir, home, "cp", "-t", dir, src); o.Action != "allow" {
		t.Fatalf("cp -t work %s %s", o.Action, o.Consequence)
	}
}
