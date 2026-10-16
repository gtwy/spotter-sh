// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindPredicateOrder(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "keep.txt"), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "bar.txt"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	// -delete before -name deletes every entry, including the home directory.
	o := roundIn(home, home, "find", ".", "-delete", "-name", "*ar")
	if o.Action != "catch" && o.Action != "hardblock" {
		t.Fatalf("delete before name %s %s", o.Action, o.Consequence)
	}
	// A name test before -delete that matches nothing removes nothing.
	o = roundIn(home, home, "find", ".", "-name", "*ar", "-delete")
	if o.Action != "allow" {
		t.Fatalf("name before delete %s %s", o.Action, o.Consequence)
	}
}

func TestFindOrDelete(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "s1.txt"), []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 101; i++ {
		name := filepath.Join(dir, "f"+itoa(i))
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// (-name s1.txt) OR (-type f AND -delete) deletes the regular files.
	o := roundIn(dir, home, "find", dir, "-name", "s1.txt", "-o", "-type", "f", "-delete")
	if o.Action != "catch" {
		t.Fatalf("or delete %s %s", o.Action, o.Consequence)
	}
}

func TestFindExecOverwrite(t *testing.T) {
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ssh, "id_ed25519"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := func(argv ...string) Outcome { return roundIn(home, home, argv...) }
	cases := [][]string{
		{"find", ssh, "-name", "*", "-exec", "cp", "/dev/null", "{}", "+"},
		{"find", ssh, "-name", "*", "-exec", "truncate", "-s", "0", "{}", "+"},
		{"find", ssh, "-name", "*", "-exec", "sh", "-c", `rm "$@"`, "_", "{}", "+"},
	}
	for _, argv := range cases {
		o := in(argv...)
		if o.Action != "catch" && o.Action != "hardblock" {
			t.Errorf("%v -> %s %s", argv, o.Action, o.Consequence)
		}
	}
}

func TestFindSymlinkMaxdepth(t *testing.T) {
	home := t.TempDir()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "canary"), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "homelink")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	o := roundIn(dir, home, "find", link, "-maxdepth", "0", "-delete")
	if o.Action != "allow" {
		t.Fatalf("symlink maxdepth 0 %s %s", o.Action, o.Consequence)
	}
	o = roundIn(dir, home, "find", link+"/", "-delete")
	if o.Action != "catch" && o.Action != "hardblock" {
		t.Fatalf("trailing slash find %s %s", o.Action, o.Consequence)
	}
}

func TestDDAndMvTargetDirectory(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	libc := ""
	libm := ""
	for _, p := range []string{
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/libc.so.6",
	} {
		if _, err := os.Lstat(p); err == nil {
			libc = p
			break
		}
	}
	for _, p := range []string{
		"/lib/x86_64-linux-gnu/libm.so.6",
		"/usr/lib/x86_64-linux-gnu/libm.so.6",
		"/lib64/libm.so.6",
	} {
		if _, err := os.Lstat(p); err == nil {
			libm = p
			break
		}
	}
	if libc == "" || libm == "" {
		t.Skip("lib")
	}
	o := roundIn(dir, home, "dd", "if=/dev/zero", "of="+libc)
	if o.Action != "catch" && o.Action != "hardblock" {
		t.Fatalf("dd libc %s %s", o.Action, o.Consequence)
	}
	o = roundIn(dir, home, "mv", "-t", filepath.Join(dir, "tmp"), libm)
	if o.Action != "catch" && o.Action != "hardblock" {
		t.Fatalf("mv -t libm %s %s", o.Action, o.Consequence)
	}
}

func TestRootlinkNotApprovable(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	link := filepath.Join(dir, "rootlink")
	if err := os.Symlink("/", link); err != nil {
		t.Fatal(err)
	}
	o := roundIn(dir, home, "rm", "-rf", "rootlink/")
	if o.Action != "hardblock" || o.Exit != 121 || o.Approve {
		t.Fatalf("rootlink/ %s %d approve %v", o.Action, o.Exit, o.Approve)
	}
	o = roundIn(dir, home, "rm", "-rf", "./rootlink/")
	if o.Action != "hardblock" || o.Approve {
		t.Fatalf("./rootlink/ %s approve %v", o.Action, o.Approve)
	}
	o = roundIn(dir, home, "rm", "-rf", "rootlink")
	if o.Action != "allow" {
		t.Fatalf("bare rootlink %s %s", o.Action, o.Consequence)
	}
	o = roundIn(dir, home, "rm", "-rf", "/")
	if o.Action != "hardblock" || o.Exit != 121 || o.Approve {
		t.Fatalf("literal / %s %s exit %d approve %v", o.Action, o.Level, o.Exit, o.Approve)
	}
}

func TestLnNoDereference(t *testing.T) {
	home := t.TempDir()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "homelink")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	o := roundIn(dir, home, "ln", "-sfn", "tmp", "homelink")
	if o.Action != "allow" {
		t.Fatalf("ln -sfn %s %s", o.Action, o.Consequence)
	}
}
