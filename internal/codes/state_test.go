// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package codes

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirFromIgnoresEnvAndTrustsStamp(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "spotter-sh")
	if err := os.WriteFile(exe, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPOTTER_SH_HOME", filepath.Join(root, "attacker"))
	t.Setenv("SHELLSPOTTER_HOME", filepath.Join(root, "attacker"))
	t.Setenv("HOME", filepath.Join(root, "attacker"))
	if err := os.WriteFile(exe+".state", []byte(state+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	if got := DirFrom(exe, uid, "/home/nobody"); got != state {
		t.Fatalf("stamp %s", got)
	}
	_ = info
	if err := os.Chmod(exe+".state", 0o666); err != nil {
		t.Fatal(err)
	}
	if got := DirFrom(exe, uid, "/home/nobody"); got == state {
		t.Fatal("world-writable stamp was trusted")
	}
	if err := os.Chmod(exe+".state", 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe+".state", []byte("../attacker\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DirFrom(exe, uid, "/home/passwd"); got != "/home/passwd/.local/state/spotter-sh" {
		t.Fatalf("relative stamp fell through to %s", got)
	}
	if err := os.Remove(exe + ".state"); err != nil {
		t.Fatal(err)
	}
	if got := DirFrom(exe, 0, "/home/passwd"); got != "/var/lib/spotter-sh" {
		t.Fatalf("root exe %s", got)
	}
	if got := DirFrom("/usr/local/lib/spotter-sh/shims/spotter-sh", 1, "/home/passwd"); got != "/var/lib/spotter-sh" {
		t.Fatalf("system path %s", got)
	}
}

func TestCallerControlsKey(t *testing.T) {
	dir := t.TempDir()
	if err := EnsureKey(dir); err != nil {
		t.Fatal(err)
	}
	if !(Store{Dir: dir}).CallerControlsKey() {
		t.Fatal("owner of a 0600 key was treated as unable to read it")
	}
	key := filepath.Join(dir, "key")
	if err := os.Chmod(key, 0o000); err != nil {
		t.Fatal(err)
	}
	if !(Store{Dir: dir}).CallerControlsKey() {
		t.Fatal("owner of a mode 0000 key was treated as unable to replace it")
	}
	if !controlsKey(0, 50, 0o640, 1000, 1000, nil, false) {
		t.Fatal("unreadable group list failed open")
	}
	// The setgid egid is not the real gid and is not in the supplementary list.
	if controlsKey(0, 50, 0o640, 1000, 1000, []int{1000}, true) {
		t.Fatal("setgid egid counted as the caller")
	}
	if !controlsKey(0, 50, 0o640, 1000, 1000, []int{50}, true) {
		t.Fatal("supplementary group was ignored")
	}
	if !controlsKey(1000, 50, 0o000, 1000, 1000, nil, true) {
		t.Fatal("owner was ignored")
	}
	if !controlsKey(0, 50, 0o644, 1000, 1000, nil, true) {
		t.Fatal("world read was ignored")
	}
	if controlsKey(0, 50, 0o640, 1000, 1000, []int{1000}, true) {
		t.Fatal("unrelated group counted")
	}
}

func TestFixedDirIgnoresFakeHome(t *testing.T) {
	fake := t.TempDir()
	t.Setenv("SPOTTER_SH_HOME", fake)
	t.Setenv("SHELLSPOTTER_HOME", fake)
	t.Setenv("HOME", fake)
	if got := FixedDir(); got == fake {
		t.Fatal("FixedDir followed the environment")
	}
}
