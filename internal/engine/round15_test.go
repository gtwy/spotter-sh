// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"testing"

	"github.com/gtwy/spotter-sh/internal/config"
)

func TestRound15WholeRootAndLaunchers(t *testing.T) {
	home := t.TempDir()
	in := func(argv ...string) Outcome {
		return Decide(Input{Argv: argv, Cwd: home, Home: home, Config: config.Defaults(), StdinKind: "null"})
	}
	top := in("rm", "-rf", "/bin", "/etc", "/usr", "/home", "/var", "/lib", "/sbin", "/opt", "/root", "/boot")
	if top.Action != "hardblock" || top.Approve || top.Exit != 121 {
		t.Fatalf("top sweep %s approve %v exit %d %s", top.Action, top.Approve, top.Exit, top.Consequence)
	}
	one := in("rm", "-rf", "/bin")
	if one.Action != "catch" || one.Exit != 120 {
		t.Fatalf("one dir %s exit %d %s", one.Action, one.Exit, one.Consequence)
	}
	two := in("rm", "-rf", "/etc", "/usr")
	if two.Action != "catch" || two.Exit != 120 {
		t.Fatalf("two dirs %s exit %d %s", two.Action, two.Exit, two.Consequence)
	}
	blocks := [][]string{
		{"runuser", "-u", "root", "--", "rm", "-rf", "/"},
		{"pkexec", "rm", "-rf", "/"},
		{"pkexec", "--user", "root", "rm", "-rf", "/"},
		{"doas", "rm", "-rf", "/"},
		{"sudo", "-u", "root", "rm", "-rf", "/"},
		{"sudo", "-u", "root", "--", "rm", "-rf", "/"},
		{"machinectl", "shell", ".host", "rm", "-rf", "/"},
		{"nsenter", "-t", "1", "--mount", "--", "rm", "-rf", "/"},
		{"chroot", "/mnt", "rm", "-rf", "/"},
		{"bash", "-c", "{ :|:& }"},
	}
	for _, argv := range blocks {
		o := in(argv...)
		if o.Action != "hardblock" || o.Approve || o.Exit != 121 {
			t.Errorf("%v -> %s approve %v exit %d %s", argv, o.Action, o.Approve, o.Exit, o.Consequence)
		}
	}
	opaque := [][]string{
		{"runuser", "-u", "root"},
		{"su"},
		{"pkexec"},
		{"doas"},
		{"sudo", "-u", "root"},
		{"nsenter", "-t", "1", "-m"},
		{"chroot", "/mnt"},
		{"systemd-run", "--user"},
		{"machinectl", "shell"},
	}
	for _, argv := range opaque {
		o := in(argv...)
		if o.Action != "catch" || !o.Approve || o.Exit != 120 {
			t.Errorf("opaque %v -> %s approve %v exit %d %s", argv, o.Action, o.Approve, o.Exit, o.Consequence)
		}
	}
	allows := [][]string{
		{"at", "--help"},
		{"at", "--version"},
		{"systemd-run", "--user", "--help"},
		{"systemd-run", "--version"},
		{"systemd-run", "--user", "sleep", "1"},
		{"runuser", "--help"},
		{"pkexec", "--help"},
		{"doas", "--help"},
		{"sudo", "--help"},
		{"sudo", "-u", "root", "--help"},
		{"nsenter", "--help"},
		{"chroot", "--help"},
		{"machinectl", "--help"},
		{"bash", "-c", "f(){ :|:& }"},
	}
	for _, argv := range allows {
		o := in(argv...)
		if o.Action != "allow" {
			t.Errorf("allow %v -> %s %s", argv, o.Action, o.Consequence)
		}
	}
}
