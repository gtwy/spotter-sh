// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"testing"

	"github.com/gtwy/spotter-sh/internal/config"
)

func TestRound14LauncherArgv(t *testing.T) {
	home := t.TempDir()
	hits := [][]string{
		{"systemd-run", "rm", "-rf", "/"},
		{"systemd-run", "--user", "rm", "-rf", "/usr"},
		{"watch", "rm", "-rf", "/"},
		{"watch", "-n", "1", "rm", "-rf", "/etc"},
		{"flock", "/tmp/lock", "rm", "-rf", "/"},
		{"flock", "-n", "/tmp/lock", "rm", "-rf", "/bin"},
		{"nsenter", "-t", "1", "-m", "rm", "-rf", "/"},
		{"unshare", "--mount", "rm", "-rf", "/"},
		{"chroot", "/mnt", "rm", "-rf", "/"},
		{"timeout", "--foreground", "5", "rm", "-rf", "/"},
		{"timeout", "-k", "1", "5", "rm", "-rf", "/usr"},
		{"chrt", "-f", "1", "rm", "-rf", "/"},
		{"taskset", "-c", "0", "rm", "-rf", "/"},
		{"taskset", "0x1", "rm", "-rf", "/"},
		{"cpulimit", "-l", "10", "rm", "-rf", "/"},
		{"ssh-agent", "rm", "-rf", "/"},
		{"dbus-launch", "--exit-with-session", "rm", "-rf", "/"},
		{"script", "-c", "rm -rf /"},
		{"su", "-c", "rm -rf /"},
		{"runuser", "-u", "nobody", "-c", "rm -rf ~"},
		{"setsid", "bash", "-c", "rm -rf /"},
		{"tmux", "new", "-d", "rm", "-rf", "/"},
		{"screen", "-dm", "rm", "-rf", "/"},
	}
	for _, argv := range hits {
		o := Decide(Input{Argv: argv, Cwd: home, Home: home, Config: config.Defaults(), StdinKind: "null"})
		if o.Action != "hardblock" && o.Action != "catch" {
			t.Errorf("%v -> %s %s", argv, o.Action, o.Consequence)
		}
	}
	allows := [][]string{
		{"systemd-run", "--user", "sleep", "1"},
		{"watch", "ls"},
		{"script", "-c", "ls"},
		{"timeout", "5", "echo", "hi"},
		{"at", "-l"},
		{"crontab", "-l"},
		{"screen", "-ls"},
	}
	for _, argv := range allows {
		o := Decide(Input{Argv: argv, Cwd: home, Home: home, Config: config.Defaults(), StdinKind: "null"})
		if o.Action != "allow" {
			t.Errorf("allow %v -> %s %s", argv, o.Action, o.Consequence)
		}
	}
	opaque := Decide(Input{Argv: []string{"at", "now"}, Cwd: home, Home: home, Config: config.Defaults(), StdinKind: "pipe"})
	if opaque.Action != "catch" || !opaque.Approve || opaque.Exit != 120 {
		t.Fatalf("opaque at %s approve %v exit %d", opaque.Action, opaque.Approve, opaque.Exit)
	}
	seen := Decide(Input{
		Argv: []string{"at", "now"}, Cwd: home, Home: home, Config: config.Defaults(),
		StdinKind: "file", StdinPeek: []byte("echo hi\n"),
	})
	if seen.Action != "allow" {
		t.Fatalf("at echo %s %s", seen.Action, seen.Consequence)
	}
	cron := Decide(Input{
		Argv: []string{"crontab", "-"}, Cwd: home, Home: home, Config: config.Defaults(),
		StdinKind: "file", StdinPeek: []byte("* * * * * rm -rf /\n"),
	})
	if cron.Action != "hardblock" {
		t.Fatalf("cron peek %s %s", cron.Action, cron.Consequence)
	}
}
