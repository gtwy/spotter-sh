// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package precheck

import (
	"testing"
)

func TestRound13CompoundAndBackground(t *testing.T) {
	home := t.TempDir()
	blocks := []string{
		`( sleep 2; rm -rf / ) & disown`,
		`( rm -rf ~ ) &`,
		`{ rm -rf /; } &`,
		`{ rm -rf ~ & }`,
		`coproc { rm -rf /; }`,
		`coproc WIP { rm -rf ~; }`,
		`nohup rm -rf / &`,
		`setsid rm -rf ~`,
		`rm -rf / &`,
	}
	for _, c := range blocks {
		r := ScanAt(c, home, home)
		if r.Action != "hardblock" || r.Approve || r.Exit != 121 {
			t.Errorf("block %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	// A single ssh file is not a text hard block. The shim judges it.
	// The same command inside a background subshell is still visible.
	r := ScanAt(`rm -rf ~/.ssh/known_hosts`, home, home)
	bg := ScanAt(`( sleep 2; rm -rf ~/.ssh/id_ed25519 ) & disown`, home, home)
	if r.Action != bg.Action || r.Approve != bg.Approve {
		t.Fatalf("background ssh %s/%v foreground %s/%v", bg.Action, bg.Approve, r.Action, r.Approve)
	}
	if r := ScanAt(`echo hi &`, home, home); r.Action != "allow" {
		t.Fatalf("echo background %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`f(){ f; }`, home, home); r.Action != "allow" {
		t.Fatalf("uncalled function %s %s", r.Action, r.Message)
	}
}

func TestRound13Globs(t *testing.T) {
	home := t.TempDir()
	catches := []string{
		`rm -rf -- ~/ws/*/`,
		`rm -rf /var/opt/gitlab/postgresql/data/*`,
		`rm -rf ~/.claude/skills/*`,
		`rm -rf ~/.ssh/*`,
		`rm -rf ~/*`,
		`rm -rf /usr/*`,
	}
	for _, c := range catches {
		r := ScanAt(c, home, home)
		if r.Action != "catch" || !r.Approve || r.Exit != 120 {
			t.Errorf("catch %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	allows := []string{
		`rm -rf ~/ws/scratch/*.png`,
		`rm -rf ~/ws/var/www/*`,
		`rm -rf ~/ws/*`,
		`rm -rf /tmp/job/*`,
	}
	for _, c := range allows {
		r := ScanAt(c, home, home)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
	if r := ScanAt(`rm -rf /*`, home, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("root glob %s approve %v", r.Action, r.Approve)
	}
}

func TestRound13WriteThenRun(t *testing.T) {
	home := t.TempDir()
	blocks := []string{
		`printf 'rm -rf ~\n' > /tmp/x.sh; bash /tmp/x.sh`,
		`echo 'rm -rf /' > /tmp/x.sh; sh /tmp/x.sh`,
		"cat > f <<EOF\nrm -rf ~\nEOF\nsh f",
		"cat > /tmp/y.sh <<'EOF'\nrm -rf /\nEOF\nbash /tmp/y.sh",
	}
	for _, c := range blocks {
		r := ScanAt(c, home, home)
		if r.Action != "hardblock" || r.Approve || r.Exit != 121 {
			t.Errorf("block %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	allows := []string{
		`printf 'echo hi\n' > /tmp/x.sh; bash /tmp/x.sh`,
		`printf 'rm -rf ~\n' > /tmp/x.sh`,
		"cat <<EOF\nrm -rf /\nEOF",
		`echo hi > notes.txt; cat notes.txt`,
	}
	for _, c := range allows {
		r := ScanAt(c, home, home)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
}

func TestRound13StateAssignments(t *testing.T) {
	home := t.TempDir()
	catches := []string{
		`SPOTTER_SH_COVERED=abc rm -rf ~/.ssh`,
		`SHELLSPOTTER_COVERED=abc echo hi`,
		`declare -x SPOTTER_SH_HOME=/tmp`,
		`declare -x SPOTTER_SH_COVERED=abc`,
		`typeset -x SHELLSPOTTER_HOME=/tmp`,
		`sudo -E env SPOTTER_SH_HOME=/tmp rm -rf ~/ws/a`,
		`sudo -E env SHELLSPOTTER_COVERED=abc echo hi`,
		`command sudo -E env SPOTTER_SH_HOME=/tmp true`,
	}
	for _, c := range catches {
		r := ScanAt(c, home, home)
		if r.Action != "catch" || !r.Approve || r.Exit != 120 {
			t.Errorf("catch %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	if r := ScanAt(`SPOTTER_SH_COVERED=abc rm -rf /`, home, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("cover prefix must not soften a root wipe %s approve %v", r.Action, r.Approve)
	}
	allows := []string{
		`echo SPOTTER_SH_COVERED=abc`,
		`echo declare -x SPOTTER_SH_HOME=/tmp`,
		`echo hi`,
	}
	for _, c := range allows {
		r := ScanAt(c, home, home)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
}

func TestRound13SVNList(t *testing.T) {
	home := t.TempDir()
	if r := ScanAt(`svn ls | xargs rm -f`, home, home); r.Action != "catch" || !r.Approve {
		t.Fatalf("svn ls %s approve %v %s", r.Action, r.Approve, r.Message)
	}
	if r := ScanAt(`svn list | xargs rm`, home, home); r.Action != "catch" || !r.Approve {
		t.Fatalf("svn list %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`svn ls | head -5 | xargs rm -f`, home, home); r.Action != "allow" {
		t.Fatalf("limited svn list %s %s", r.Action, r.Message)
	}
}
