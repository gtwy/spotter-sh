// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package precheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRound12EscapesHerestringAndOpaque(t *testing.T) {
	home := t.TempDir()
	allows := []string{
		`echo "\$(rm -rf /)"`,
		`echo '$(rm -rf /)'`,
		"cat <<EOF\nrm -rf /\nEOF",
		`bash -c 'echo hi'`,
		`bash -c $'echo hi'`,
		`echo $0`,
		`sh -c 'echo $0'`,
		`echo SPOTTER_SH_HOME=/tmp`,
	}
	for _, c := range allows {
		r := ScanAt(c, home, home)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
	if r := ScanAt(`echo "$(rm -rf /)"`, home, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("live subst %s approve %v", r.Action, r.Approve)
	}
	if r := ScanAt(`cat <<< "$(rm -rf ~)"`, home, home); r.Action != "hardblock" || r.Approve || r.Exit != 121 {
		t.Fatalf("herestring %s approve %v exit %d %s", r.Action, r.Approve, r.Exit, r.Message)
	}
	if r := ScanAt(`bash -c $'\x65\x63\x68\x6f\x20\x68\x69'`, home, home); r.Action != "catch" || !r.Approve || r.Exit != 120 {
		t.Fatalf("ansi -c %s approve %v exit %d %s", r.Action, r.Approve, r.Exit, r.Message)
	}
	if r := ScanAt(`perl -e $'\x65\x78\x69\x74'`, home, home); r.Action != "catch" || !r.Approve {
		t.Fatalf("perl ansi %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`SPOTTER_SH_HOME=/tmp rm -rf ~/ws/only`, home, home); r.Action != "catch" || !r.Approve {
		t.Fatalf("home override %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`env SHELLSPOTTER_HOME=/tmp echo hi`, home, home); r.Action != "catch" || !r.Approve {
		t.Fatalf("env override %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`SPOTTER_SH_HOME=/tmp rm -rf /`, home, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("override must not soften a root wipe %s approve %v", r.Action, r.Approve)
	}
}

func TestRound12GlobsListsAndSelf(t *testing.T) {
	home := t.TempDir()
	if r := ScanAt(`rm -rf ~/ws/scratch/*.png`, home, home); r.Action != "allow" {
		t.Fatalf("project glob %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`rm -rf ~/ws/var/www/*`, home, home); r.Action != "allow" {
		t.Fatalf("deeper glob %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`rm -rf ~/*`, home, home); r.Action != "catch" || !r.Approve {
		t.Fatalf("home children %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`rm -rf /var/*`, home, home); r.Action != "catch" || !r.Approve {
		t.Fatalf("var children %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`echo a b | xargs -I{} rm -f {}`, home, home); r.Action != "allow" {
		t.Fatalf("names %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`echo /tmp/a /tmp/b | xargs rm -f`, home, home); r.Action != "catch" || !r.Approve {
		t.Fatalf("two tmp paths %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`git ls-files | xargs rm -f`, home, home); r.Action != "catch" || !r.Approve {
		t.Fatalf("git list %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`hg status | xargs rm -f`, home, home); r.Action != "catch" || !r.Approve {
		t.Fatalf("hg list %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`ls ~/ws/many/*.tmp | head -5 | xargs rm -f`, home, home); r.Action != "allow" {
		t.Fatalf("short unknown %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`rm -rf ~/ws/a ~/ws/b ~/ws/c ~/ws/d`, home, home); r.Action != "catch" || !r.Approve {
		t.Fatalf("four dirs %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`rm -rf ~/ws/a ~/ws/b ~/ws/c`, home, home); r.Action != "allow" {
		t.Fatalf("three dirs %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`exec $0`, home, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("exec dollar0 %s approve %v", r.Action, r.Approve)
	}
	if r := ScanAt(`exec ${BASH_SOURCE[0]}`, home, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("exec bash source %s approve %v %s", r.Action, r.Approve, r.Message)
	}
	if r := ScanAt(`exec "$0"`, home, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("exec quoted %s approve %v", r.Action, r.Approve)
	}

	script := filepath.Join(home, "relaunch.sh")
	body := "#!/bin/sh\nexec \"$0\" \"$@\"\n"
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := ScanAt("bash "+script, home, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("script exec %s approve %v %s", r.Action, r.Approve, r.Message)
	}
	bg := filepath.Join(home, "again.sh")
	if err := os.WriteFile(bg, []byte("#!/bin/sh\n${BASH_SOURCE[0]} &\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := ScanAt(bg, home, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("script background %s approve %v %s", r.Action, r.Approve, r.Message)
	}
	plain := filepath.Join(home, "ok.sh")
	if err := os.WriteFile(plain, []byte("#!/bin/sh\necho hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := ScanAt("bash "+plain, home, home); r.Action != "allow" {
		t.Fatalf("plain script %s %s", r.Action, r.Message)
	}
}
