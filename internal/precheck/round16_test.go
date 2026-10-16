// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package precheck

import "testing"

func TestRound16SystemdHomeDelete(t *testing.T) {
	home := t.TempDir()
	catches := []string{
		`systemd-run --user rm -rf ~/.ssh`,
		`systemd-run --user --scope rm -rf ~/.appdata`,
		`systemd-run --user --on-active=1min rm -rf ~/notes`,
		`systemd-run --scope rm -rf ~/.ssh`,
		`systemd-run --user --collect rm -rf "$HOME/notes"`,
		`systemd-run --uid=0 -- rm -rf ${HOME}/.ssh`,
	}
	for _, c := range catches {
		r := ScanAt(c, home, home)
		if r.Action != "catch" || !r.Approve || r.Exit != 120 {
			t.Errorf("catch %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	blocks := []string{
		`systemd-run --user rm -rf /`,
		`systemd-run --scope rm -rf /`,
		`systemd-run --user --scope rm -rf /`,
		`systemd-run --user --on-active=1min rm -rf /`,
		`systemd-run --user --timer-property=AccuracySec=1s rm -rf /`,
		`systemd-run rm -rf /bin /etc /usr /home /var /lib /sbin /opt /root /boot`,
	}
	for _, c := range blocks {
		r := ScanAt(c, home, home)
		if r.Action != "hardblock" || r.Approve || r.Exit != 121 {
			t.Errorf("hard %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	allows := []string{
		`systemd-run --user sleep 1`,
		`systemd-run --user --scope make`,
		`systemd-run --scope go build`,
		`systemd-run --user --scope cargo build --release`,
		`systemd-run --scope -- make -C ~/src`,
		`rm -rf ~/notes`,
		`rm -rf ~/ws/only`,
		`systemd-run --user rm -f ~/notes/one.txt`,
		`systemd-run --user --help`,
	}
	for _, c := range allows {
		r := ScanAt(c, home, home)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
}

func TestRound16IfForkBomb(t *testing.T) {
	home := t.TempDir()
	blocks := []string{
		`if true; then :|:& fi`,
		`if :; then :|:& fi`,
		`if true; then :|:&; fi`,
		`if :; then :|:&; fi`,
		"if true; then :|:&\nfi",
		`if true; then (:|:&)& fi`,
		`if true; then :|:&; else :; fi`,
		`if false; then :; else :|:&; fi`,
		`if false; then echo hi; elif :; then :|:&; fi`,
		`if true; then if :; then :|:& fi fi`,
		`f(){ if true; then :|:& fi }; f`,
		`while true; do :|:& done`,
		`until false; do :|:& done`,
		`f(){ :|:& }; f`,
	}
	for _, c := range blocks {
		r := ScanAt(c, home, home)
		if r.Action != "hardblock" || r.Approve || r.Exit != 121 {
			t.Errorf("bomb %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	allows := []string{
		`if true; then echo hi; fi`,
		`if true; then true|false&; fi`,
		`if :; then :|:; fi`,
		`while false; do :|:& done`,
		`f(){ if true; then :|:& fi }`,
		`f(){ :|:& }`,
		`if true; then ls | head &; fi`,
	}
	for _, c := range allows {
		r := ScanAt(c, home, home)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
}
