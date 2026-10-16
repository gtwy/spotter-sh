// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package precheck

import "testing"

func TestRound15WholeRootAndBrace(t *testing.T) {
	home := t.TempDir()
	top := `rm -rf /bin /etc /usr /home /var /lib /sbin /opt /root /boot`
	if r := ScanAt(top, home, home); r.Action != "hardblock" || r.Approve || r.Exit != 121 {
		t.Fatalf("top sweep %s approve %v exit %d %s", r.Action, r.Approve, r.Exit, r.Message)
	}
	for _, c := range []string{`rm -rf /bin`, `rm -rf /usr`, `rm -rf /etc /usr`, `rm -rf /bin /etc`} {
		r := ScanAt(c, home, home)
		if r.Action != "catch" || !r.Approve || r.Exit != 120 {
			t.Errorf("partial %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	for _, c := range []string{`{ :|:& }`, `{ : | : & }`, `{true|true&}`, `{:|:&}`} {
		r := ScanAt(c, home, home)
		if r.Action != "hardblock" || r.Approve || r.Exit != 121 {
			t.Errorf("brace bomb %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	if r := ScanAt(`f(){ :|:& }`, home, home); r.Action != "allow" {
		t.Fatalf("uncalled brace %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`f(){ :|:& }; f`, home, home); r.Action != "hardblock" || r.Approve || r.Exit != 121 {
		t.Fatalf("called brace %s approve %v exit %d", r.Action, r.Approve, r.Exit)
	}
}

func TestRound15BypassLaunchers(t *testing.T) {
	home := t.TempDir()
	blocks := []string{
		`runuser -u root -- rm -rf /`,
		`runuser -u root -- rm -rf /bin /etc /usr /home /var /lib /sbin /opt /root /boot`,
		`runuser --user root rm -rf /`,
		`pkexec rm -rf /`,
		`pkexec --user root rm -rf /`,
		`doas rm -rf /`,
		`doas -u root rm -rf /`,
		`sudo -u root rm -rf /`,
		`sudo -u root -- rm -rf /`,
		`nsenter -t 1 -m -- rm -rf /`,
		`chroot /mnt rm -rf /`,
		`machinectl shell .host rm -rf /`,
		`machinectl shell root@.host /bin/rm -rf /`,
		`su -c 'rm -rf /'`,
	}
	for _, c := range blocks {
		r := ScanAt(c, home, home)
		if r.Action != "hardblock" || r.Approve || r.Exit != 121 {
			t.Errorf("block %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	catches := []string{
		`runuser -u root`,
		`runuser`,
		`su`,
		`su -`,
		`pkexec`,
		`doas`,
		`doas -u root`,
		`sudo -u root`,
		`nsenter -t 1 -m`,
		`nsenter -t 1 --mount`,
		`chroot /mnt`,
		`systemd-run --user`,
		`machinectl shell`,
		`machinectl shell .host`,
	}
	for _, c := range catches {
		r := ScanAt(c, home, home)
		if r.Action != "catch" || !r.Approve || r.Exit != 120 {
			t.Errorf("opaque %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	allows := []string{
		`at --help`,
		`at --version`,
		`at -h`,
		`batch --help`,
		`systemd-run --user --help`,
		`systemd-run --help`,
		`systemd-run --version`,
		`systemd-run -h`,
		`nsenter --help`,
		`nsenter --version`,
		`chroot --help`,
		`chroot --version`,
		`runuser --help`,
		`runuser --version`,
		`su --help`,
		`pkexec --help`,
		`pkexec --version`,
		`doas --help`,
		`machinectl --help`,
		`machinectl shell --help`,
		`sudo --help`,
		`sudo -u root --help`,
		`systemd-run --user sleep 1`,
		`echo hi`,
	}
	for _, c := range allows {
		r := ScanAt(c, home, home)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
}
