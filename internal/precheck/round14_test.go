// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package precheck

import "testing"

func TestRound14ForkShape(t *testing.T) {
	home := t.TempDir()
	blocks := []string{
		`:|:&`,
		`(:|:&)&`,
		`true|true&`,
		`true | true &`,
		`false|false&`,
		`builtin : | builtin : &`,
		`command true | command true &`,
		`f(){ true|true& }; f`,
		`f(){ :|:& }; f`,
		`g(){ (:|:&)& }; g`,
		`while true; do false|false& done`,
		`until false; do :|:& done`,
		`eval ':|:&'`,
		`bash -c ':|:&'`,
		`sh -c '(:|:&)&'`,
		`bash -c 'true|true&'`,
	}
	for _, c := range blocks {
		r := ScanAt(c, home, home)
		if r.Action != "hardblock" || r.Approve || r.Exit != 121 {
			t.Errorf("bomb %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	allows := []string{
		`:|:`,
		`true|true`,
		`true|false&`,
		`echo hi | cat &`,
		`ls | head &`,
		`echo ":|:&"`,
		`f(){ :|:& }`,
		`f(){ true|true& }`,
		`while false; do :|:& done`,
		`sleep 1 | sleep 1 &`,
	}
	for _, c := range allows {
		r := ScanAt(c, home, home)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
}

func TestRound14Launchers(t *testing.T) {
	home := t.TempDir()
	blocks := []string{
		`at now <<< 'rm -rf /'`,
		`at noon <<< $'rm -rf /'`,
		`echo 'rm -rf /' | at now`,
		`echo 'rm -rf ~' | batch`,
		"batch <<EOF\nrm -rf /\nEOF",
		`at -f /tmp/x.sh now`,
		`batch`,
		`systemd-run rm -rf /`,
		`systemd-run --user rm -rf /`,
		`systemd-run --user --collect --unit=job -- rm -rf /`,
		`systemd-run --user`,
		`script -c 'rm -rf /'`,
		`script --command 'rm -rf ~' /tmp/typescript`,
		`flock /tmp/lock rm -rf /`,
		`flock -n /tmp/lock rm -rf /`,
		`flock --timeout 2 /tmp/lock rm -rf /usr`,
		`flock /tmp/lock -c 'rm -rf /'`,
		`watch rm -rf /`,
		`watch -n 1 rm -rf /`,
		`watch -n1 rm -rf ~`,
		`nsenter -t 1 -m rm -rf /`,
		`nsenter -t 1 --mount -- rm -rf /`,
		`unshare --mount rm -rf /`,
		`unshare -m rm -rf /`,
		`chroot /mnt rm -rf /`,
		`chroot /mnt /bin/rm -rf /`,
		`su -c 'rm -rf /'`,
		`su -c 'rm -rf /' root`,
		`su - root -c 'rm -rf ~'`,
		`runuser -u nobody -c 'rm -rf /'`,
		`runuser -c 'rm -rf /'`,
		`echo '* * * * * rm -rf /' | crontab -`,
		`crontab -`,
		`tmux new -d rm -rf /`,
		`tmux new-session -d -s x rm -rf /`,
		`tmux new-session -d 'rm -rf /'`,
		`screen -dm rm -rf /`,
		`screen -dmS sess rm -rf /`,
		`ssh-agent rm -rf /`,
		`ssh-agent bash -c 'rm -rf /'`,
		`dbus-launch rm -rf /`,
		`dbus-launch --exit-with-session rm -rf /`,
		`chrt -f 1 rm -rf /`,
		`chrt --fifo 1 rm -rf /`,
		`taskset -c 0 rm -rf /`,
		`taskset -c 0-1 rm -rf /`,
		`taskset 0x1 rm -rf /`,
		`cpulimit -l 50 -- rm -rf /`,
		`cpulimit -l 10 rm -rf /`,
		`stdbuf -oL rm -rf /`,
		`ionice -c 3 rm -rf /`,
		`printf 'rm -rf ~\n' > /tmp/x.sh; at -f /tmp/x.sh now`,
	}
	for _, c := range blocks {
		r := ScanAt(c, home, home)
		if r.Action != "hardblock" && r.Action != "catch" {
			t.Errorf("launch %q -> %s %s", c, r.Action, r.Message)
			continue
		}
		if r.Action == "hardblock" && r.Approve {
			t.Errorf("hard %q approve", c)
		}
		if r.Action == "catch" && (!r.Approve || r.Exit != 120) {
			t.Errorf("catch %q approve %v exit %d", c, r.Approve, r.Exit)
		}
	}
	// /usr inside flock is an approvable catch, not a hard block.
	if r := ScanAt(`flock --timeout 2 /tmp/lock rm -rf /usr`, home, home); r.Action != "catch" || !r.Approve {
		t.Fatalf("flock usr %s approve %v %s", r.Action, r.Approve, r.Message)
	}
	allows := []string{
		`at now + 1 hour <<< 'echo hi'`,
		`systemd-run --user sleep 1`,
		`systemd-run --uid=0 sleep 1`,
		`watch ls`,
		`watch -n 1 ls`,
		`script -c 'ls'`,
		`script -c 'echo hi'`,
		`echo '0 * * * * echo hi' | crontab -`,
		`crontab -l`,
		`at -l`,
		`tmux ls`,
		`screen -ls`,
		`ssh-agent -s`,
		`chrt -p 1 4321`,
		`nice -n 5 echo hi`,
		`flock /tmp/lock echo hi`,
	}
	for _, c := range allows {
		r := ScanAt(c, home, home)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
}

func TestRound14BackgroundDeletes(t *testing.T) {
	home := t.TempDir()
	blocks := []string{
		`{ rm -rf /var; } &`,
		`{ sleep 1; rm -rf /opt; } & disown`,
		`timeout --foreground 5 rm -rf / &`,
		`timeout -k 1 5 rm -rf /`,
		`timeout -s KILL 5 rm -rf ~ &`,
		`timeout --signal=TERM 5 rm -rf /usr &`,
		`( sleep 3 && rm -rf /lib ) & disown`,
		`sleep 2; rm -rf /boot & disown`,
		`setsid bash -c 'rm -rf /lib'`,
		`setsid -f bash -c 'rm -rf /' &`,
		`setsid --wait bash -c 'rm -rf /var'`,
		`setsid --fork -- bash -c 'rm -rf /'`,
	}
	for _, c := range blocks {
		r := ScanAt(c, home, home)
		if r.Action != "hardblock" && r.Action != "catch" {
			t.Errorf("bg %q -> %s %s", c, r.Action, r.Message)
			continue
		}
		if r.Action == "catch" && !r.Approve {
			t.Errorf("bg catch %q not approvable", c)
		}
	}
	if r := ScanAt(`{ echo hi; } &`, home, home); r.Action != "allow" {
		t.Fatalf("brace echo %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`timeout 5 echo hi &`, home, home); r.Action != "allow" {
		t.Fatalf("timeout echo %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`setsid bash -c 'echo hi'`, home, home); r.Action != "allow" {
		t.Fatalf("setsid echo %s %s", r.Action, r.Message)
	}
}
