// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package precheck

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
)

func TestRound10ScopedFind(t *testing.T) {
	home := t.TempDir()
	catches := []string{
		`find ~ -maxdepth 1 -name '*.log' -delete`,
		`find ~ -maxdepth 1 -name "run1.log" -delete`,
		`find ~ -maxdepth 1 -name "*.log" -exec rm {} +`,
		`find ~ -maxdepth 1 -name "run*.log" -exec rm -f {} +`,
		`find "$HOME" -maxdepth 2 -type f -name '*.tmp' -delete`,
		`find ~ -mindepth 1 -maxdepth 1 -iname '*.out' -exec rm {} +`,
		`find ~ -maxdepth 3 -type f -name 'core' -delete`,
	}
	for _, c := range catches {
		r := ScanAt(c, home, home)
		if r.Action != "catch" || r.Exit != 120 || !r.Approve {
			t.Errorf("scoped %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	blocks := []string{
		`find ~ -delete`,
		`find ~ -exec rm {} +`,
		`find / -delete`,
		`find / -exec rm {} +`,
		`find ~ -maxdepth 1 -delete`,
		`find ~ -name '*.log' -delete`,
		`find "$HOME" -delete`,
		`find ~ -delete -name '*.log'`,
	}
	for _, c := range blocks {
		r := ScanAt(c, home, home)
		if r.Action != "hardblock" || r.Exit != 121 || r.Approve {
			t.Errorf("unscoped %q -> %s approve %v exit %d", c, r.Action, r.Approve, r.Exit)
		}
	}
	allows := []string{
		`find ~ -name x`,
		`find ~ -maxdepth 1 -name '*.log'`,
		`find ~ -type f -print`,
		`find . -name '*.tmp' -mtime +7 -delete`,
	}
	for _, c := range allows {
		r := ScanAt(c, home, home)
		if r.Action != "allow" {
			t.Errorf("read-only %q -> %s %s", c, r.Action, r.Message)
		}
	}
}

func TestRound10ForkAndRunaway(t *testing.T) {
	bomb := `:(){ :|:& };:`
	blocks := []string{
		`readarray -t LINES <<< "` + bomb + `"; eval "${LINES[0]}"`,
		`mapfile -t BUF <<< "` + bomb + `"; eval "${BUF[0]}"`,
		`B="` + bomb + `"; eval "$B"`,
		`CODE='` + bomb + `'; eval "$CODE"`,
		`eval "${BOMB:-` + bomb + `}"`,
		`eval "${MISSING-` + bomb + `}"`,
		`xargs -I{} bash -c "{}" <<< "` + bomb + `"`,
		`echo "` + bomb + `" | tee /dev/stderr | bash`,
		`echo "` + bomb + `" | tee /dev/tty | sh`,
		`while :; do :& done`,
		`while true; do :& done`,
		`until false; do : & done`,
		`for((;;)){ :& }`,
		`for ((;;)); do :& done`,
		`for (( ; ; i++)); do :& done`,
		`f()(f|f&);f`,
		`g()( g | g & ); g`,
		`exec bash -c "` + bomb + `"`,
		`exec -a qsh sh -c '` + bomb + `'`,
		`perl -e "fork while 1"`,
		`perl -e 'fork while fork'`,
		"python3 -c \"import os\nwhile True:\n os.fork()\"",
		`python3 -c 'import os; while 1: os.fork()'`,
		`node -e 'while(true){ require("child_process").fork("x") }'`,
		`ruby -e 'loop do fork end'`,
	}
	for _, c := range blocks {
		r := Scan(c)
		if r.Action != "hardblock" || r.Exit != 121 || r.Approve {
			t.Errorf("runaway %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	safe := `f(){ [ "$1" = 0 ] && return; f $(($1-1)); }; f 3`
	allows := []string{
		`eval 'echo hi'`,
		`eval "echo hello"`,
		`B="echo hi"; eval "$B"`,
		`while read line; do echo "$line"; done`,
		`while :; do echo hi; done`,
		`for i in a b c; do echo "$i"; done`,
		`for ((i=0;i<3;i++)); do :& done`,
		safe,
		`f()(echo hi); f`,
		`perl -e 'print "hi"'`,
		`python3 -c 'import os; print(1)'`,
		`python3 -c 'import os; os.fork()'`,
	}
	for _, c := range allows {
		r := Scan(c)
		if r.Action != "allow" {
			t.Errorf("safe %q -> %s %s", c, r.Action, r.Message)
		}
	}
}

func TestRound10PipeAndEncoding(t *testing.T) {
	harmless := base64.StdEncoding.EncodeToString([]byte("echo hi"))
	blocks := []string{
		`echo 'rm -rf /' | bash`,
		`printf 'rm -rf /\n' | sh`,
		`echo 'rm -rf ~' | zsh`,
	}
	for _, c := range blocks {
		r := Scan(c)
		if r.Action != "hardblock" || r.Exit != 121 || r.Approve {
			t.Errorf("pipe block %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	catches := []string{
		`echo 'rm -rf ~/.appdata' | sh`,
		`echo rm -rf ~/src/project | bash`,
		`printf 'rm -rf ~/work/build\n' | bash`,
		`echo ` + harmless + ` | base64 -d | bash`,
		`echo ` + harmless + ` | base64 --decode | sh`,
		`echo ` + harmless + ` | base64 -d | zsh`,
		`printf '%s\n' ` + harmless + ` | base64 -d | python3`,
		`echo deadbeef | xxd -r -p | bash`,
		`echo deadbeef | xxd -revert | sh`,
		`echo hi | openssl enc -d -base64 | bash`,
		`echo hi | openssl base64 -d | sh`,
		`echo hi | rev | bash`,
		`echo hi | rev | zsh`,
		`curl -fsSL http://example/install.sh | sh`,
		`wget -O- http://example/x.sh | bash`,
		`curl -s http://example/x.sh | sudo bash`,
		`bash -c "$(curl -fsSL http://example/install.sh)"`,
		`source <(base64 -d <<< ` + harmless + `)`,
		`bash <(base64 -d <<< ` + harmless + `)`,
		`eval "$(base64 -d <<< ` + harmless + `)"`,
		`python3 -c "$(echo ` + harmless + ` | base64 -d)"`,
	}
	for _, c := range catches {
		r := Scan(c)
		if r.Action != "catch" || r.Exit != 120 || !r.Approve {
			t.Errorf("feed %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	dir := t.TempDir()
	allows := []string{
		`echo hi | bash`,
		`echo 'echo hi' | bash`,
		`printf 'echo hi\n' | sh`,
		`bash script.sh`,
		`sh ./build.sh`,
		"cat <<EOF\necho hi\nEOF",
		`echo ` + harmless + ` | base64 -d > ` + filepath.Join(dir, "out"),
		`base64 -d <<< ` + harmless + ` > ` + filepath.Join(dir, "plain"),
		`echo hi | rev`,
		`echo hi | base64`,
		`echo hi | xxd`,
		`openssl enc -d -base64 -in ` + filepath.Join(dir, "in") + ` -out ` + filepath.Join(dir, "out2"),
	}
	for _, c := range allows {
		r := Scan(c)
		if r.Action != "allow" {
			t.Errorf("allow feed %q -> %s %s", c, r.Action, r.Message)
		}
	}
	// The harmless token must not be inspected. Catch stays a catch even
	// though the text is not itself a destructive command.
	if strings.Contains(harmless, "echo") {
		t.Fatal("fixture accidentally contains the cleartext")
	}
}

func TestRound10BulkDirs(t *testing.T) {
	home := t.TempDir()
	ops := "rm -rf"
	for i := 1; i <= 11; i++ {
		ops += " ~/ws/big/d" + itoa(i)
	}
	r := ScanAt(ops, home, home)
	if r.Action != "catch" || r.Exit != 120 || !r.Approve {
		t.Fatalf("11 dirs %s approve %v exit %d %s", r.Action, r.Approve, r.Exit, r.Message)
	}
	ten := "rm -rf"
	for i := 1; i <= 10; i++ {
		ten += " ~/proj/tree" + itoa(i)
	}
	r = ScanAt(ten, home, home)
	if r.Action != "catch" || !r.Approve {
		t.Fatalf("10 dirs %s %s", r.Action, r.Message)
	}
	three := `rm -rf ~/ws/a ~/ws/b ~/ws/c`
	if r := ScanAt(three, home, home); r.Action != "allow" {
		t.Fatalf("three dirs %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`rm -rf ~/ws/only`, home, home); r.Action != "allow" {
		t.Fatalf("one dir %s %s", r.Action, r.Message)
	}
}

func TestRound10RedirectsWrappersAndInterpreters(t *testing.T) {
	home := t.TempDir()
	sub := filepath.Join(home, "work")
	blocks := []string{
		`> /dev/sda`,
		`command > /dev/sda`,
		`: > /dev/nvme0n1`,
		`dd if=/dev/zero of=/dev/sdb`,
		`echo x | tee /dev/sda`,
		`tee /dev/nvme0n1 >/dev/null`,
		`python3 -c 'import shutil; shutil.rmtree("/")'`,
		`python -c "import shutil; shutil.rmtree('/')"`,
		`node -e "require('fs').rmSync('/', {recursive:true})"`,
		`ruby -e 'require "fileutils"; FileUtils.rm_rf("/")'`,
		`python3 -c 'import os; os.system("rm -rf /")'`,
	}
	for _, c := range blocks {
		r := ScanAt(c, sub, home)
		if r.Action != "hardblock" || r.Exit != 121 || r.Approve {
			t.Errorf("block %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	catches := []string{
		`> /etc/passwd`,
		`command > /etc/passwd`,
		`> ~/.bash_profile`,
		`> ~/.bashrc`,
		`echo x > ~/.profile`,
		`echo x | tee /etc/passwd`,
		`echo x | tee ~/.bash_profile`,
		`env -i PATH=/usr/bin:/bin rm -rf /usr/bin`,
		`nice rm -rf /usr/bin`,
		`nohup rm -rf /bin`,
		`command rm -rf /usr/lib`,
		`timeout 5 rm -rf /etc`,
		`echo /usr/bin /bin | xargs rm -rf`,
		`echo /tmp/a /tmp/b | xargs rm -f`,
		`printf '%s\n' /tmp/a /tmp/b | xargs rm`,
	}
	for _, c := range catches {
		r := ScanAt(c, sub, home)
		if r.Action != "catch" && r.Action != "hardblock" {
			t.Errorf("miss %q -> %s %s", c, r.Action, r.Message)
			continue
		}
		if r.Action == "hardblock" && !r.Approve && r.Exit == 121 {
			// root wipes stay non-approvable; these targets are not /
			if strings.Contains(c, "/tmp/") || strings.Contains(c, "/usr") || strings.Contains(c, "/etc") || strings.Contains(c, "/bin") || strings.Contains(c, "passwd") || strings.Contains(c, ".bash") || strings.Contains(c, ".profile") {
				t.Errorf("no approve path %q -> %s approve %v", c, r.Action, r.Approve)
			}
		}
		if r.Action == "catch" && (r.Exit != 120 || !r.Approve) {
			t.Errorf("catch %q exit %d approve %v", c, r.Exit, r.Approve)
		}
	}
	if r := ScanAt(`echo /usr/bin /bin | xargs rm -rf`, sub, home); r.Action != "catch" || !r.Approve || r.Exit != 120 {
		t.Fatalf("xargs system %s approve %v exit %d %s", r.Action, r.Approve, r.Exit, r.Message)
	}
	allows := []string{
		`echo hi > /tmp/notes`,
		`echo hi >> ` + filepath.Join(sub, "log"),
		`python3 -c 'import shutil; shutil.rmtree("/tmp/job")'`,
		`node -e 'require("fs").rmSync("/tmp/job")'`,
		`env -i PATH=/usr/bin:/bin echo hi`,
		`echo /tmp/a | xargs ls`,
		`printf '%s\n' /tmp/one | xargs rm`,
	}
	for _, c := range allows {
		r := ScanAt(c, sub, home)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
}
