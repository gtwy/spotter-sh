// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package precheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRound9ForkBombs(t *testing.T) {
	bomb := `:(){ :|:& };:`
	mutual := `x(){ y|y& };y(){ x; };x`
	blocks := []string{
		`printf "` + bomb + `\n" | sh`,
		`printf '` + bomb + `\n' | sh`,
		`printf "` + bomb + `\n" | bash`,
		`printf '%s\n' '` + bomb + `' | sh`,
		"eval `echo \"" + bomb + "\"`",
		"eval `echo '" + bomb + "'`",
		"command eval `echo \"" + bomb + "\"`",
		"builtin eval `echo \"" + bomb + "\"`",
		"env eval `echo \"" + bomb + "\"`",
		"env FOO=1 eval `echo \"" + bomb + "\"`",
		`command eval '` + bomb + `'`,
		`builtin eval '` + bomb + `'`,
		`env eval '` + bomb + `'`,
		`command -p eval '` + bomb + `'`,
		`env -- eval '` + bomb + `'`,
		mutual,
		`x(){ y|y& };y(){ x; };x`,
		`x(){y|y&};y(){x;};x`,
		"x(){\n y | y &\n}\ny(){\n x\n}\nx",
		`x () { y | y & }; y () { x; }; x`,
		`function x { y|y&; }; function y { x; }; x`,
		`a(){ b|b& };b(){ c; };c(){ a; };a`,
		`printf '` + mutual + `\n' | sh`,
		"eval `echo \"" + mutual + "\"`",
		`command eval ` + "`echo \"" + mutual + "\"`",
	}
	for _, c := range blocks {
		r := Scan(c)
		if r.Action != "hardblock" || r.Exit != 121 || r.Approve {
			t.Errorf("bomb %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	allows := []string{
		`printf '` + bomb + `'`,
		`printf "` + bomb + `\n"`,
		`echo '` + bomb + `'`,
		`x(){ y|y& };y(){ x; }`,
		`x(){ y|y& };y(){ x|x& }`,
		`a(){ b|b& };b(){ c; };c(){ a; }`,
		`up(){ warmup && up; }`,
	}
	for _, c := range allows {
		r := Scan(c)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
}

func TestRound9LiteralTilde(t *testing.T) {
	home := t.TempDir()
	sub := filepath.Join(home, "work")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	allows := []string{
		`rm -rf "~"`,
		`rm -rf "~/"`,
		`rm -rf '~'`,
		`rm -rf '~/'`,
		`rm -rf \~`,
		`rm -rf \~/`,
		`chmod -R 700 '~'`,
		`chmod -R 700 "~"`,
		`chmod -R 700 \~`,
		`rm -rf -- $'~'`,
		`rm -rf -- $'~/'`,
	}
	for _, c := range allows {
		r := ScanAt(c, sub, home)
		if r.Action != "allow" {
			t.Errorf("literal %q -> %s %s", c, r.Action, r.Message)
		}
	}
	if r := ScanAt(`rm -rf ~`, sub, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("unquoted tilde %s approve %v", r.Action, r.Approve)
	}
	if r := ScanAt(`chmod -R 700 ~`, sub, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("unquoted chmod tilde %s approve %v", r.Action, r.Approve)
	}

	os.Unsetenv("D")
	if r := ScanAt(`rm -rf -- "${D:?}"/.`, sub, home); r.Action != "allow" {
		t.Fatalf("unset D:? %s %s", r.Action, r.Message)
	}
	if r := ScanAt(`rm -rf -- "${D?}"/.`, sub, home); r.Action != "allow" {
		t.Fatalf("unset D? %s %s", r.Action, r.Message)
	}
	dir := filepath.Join(sub, "data")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("D", dir)
	if r := ScanAt(`rm -rf -- "${D:?}"/.`, sub, home); r.Action != "allow" {
		t.Fatalf("set D:? %s %s", r.Action, r.Message)
	}
	t.Setenv("D", "/")
	if r := ScanAt(`rm -rf -- "${D:?}"/.`, sub, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("D:? of / %s approve %v", r.Action, r.Approve)
	}
	t.Setenv("D", home)
	if r := ScanAt(`rm -rf -- "${D:?}"/.`, sub, home); r.Action != "hardblock" || r.Approve {
		t.Fatalf("D:? of home %s approve %v %s", r.Action, r.Approve, r.Message)
	}
}

func TestRound9SubstAndFind(t *testing.T) {
	home := t.TempDir()
	sub := filepath.Join(home, "work")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	blocks := []string{
		`rm -rf $(echo /)`,
		`rm -rf "$(printf /)"`,
		`rm -rf $(echo /)/*`,
		`chmod -R 777 $(echo /)`,
		`find / -delete`,
		`find / -print0 | xargs -0 rm`,
		`find "$HOME" -delete`,
		`ls / | sed 's/^/\//' | xargs rm -rf`,
		`ls / | awk '{print "/" $1}' | xargs rm -rf`,
		`ls -1 / | sed 's,^,/,' | xargs rm -rf`,
		`ls / | xargs rm -rf`,
	}
	for _, c := range blocks {
		r := ScanAt(c, sub, home)
		if r.Action != "hardblock" || r.Exit != 121 || r.Approve {
			t.Errorf("block %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	sed := ScanAt(`ls / | sed 's/^/\//' | xargs rm -rf`, sub, home)
	awk := ScanAt(`ls / | awk '{print "/" $1}' | xargs rm -rf`, sub, home)
	if sed.Action != awk.Action || sed.Exit != awk.Exit || sed.Approve != awk.Approve {
		t.Fatalf("sed %s/%d awk %s/%d", sed.Action, sed.Exit, awk.Action, awk.Exit)
	}

	few := filepath.Join(sub, "few")
	if err := os.MkdirAll(few, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(filepath.Join(few, "f"+string(rune('a'+i))), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if r := ScanAt(`find `+few+` -print0 | xargs -0 rm`, sub, home); r.Action != "allow" {
		t.Fatalf("few find|xargs %s %s", r.Action, r.Message)
	}
	many := filepath.Join(sub, "many")
	if err := os.MkdirAll(many, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 150; i++ {
		name := "f" + itoa(i)
		if err := os.WriteFile(filepath.Join(many, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := ScanAt(`find `+many+` -print0 | xargs -0 rm`, sub, home)
	if r.Action != "catch" || r.Exit != 120 {
		t.Fatalf("many find|xargs %s exit %d %s", r.Action, r.Exit, r.Message)
	}
	if r := ScanAt(`find `+many+` -name '*.tmp' -print0 | xargs -0 rm`, sub, home); r.Action != "allow" {
		t.Fatalf("name filter %s %s", r.Action, r.Message)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
