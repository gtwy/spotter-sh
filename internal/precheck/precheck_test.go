// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package precheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHardBlocks(t *testing.T) {
	blocks := []string{
		"rm -rf /",
		"rm -rf /*",
		"rm -rf ~",
		"rm -rf $HOME",
		"rm -fr /",
		"sudo rm -rf /",
		`:(){ :|:& };:`,
		"mkfs.ext4 /dev/sda",
		"dd if=/dev/zero of=/dev/sda",
		"chmod -R 777 /",
		`bash -c 'rm -rf /'`,
		"git commit -m 'rm -rf /' && true",
		"bomb(){ bomb|bomb &};bomb",
		`python -c 'import shutil; shutil.rmtree("/")'`,
		`python -c 'import os; os.unlink("/root")'`,
		`python3 -c 'shutil.rmtree(os.path.expanduser("~"))'`,
		"echo hi > /dev/sda",
		"wipefs /dev/nvme0n1",
		"blkdiscard /dev/sda",
		"shred /dev/sda",
		`.(){ .|.& };.`,
		`boom () { boom | boom & } ; boom`,
		`k(){ k|k; }; k`,
		`function f { f|f& }; f`,
		"dd if=/dev/audio of=/dev/hda",
	}
	for _, c := range blocks {
		r := Scan(c)
		if c == "git commit -m 'rm -rf /' && true" {
			if r.Action != "allow" {
				t.Errorf("quoted message must pass: %s -> %s", c, r.Action)
			}
			continue
		}
		if r.Action != "hardblock" || r.Exit != 121 {
			t.Errorf("want block %q got %s %d", c, r.Action, r.Exit)
		}
	}
}

func TestAllows(t *testing.T) {
	for _, c := range []string{
		"rm -rf ./build",
		"echo rm -rf /",
		"rm notes.txt",
		"chmod +x script.sh",
		"cat <<EOF\nrm -rf /\nEOF",
		"echo '> /dev/sda1'",
		`echo "> /dev/sda1"`,
		"# rm -rf /",
		"echo kept # rm -rf /",
		"deploy(){ build && ship; }",
		"up(){ warmup && up; }",
		"d(){ cd .. && echo hi; }",
		"log(){ echo hi | tee out; }",
		"python -c 'import shutil; shutil.rmtree(\"/tmp/job\")'",
		"python3 -c 'import shutil; shutil.rmtree(\"/var/tmp/build\")'",
		"mkfs.ext4 disk.img",
		"mkfs.ext4 ./images/root.img",
		"echo hi > /tmp/out.txt",
		"echo '> /etc/passwd'",
		`echo hi > "~/.bashrc"`,
		`echo hi > $'\x7e/.bashrc'`,
		`p(){ echo p | tr p q; }; p`,
		`f(){ f|f& }; : f`,
		`k(){ k|k; }`,
	} {
		r := Scan(c)
		if r.Action != "allow" {
			t.Errorf("want allow %q got %s %s", c, r.Action, r.Message)
		}
	}
}

func TestProtectedRedirect(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, c := range []string{
		"echo hi > /etc/passwd",
		"echo hi > /etc/shadow",
		"echo hi > ~/.bashrc",
		"echo hi >> ~/.ssh/authorized_keys",
		"printf x >| /etc/hosts",
		"echo hi > ~/.ssh/config",
		"echo hi >| ~/.ssh/config",
		"echo hi > \"$HOME/.bashrc\"",
		"echo hi > ${HOME}/.profile",
		"echo hi > ~/'.zshrc'",
		`echo hi > ~/".bashrc"`,
		`echo hi > "$HOME/../` + filepath.Base(home) + `/.bashrc"`,
	} {
		r := Scan(c)
		if r.Action != "catch" || r.Exit != 120 {
			t.Errorf("want catch %q got %s %d", c, r.Action, r.Exit)
		}
	}
}

func TestConfigRedirectOnlyExisting(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	fresh := "echo hi > ~/.config/app/settings"
	if r := Scan(fresh); r.Action != "allow" {
		t.Fatalf("new config file %s", r.Action)
	}
	log := "tool 2> ~/.config/app/run.log"
	if r := Scan(log); r.Action != "allow" {
		t.Fatalf("stderr log %s", r.Action)
	}
	path := home + "/.config/app/settings"
	if err := os.MkdirAll(home+"/.config/app", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := Scan("echo hi > ~/.config/app/settings"); r.Action != "catch" {
		t.Fatalf("overwrite config %s", r.Action)
	}
	if r := Scan("echo hi >> ~/.config/app/settings"); r.Action != "allow" {
		t.Fatalf("append config %s", r.Action)
	}
	if r := Scan("echo hi &> ~/.config/app/settings"); r.Action != "catch" {
		t.Fatalf("both-fd overwrite %s", r.Action)
	}
	real := t.TempDir()
	if err := os.WriteFile(real+"/.bashrc", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := t.TempDir() + "/linkhome"
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", link)
	if r := Scan("echo hi > ~/.bashrc"); r.Action != "catch" {
		t.Fatalf("symlinked home %s", r.Action)
	}
}

func TestLibRedirect(t *testing.T) {
	libc := ""
	for _, p := range []string{"/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6"} {
		if _, err := os.Lstat(p); err == nil {
			libc = p
			break
		}
	}
	if libc == "" {
		t.Skip("libc")
	}
	if r := Scan("echo hi > " + libc); r.Action != "catch" {
		t.Fatalf("libc redirect %s", r.Action)
	}
	if r := Scan("echo hi >> " + libc); r.Action != "allow" {
		t.Fatalf("libc append %s", r.Action)
	}
}

func TestDisguisedRM(t *testing.T) {
	r := Scan(`$'\x72m' -rf /`)
	if r.Action != "hardblock" {
		t.Fatalf("ansi-c rm: %s", r.Action)
	}
}

func TestQuotedDataIsNotABomb(t *testing.T) {
	for _, c := range []string{
		`echo ":(){ :|:& };:"`,
		`echo ':(){ :|:& };:'`,
		`grep -F ':(){ :|:& };:' notes.txt`,
		`printf '%s\n' ':(){ :|:& };:'`,
		`printf "%s\n" ":(){ :|:& };:"`,
		`rm -rf "~"`,
		`rm -rf "~/"`,
		`rm -rf '~'`,
		`rm -rf '$HOME'`,
	} {
		r := Scan(c)
		if r.Action != "allow" {
			t.Errorf("quoted data %q -> %s %s", c, r.Action, r.Message)
		}
	}
	bomb := Scan(`:(){ :|:& };:`)
	if bomb.Action != "hardblock" || bomb.Approve || bomb.Exit != 121 {
		t.Fatalf("real bomb %s approve %v exit %d", bomb.Action, bomb.Approve, bomb.Exit)
	}
	root := Scan("rm -rf /")
	if root.Action != "hardblock" || root.Approve {
		t.Fatalf("rm / approve %v action %s", root.Approve, root.Action)
	}
	if r := Scan(`rm -rf "$HOME"`); r.Action != "hardblock" {
		t.Fatalf("double quoted HOME %s", r.Action)
	}
}

func TestShellRedirects(t *testing.T) {
	home := t.TempDir()
	sub := filepath.Join(home, "work")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	link := filepath.Join(sub, "homelink")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	slashHome := home + "/"
	t.Setenv("HOME", slashHome)
	cases := []struct {
		cwd, home, cmd string
	}{
		{sub, home, "echo x > ${HOME:-..}/.bashrc"},
		{sub, slashHome, "echo x > ${HOME%/}/.bashrc"},
		{sub, home, "echo x > $PWD/../.bashrc"},
		{sub, home, "echo x > ~+/../.bashrc"},
		{sub, home, "echo x > homelink/.bashrc"},
		{sub, home, "cd ~ && echo x > .bashrc"},
		{sub, home, "cd " + home + " && echo x > .bashrc"},
	}
	for _, c := range cases {
		t.Setenv("HOME", c.home)
		r := ScanAt(c.cmd, c.cwd, c.home)
		if r.Action != "catch" {
			t.Errorf("%q cwd %s -> %s %s", c.cmd, c.cwd, r.Action, r.Message)
		}
	}
	t.Setenv("HOME", "")
	r := ScanAt("echo x > ${HOME:-..}/.bashrc", sub, home)
	if r.Action != "catch" {
		t.Fatalf("empty HOME default .. -> %s %s", r.Action, r.Message)
	}
	r = ScanAt("cd /no/such && echo x > .bashrc", home, home)
	if r.Action != "allow" {
		t.Fatalf("failed cd still redirected: %s", r.Action)
	}
}

func TestRound6CodeAndDirectory(t *testing.T) {
	home := t.TempDir()
	sub := filepath.Join(home, "work")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	bomb := `:(){ :|:& };:`
	blocks := []string{
		`eval '` + bomb + `'`,
		`eval 'b(){ b|b& };b'`,
		`echo '` + bomb + `' | bash`,
		`bash <<< '` + bomb + `'`,
		`a(){ b|b& }; b(){ a|a& }; a`,
		"bash <<EOF\n" + bomb + "\nEOF",
	}
	bare := Scan(bomb)
	if bare.Action != "hardblock" || bare.Approve || bare.Exit != 121 {
		t.Fatalf("bare bomb approve %v %s exit %d", bare.Approve, bare.Action, bare.Exit)
	}
	for _, c := range blocks {
		r := ScanAt(c, sub, home)
		if r.Action != "hardblock" || r.Exit != 121 || r.Approve {
			t.Errorf("bomb %q -> %s approve %v", c, r.Action, r.Approve)
		}
	}
	uncalled := ScanAt(`a(){ b|b& }; b(){ a|a& }`, sub, home)
	if uncalled.Action != "allow" {
		t.Fatalf("uncalled mutual %s %s", uncalled.Action, uncalled.Message)
	}
	py := ScanAt(`python3 -c 'shutil.rmtree("/")'`, sub, home)
	if py.Action != "hardblock" || py.Approve || py.Exit != 121 {
		t.Fatalf("rmtree / %s approve %v exit %d", py.Action, py.Approve, py.Exit)
	}
	if r := ScanAt(`python3 -c 'shutil.rmtree("/tmp/job")'`, sub, home); r.Action != "allow" {
		t.Fatalf("rmtree tmp %s", r.Action)
	}
	link := filepath.Join(sub, "rootlink")
	if err := os.Symlink("/", link); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"rm -rf rootlink/", "rm -rf ./rootlink/", "rm -rf rootlink/."} {
		r := ScanAt(c, sub, home)
		if r.Action != "hardblock" || r.Approve || r.Exit != 121 {
			t.Errorf("%s -> %s approve %v exit %d", c, r.Action, r.Approve, r.Exit)
		}
	}
	if r := ScanAt("rm -rf rootlink", sub, home); r.Action != "allow" {
		t.Fatalf("bare rootlink %s %s", r.Action, r.Message)
	}
	shellRM := ScanAt(`sh -c 'rm -rf ~'`, sub, home)
	direct := ScanAt(`rm -rf ~`, sub, home)
	if shellRM.Action != "hardblock" || shellRM.Approve || shellRM.Exit != direct.Exit || direct.Approve {
		t.Fatalf("sh -c %s approve %v direct %s approve %v", shellRM.Action, shellRM.Approve, direct.Action, direct.Approve)
	}
	allows := []string{
		"cat <<EOF\n" + bomb + "\nEOF",
		`echo '` + bomb + `'`,
		"(cd ~); echo x > .bashrc",
		"echo x | cd ~; echo x > .bashrc",
	}
	for _, c := range allows {
		r := ScanAt(c, sub, home)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
	catches := []string{
		"pushd ~ && echo x > .bashrc",
		"(cd ~ && echo x > .profile)",
	}
	for _, c := range catches {
		r := ScanAt(c, sub, home)
		if r.Action != "catch" {
			t.Errorf("catch %q -> %s %s", c, r.Action, r.Message)
		}
	}
}

func TestRound7BombsAndBraces(t *testing.T) {
	home := t.TempDir()
	sub := filepath.Join(home, "work")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	bomb := `:(){ :|:& };:`
	blocks := []string{
		`printf '` + bomb + `' | bash`,
		`printf '%s\n' '` + bomb + `' | sh`,
		`command eval '` + bomb + `'`,
		`builtin eval '` + bomb + `'`,
		`env eval '` + bomb + `'`,
		`env FOO=1 eval '` + bomb + `'`,
		`eval "$(echo '` + bomb + `')"`,
		"cat <<EOF | bash\n" + bomb + "\nEOF",
		`x(){ y|y& }; y(){ x|x& }; x`,
		`x(){ y; }; y(){ x; }; x`,
	}
	for _, c := range blocks {
		r := ScanAt(c, sub, home)
		if r.Action != "hardblock" || r.Exit != 121 || r.Approve {
			t.Errorf("bomb %q -> %s approve %v exit %d %s", c, r.Action, r.Approve, r.Exit, r.Message)
		}
	}
	allows := []string{
		`x(){ y; }; y(){ x; }`,
		`x(){ y|y& }; y(){ x|x& }`,
		`up(){ warmup && up; }`,
		`p(){ echo p | tr p q; }; p`,
		"cat <<EOF\n" + bomb + "\nEOF",
		`printf '` + bomb + `'`,
	}
	for _, c := range allows {
		r := ScanAt(c, sub, home)
		if r.Action != "allow" {
			t.Errorf("allow %q -> %s %s", c, r.Action, r.Message)
		}
	}
	braced := ScanAt("{ cd ~; echo x > .bashrc; }", sub, home)
	if braced.Action != "catch" {
		t.Fatalf("brace cd %s %s", braced.Action, braced.Message)
	}
	if r := ScanAt("(cd ~); echo x > .bashrc", sub, home); r.Action != "allow" {
		t.Fatalf("subshell cd %s %s", r.Action, r.Message)
	}
}
