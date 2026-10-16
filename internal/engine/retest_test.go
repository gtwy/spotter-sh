// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/gtwy/spotter-sh/internal/config"
)

func TestRetestDeletes(t *testing.T) {
	dir := t.TempDir()
	for _, root := range []string{"/bin", "/sbin", "/lib64", "/usr/bin"} {
		o := decide(t, dir, "rm", "-rf", root)
		if o.Action != "catch" && o.Action != "hardblock" {
			t.Errorf("rm -rf %s -> %s", root, o.Action)
		}
	}
	o := decide(t, dir, "shred", "/dev/sda")
	if o.Action != "hardblock" {
		t.Fatalf("shred disk %s", o.Action)
	}
	o = decide(t, dir, "rm", "/var/log/nginx/access.log")
	if o.Action != "allow" {
		t.Fatalf("one log file %s %s", o.Action, o.Consequence)
	}
	o = decide(t, dir, "rm", "-rf", "/var/log")
	if o.Action != "catch" {
		t.Fatalf("rm -rf /var/log %s", o.Action)
	}
	o = decide(t, dir, "rm", "-rf", "/var/log/nginx")
	if o.Action != "catch" {
		t.Fatalf("rm -rf log dir %s", o.Action)
	}
}

func TestBrainNotes(t *testing.T) {
	brain := t.TempDir()
	mem := filepath.Join(brain, "memory")
	people := filepath.Join(brain, "people")
	if err := os.MkdirAll(mem, 0o755); err != nil || os.MkdirAll(people, 0o755) != nil {
		t.Fatal(err)
	}
	one := filepath.Join(mem, "one.md")
	two := filepath.Join(people, "two.md")
	if err := os.WriteFile(one, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(two, []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPOTTER_SH_BRAIN", brain)
	cwd := t.TempDir()
	if o := decide(t, cwd, "rm", one); o.Action != "allow" {
		t.Fatalf("one note %s %s", o.Action, o.Consequence)
	}
	if o := decide(t, cwd, "rm", "-f", one); o.Action != "allow" {
		t.Fatalf("one note -f %s", o.Action)
	}
	if o := decide(t, cwd, "rm", "-rf", mem); o.Action != "catch" {
		t.Fatalf("brain folder %s", o.Action)
	}
	if o := decide(t, cwd, "rm", one, two); o.Action != "catch" {
		t.Fatalf("two notes %s", o.Action)
	}
}

func TestFindExecPlusAndMarker(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, ".spotter-sh-protect"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := decide(t, root, "find", root, "-exec", "rm", "{}", "+")
	if o.Action != "catch" {
		t.Fatalf("find -exec + marker %s %s", o.Action, o.Consequence)
	}
	o = decide(t, root, "find", root, "-exec", "rm", "{}", ";")
	if o.Action != "allow" {
		t.Fatalf("per-file exec %s", o.Action)
	}
}

func TestSQLSourceAndCmd(t *testing.T) {
	dir := t.TempDir()
	sql := filepath.Join(dir, "drop.sql")
	if err := os.WriteFile(sql, []byte("DROP TABLE t;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := Decide(Input{
		Argv: []string{"mysql", "-e", "source " + sql}, Cwd: dir, Home: dir,
		Config: config.Defaults(), StdinKind: "null",
	})
	if o.Action != "catch" {
		t.Fatalf("mysql source %s %s", o.Action, o.Consequence)
	}
	o = Decide(Input{
		Argv: []string{"sqlite3", "app.db", "-cmd", "DROP TABLE t"}, Cwd: dir, Home: dir,
		Config: config.Defaults(), StdinKind: "null",
	})
	if o.Action != "catch" {
		t.Fatalf("sqlite -cmd %s %s", o.Action, o.Consequence)
	}
	o = Decide(Input{
		Argv: []string{"sqlite3", "app.db", "-cmd", "SELECT 1"}, Cwd: dir, Home: dir,
		Config: config.Defaults(), StdinKind: "null",
	})
	if o.Action != "allow" {
		t.Fatalf("sqlite select %s", o.Action)
	}
}

func TestGitCleanForce(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com", "GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	run("init")
	if err := os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "keep.txt")
	run("commit", "-m", "keep")
	if err := os.WriteFile(filepath.Join(dir, "junk.txt"), []byte("j"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := Decide(Input{
		Argv: []string{"git", "clean", "-f"}, Cwd: dir, Home: dir,
		Config: config.Defaults(), StdinKind: "null",
	})
	if o.Action != "catch" {
		t.Fatalf("git clean -f %s %s", o.Action, o.LogNote)
	}
	if err := os.Remove(filepath.Join(dir, "junk.txt")); err != nil {
		t.Fatal(err)
	}
	o = Decide(Input{
		Argv: []string{"git", "clean", "-f"}, Cwd: dir, Home: dir,
		Config: config.Defaults(), StdinKind: "null",
	})
	if o.Action != "allow" {
		t.Fatalf("clean tree %s %s", o.Action, o.Consequence)
	}
}

func TestLinkOntoProtected(t *testing.T) {
	dir := t.TempDir()
	o := decide(t, dir, "ln", "-s", "/tmp/elsewhere", "/etc/passwd")
	if o.Action != "catch" {
		t.Fatalf("ln -s onto passwd %s", o.Action)
	}
	o = decide(t, dir, "ln", "-s", "/etc/passwd", filepath.Join(dir, "out"))
	if o.Action != "allow" {
		t.Fatalf("ln -s of a protected source %s %s", o.Action, o.Consequence)
	}
	o = decide(t, dir, "ln", "-s", "/etc/hostname", filepath.Join(dir, "out"))
	if o.Action != "allow" {
		t.Fatalf("ln -s %s %s", o.Action, o.Consequence)
	}
}

func TestEmptyDirTimeoutIsCatch(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		if err := os.MkdirAll(filepath.Join(dir, "d", string(rune('a'+i))), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Defaults()
	cfg.Thresholds.TreeFiles = 3
	o := Decide(Input{
		Argv: []string{"rm", "-rf", dir}, Cwd: t.TempDir(), Home: t.TempDir(),
		Config: cfg, StdinKind: "null",
	})
	if o.Action != "catch" {
		t.Fatalf("many empty dirs %s", o.Action)
	}
	home := t.TempDir()
	past := Decide(Input{
		Argv: []string{"rm", "-rf", dir}, Cwd: home, Home: home,
		Config: config.Defaults(), StdinKind: "null",
		Deadline: time.Now().Add(-time.Second),
	})
	if past.Action != "catch" || !past.Affected.TimedOut {
		t.Fatalf("past deadline %+v", past.Affected)
	}
}

func TestRound3Classify(t *testing.T) {
	home := t.TempDir()
	brain := filepath.Join(home, "agent-notes", "memory")
	if err := os.MkdirAll(brain, 0o755); err != nil {
		t.Fatal(err)
	}
	note := filepath.Join(brain, "one.md")
	if err := os.WriteFile(note, []byte("n"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(brain, "two.md")
	if err := os.WriteFile(other, []byte("t"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPOTTER_SH_BRAIN", filepath.Join(home, "agent-notes"))
	cwd := t.TempDir()
	in := func(argv ...string) Outcome {
		return Decide(Input{Argv: argv, Cwd: cwd, Home: home, Config: config.Defaults(), StdinKind: "null"})
	}
	if o := in("rm", note); o.Action != "allow" {
		t.Fatalf("one brain note %s %s", o.Action, o.Consequence)
	}
	if o := in("rm", "-rf", filepath.Dir(note)); o.Action != "catch" {
		t.Fatalf("brain folder %s", o.Action)
	}
	if o := in("rm", note, other); o.Action != "catch" {
		t.Fatalf("two notes %s", o.Action)
	}
	if o := in("chmod", "-x", "/bin/chmod"); o.Action != "catch" {
		t.Fatalf("chmod /bin/chmod %s %s", o.Action, o.Consequence)
	}
	if o := in("find", "/var/log", "-delete"); o.Action != "catch" {
		t.Fatalf("find /var/log -delete %s %s", o.Action, o.Consequence)
	}
	if o := in("dd", "if=/dev/audio", "of=/dev/hda"); o.Action != "hardblock" {
		t.Fatalf("dd hda %s", o.Action)
	}
	sql := filepath.Join(cwd, "drop.sql")
	if err := os.WriteFile(sql, []byte("DROP TABLE t;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if o := in("psql", "-c", `\i `+sql); o.Action != "catch" {
		t.Fatalf("psql \\i %s %s", o.Action, o.Consequence)
	}
	keep := filepath.Join(cwd, "keep.sql")
	if err := os.WriteFile(keep, []byte("SELECT 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if o := in("psql", "-c", `\i `+keep); o.Action != "allow" {
		t.Fatalf("psql \\i select %s", o.Action)
	}

	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.tmp"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, ".spotter-sh-protect"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if o := in("find", root, "-maxdepth", "1", "-delete"); o.Action != "allow" {
		t.Fatalf("maxdepth delete %s %s", o.Action, o.Consequence)
	}
	if o := in("find", root, "-delete"); o.Action != "catch" {
		t.Fatalf("full find -delete %s", o.Action)
	}
	bin := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Defaults()
	cfg.Thresholds.BulkTargets = 2
	wide := Decide(Input{
		Argv: []string{"find", bin, "-exec", "chmod", "000", "{}", "+"},
		Cwd:  cwd, Home: home, Config: cfg, StdinKind: "null",
	})
	if wide.Action != "catch" {
		t.Fatalf("find -exec chmod 000 + %s %s", wide.Action, wide.Consequence)
	}
	small := config.Defaults()
	few := Decide(Input{
		Argv: []string{"find", bin, "-name", "a", "-exec", "rm", "{}", "+"},
		Cwd:  cwd, Home: home, Config: small, StdinKind: "null",
	})
	if few.Action != "allow" {
		t.Fatalf("small find -exec rm %s %s", few.Action, few.Consequence)
	}
	if err := os.WriteFile(filepath.Join(bin, "d"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	tree := config.Defaults()
	tree.Thresholds.BulkTargets = 1
	tree.Thresholds.TreeFiles = 3
	deep := Decide(Input{
		Argv: []string{"find", bin, "-mindepth", "1", "-type", "f", "-exec", "rm", "-r", "{}", "+"},
		Cwd:  cwd, Home: home, Config: tree, StdinKind: "null",
	})
	if deep.Action != "catch" {
		t.Fatalf("find -exec rm -r over tree %s %s", deep.Action, deep.Consequence)
	}
	if o := in("find", "/var/log", "-exec", "rm", "{}", "+"); o.Action != "catch" {
		t.Fatalf("find -exec rm + /var/log %s %s", o.Action, o.Consequence)
	}
	src := filepath.Join(cwd, "src")
	dst := filepath.Join(cwd, "dst")
	if err := os.MkdirAll(src, 0o755); err != nil || os.MkdirAll(dst, 0o755) != nil {
		t.Fatal(err)
	}
	if o := in("rsync", "-n", "-a", "--delete", src, "/etc"); o.Action != "allow" {
		t.Fatalf("rsync -n %s %s", o.Action, o.Consequence)
	}
	if o := in("rsync", "-a", "--delete", src, "/etc"); o.Action != "catch" {
		t.Fatalf("rsync --delete /etc %s", o.Action)
	}
	if o := in("env", "-i", "true"); o.Action != "allow" {
		t.Fatalf("env -i %s %s", o.Action, o.Consequence)
	}

	if err := os.WriteFile(filepath.Join(home, ".bashrc"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if o := in("find", home, "-maxdepth", "1", "-name", ".bashrc", "-delete"); o.Action != "catch" {
		t.Fatalf("find bashrc %s %s", o.Action, o.Consequence)
	}
	if o := in("find", "/var/log", "-type", "f", "-delete"); o.Action != "catch" {
		t.Fatalf("find log type f %s", o.Action)
	}
	if o := in("find", "/var/log", "-mindepth", "1", "-delete"); o.Action != "catch" {
		t.Fatalf("find log mindepth %s", o.Action)
	}
	link := filepath.Join(cwd, "link")
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Fatal(err)
	}
	if o := in("rm", link); o.Action != "allow" {
		t.Fatalf("rm symlink %s %s", o.Action, o.Consequence)
	}
	if o := in("unlink", link); o.Action != "allow" {
		t.Fatalf("unlink symlink %s %s", o.Action, o.Consequence)
	}
	quoted := Decide(Input{
		Argv: []string{"rm", "-rf", "~/src/project"},
		Cwd:  cwd, Home: home, Config: config.Defaults(), StdinKind: "null",
	})
	if quoted.Action != "allow" {
		t.Fatalf("quoted tilde %s %s", quoted.Action, quoted.Consequence)
	}
	sshFile := filepath.Join(home, ".ssh", "id_example")
	if o := in("rm", "-rf", sshFile); o.Action != "catch" {
		t.Fatalf("ssh path %s %s", o.Action, o.Consequence)
	}
	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		t.Fatal(err)
	}
	t.Setenv("HOME", "")
	bare := Decide(Input{
		Argv:      []string{"rm", "-rf", filepath.Join(u.HomeDir, ".ssh", "spotter-sh-env-i-probe")},
		Cwd:       cwd,
		Home:      "",
		Config:    config.Defaults(),
		StdinKind: "null",
	})
	if bare.Action != "catch" {
		t.Fatalf("passwd home ssh %s %s", bare.Action, bare.Consequence)
	}
	drop := filepath.Join(cwd, "drop.sql")
	if err := os.WriteFile(drop, []byte("DROP TABLE t;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if o := in("psql", "-c", `\ir `+drop); o.Action != "catch" {
		t.Fatalf("psql \\ir %s %s", o.Action, o.Consequence)
	}
	if o := in("mysql", "-e", "SELECT 1; source "+drop); o.Action != "catch" {
		t.Fatalf("mysql source %s %s", o.Action, o.Consequence)
	}
	if o := in("sqlite3", "db", "-cmd", ".read "+drop); o.Action != "catch" {
		t.Fatalf("sqlite .read %s %s", o.Action, o.Consequence)
	}
}

func TestSystemctlUserStop(t *testing.T) {
	dir := t.TempDir()
	o := decide(t, dir, "systemctl", "--user", "stop", "spotter-sh-no-such-unit")
	if o.Action != "allow" {
		t.Fatalf("--user stop of a missing unit %s %s", o.Action, o.Consequence)
	}
}
