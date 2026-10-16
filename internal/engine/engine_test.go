// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gtwy/spotter-sh/internal/config"
)

func homeDir(t *testing.T) string {
	t.Helper()
	h, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func decide(t *testing.T, cwd string, argv ...string) Outcome {
	t.Helper()
	return Decide(Input{
		Argv: argv, Cwd: cwd, Home: homeDir(t), Config: config.Defaults(), StdinKind: "null",
	})
}

func TestMustCatchClassify(t *testing.T) {
	dir := t.TempDir()
	home := homeDir(t)
	cases := [][]string{
		{"rm", "-rf", "/"},
		{"rm", "-rf", home},
		{"chmod", "-R", "777", "/"},
		{"chmod", "-R", "600", ".."},
	}
	for _, argv := range cases {
		o := decide(t, dir, argv...)
		if o.Action != "catch" && o.Action != "hardblock" {
			t.Errorf("%v action %s", argv, o.Action)
		}
	}
	// parent via ..
	o := decide(t, dir, "rm", "-rf", "..")
	if o.Action != "catch" {
		t.Fatalf("rm .. = %s", o.Action)
	}
}

func TestMustPassClassify(t *testing.T) {
	dir := t.TempDir()
	home := homeDir(t)
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "node_modules", "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	// .git as a file doesn't make a project root. Use a directory.
	os.Remove(filepath.Join(dir, ".git"))
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	passes := [][]string{
		{"rm", "-rf", filepath.Join(dir, "node_modules")},
		{"rm", filepath.Join(dir, "a.txt")},
		{"rm", "-rf", filepath.Join(dir, "nope")},
		{"chmod", "+x", filepath.Join(dir, "a.txt")},
		{"chmod", "644", filepath.Join(dir, "a.txt")},
		{"cp", filepath.Join(dir, "a.txt"), home},
		{"git", "status"},
		{"git", "add", "-A"},
		{"git", "push"},
	}
	for _, argv := range passes {
		o := decide(t, dir, argv...)
		if o.Action != "allow" {
			t.Errorf("want allow %v got %s (%s)", argv, o.Action, o.Consequence)
		}
	}
}

func TestBuildOutputNotExemptAtRoot(t *testing.T) {
	// A node_modules directory whose parent is not a project root is not exempt.
	// We don't create /node_modules. Resolve a fake path under / .
	o := Decide(Input{
		Argv: []string{"rm", "-rf", "/node_modules"}, Cwd: "/", Home: homeDir(t),
		Config: config.Defaults(), StdinKind: "null",
	})
	// /node_modules may not exist. Missing target is a single file, under threshold, allow.
	// The exemption must not be the reason. Check buildExempt directly.
	in := Input{Home: homeDir(t), Config: config.Defaults(), Cwd: "/"}
	if in.buildExempt("/node_modules") {
		t.Fatal("root node_modules must not be exempt")
	}
	_ = o
}

func TestSQL(t *testing.T) {
	dir := t.TempDir()
	catch := []string{
		"DELETE FROM orders",
		"DELETE FROM t WHERE 1=1",
		"UPDATE t SET x=1",
		"DROP TABLE t",
		"TRUNCATE t",
		"WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
		"/*! DROP TABLE t */",
	}
	for _, sql := range catch {
		o := decide(t, dir, "psql", "-c", sql)
		if o.Action != "catch" {
			t.Errorf("catch %q got %s", sql, o.Action)
		}
	}
	pass := []string{
		"SELECT 1",
		"UPDATE t SET x=1 WHERE id=5",
		"DELETE FROM t WHERE id=5",
	}
	for _, sql := range pass {
		o := decide(t, dir, "psql", "-c", sql)
		if o.Action != "allow" {
			t.Errorf("allow %q got %s %s", sql, o.Action, o.Consequence)
		}
	}
	dollar := "SELECT $tag$ DELETE FROM t $tag$"
	o := decide(t, dir, "psql", "-c", dollar)
	if o.Action != "allow" {
		t.Fatalf("dollar quote caught: %s", o.Consequence)
	}
	pipe := Decide(Input{Argv: []string{"psql"}, Cwd: dir, Home: homeDir(t), Config: config.Defaults(), StdinKind: "pipe"})
	if pipe.Action != "allow" || pipe.LogNote != "sql_unscanned" {
		t.Fatalf("pipe = %+v", pipe.LogNote)
	}
	inter := decide(t, dir, "psql")
	if inter.Action != "catch" || !inter.InjectSafe {
		t.Fatalf("interactive = %s inject %v", inter.Action, inter.InjectSafe)
	}
}

func TestGitForce(t *testing.T) {
	dir := t.TempDir()
	if decide(t, dir, "git", "push", "--force").Action != "catch" {
		t.Fatal("force")
	}
	if decide(t, dir, "git", "push", "--force-with-lease").Action != "allow" {
		t.Fatal("lease")
	}
	if decide(t, dir, "git", "branch", "-D", "old").Action != "catch" {
		t.Fatal("branch -D")
	}
}

func TestBulk(t *testing.T) {
	dir := t.TempDir()
	var argv []string
	argv = append(argv, "rm")
	for i := 0; i < 101; i++ {
		p := filepath.Join(dir, "f"+itoa(i))
		os.WriteFile(p, []byte("x"), 0o644)
		argv = append(argv, p)
	}
	o := decide(t, dir, argv...)
	if o.Action != "catch" || o.Level != "bulk" {
		t.Fatalf("bulk %s %s", o.Action, o.Level)
	}
}

func TestTimeoutIsCatch(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	if err := os.MkdirAll(filepath.Join(big, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := walkTree(big, 100000, 0, time.Now().Add(-time.Second))
	if !w.Timeout {
		t.Fatal("expected timeout")
	}
	cfg := config.Defaults()
	o := Decide(Input{
		Argv: []string{"rm", "-rf", big}, Cwd: dir, Home: homeDir(t), Config: cfg, StdinKind: "null",
		Deadline: time.Now().Add(-time.Second),
	})
	if o.Action != "catch" || o.Exit == 122 {
		t.Fatalf("timeout must be a catch, got %s exit %d", o.Action, o.Exit)
	}
	if !o.Affected.TimedOut {
		t.Fatal("timed_out not set")
	}
	if o.Affected.Partial == 0 || o.Affected.Count == 0 {
		t.Fatalf("timeout reported no progress: partial %d count %d", o.Affected.Partial, o.Affected.Count)
	}
}

func TestCorpus(t *testing.T) {
	dir := t.TempDir()
	home := homeDir(t)
	catch := [][]string{
		{"find", "/", "-name", "x", "-delete"},
		{"sudo", "xargs", "rm"},
		{"git", "push", "--force"},
		{"git", "branch", "-D", "old"},
		{"docker", "system", "prune", "-a", "--volumes"},
		{"terraform", "destroy"},
		{"kubectl", "delete", "ns", "prod"},
		{"aws", "s3", "rm", "s3://b", "--recursive"},
		{"crontab", "-r"},
		{"reboot"},
	}
	for _, argv := range catch {
		o := decide(t, dir, argv...)
		if o.Action == "allow" {
			t.Errorf("want catch %v", argv)
		}
	}
	if decide(t, dir, "dd", "if=a", "of=b").Action != "allow" {
		t.Fatal("dd files")
	}
	if decide(t, dir, "dd", "if=/dev/zero", "of=/dev/sda").Action != "hardblock" {
		t.Fatal("dd disk")
	}
	if decide(t, dir, "docker", "ps").Action != "allow" {
		t.Fatal("docker ps")
	}
	if decide(t, dir, "kubectl", "get", "pods").Action != "allow" {
		t.Fatal("kubectl get")
	}
	repo := filepath.Join(dir, "repo")
	os.MkdirAll(repo, 0o755)
	os.Mkdir(filepath.Join(repo, ".git"), 0o755)
	os.MkdirAll(filepath.Join(repo, "node_modules", "pkg"), 0o755)
	if decide(t, repo, "rm", "-rf", filepath.Join(repo, "node_modules")).Action != "allow" {
		t.Fatal("node_modules")
	}
	if in := (Input{Home: home, Config: config.Defaults()}); in.buildExempt(filepath.Join(home, "node_modules")) {
		t.Fatal("home node_modules exempt")
	}
}

func TestPrecheckNotHere(t *testing.T) {
	// engine hard-blocks rm -rf / . An admin cannot approve it.
	o := decide(t, t.TempDir(), "rm", "-rf", "/")
	if o.Action != "hardblock" || o.Exit != 121 || o.Approve {
		t.Fatalf("%s %s exit %d approve %v", o.Action, o.Level, o.Exit, o.Approve)
	}
}
