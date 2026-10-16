// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gtwy/spotter-sh/internal/config"
	"github.com/gtwy/spotter-sh/internal/precheck"
)

func reviewDecide(home, cwd, kind string, argv ...string) Outcome {
	if kind == "" {
		kind = "null"
	}
	return Decide(Input{
		Argv: argv, Cwd: cwd, Home: home, Config: config.Defaults(), StdinKind: kind,
	})
}

func TestReviewFindings(t *testing.T) {
	home := t.TempDir()
	site := filepath.Join(home, "site")
	repo := filepath.Join(home, "src", "project")
	state := filepath.Join(home, ".appstate")
	ResetRegistry()
	t.Cleanup(ResetRegistry)
	RegisterProtected(repo + "/**")
	RegisterProtected(state + "/**")
	for _, dir := range []string{
		site, filepath.Join(site, ".git"), filepath.Join(site, "node_modules", "pkg"),
		filepath.Join(site, "build"), filepath.Join(site, "images"),
		repo, state, filepath.Join(home, "src", "other"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(home, "notes.txt"), "note\n")
	write(filepath.Join(home, "a.log"), "log\n")
	write(filepath.Join(home, "b.txt"), "b\n")
	write(filepath.Join(home, ".hidden"), "dot\n")
	write(filepath.Join(state, "state.json"), "{}\n")
	write(filepath.Join(repo, "go.mod"), "module example.com/project\n")
	write(filepath.Join(repo, "main.go"), "package main\n")
	write(filepath.Join(home, "src", "other", "app.go"), "package other\n")
	write(filepath.Join(site, "index.html"), "<p>ok</p>\n")
	write(filepath.Join(site, "old.html"), "<p>old</p>\n")
	write(filepath.Join(site, "node_modules", "pkg", "x.js"), "x\n")
	write(filepath.Join(site, "build", "out.js"), "o\n")
	write(filepath.Join(site, "images", "root.img"), "img\n")
	write(filepath.Join(site, "disk.img"), "img\n")
	write(filepath.Join(site, "drop.sql"), "DROP TABLE orders;\n")
	write(filepath.Join(site, "keep.sql"), "SELECT 1;\n")
	write(filepath.Join(site, "a.tmp"), "t\n")
	src := filepath.Join(site, "payload")
	dst := filepath.Join(site, "mirror")
	if err := os.MkdirAll(src, 0o755); err != nil || os.MkdirAll(dst, 0o755) != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		write(filepath.Join(src, name), name)
		write(filepath.Join(dst, name), name)
	}

	passN, catchN, fp, fn := 0, 0, 0, 0
	pass := func(argv ...string) {
		t.Helper()
		passN++
		o := reviewDecide(home, site, "null", argv...)
		if o.Action != "allow" {
			fp++
			t.Errorf("FP %v -> %s %s", argv, o.Action, o.Consequence)
		}
	}
	catch := func(argv ...string) {
		t.Helper()
		catchN++
		o := reviewDecide(home, site, "null", argv...)
		if o.Action == "allow" {
			fn++
			t.Errorf("FN %v", argv)
		}
	}
	catchKind := func(kind string, argv ...string) {
		t.Helper()
		catchN++
		o := reviewDecide(home, site, kind, argv...)
		if o.Action == "allow" {
			fn++
			t.Errorf("FN %v (%s)", argv, kind)
		}
	}

	// Priority 1 false negatives.
	catch("rm", "-rf", repo)
	catch("rm", "-rf", filepath.Join(repo, "main.go"))
	catch("rm", "-rf", state)
	catch("rm", "-rf", filepath.Join(state, "state.json"))
	globHome := filepath.Join(home, "globhome")
	if err := os.MkdirAll(globHome, 0o755); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(globHome, "a.txt"), "a\n")
	write(filepath.Join(globHome, "b.txt"), "b\n")
	write(filepath.Join(globHome, ".keep"), "dot\n")
	catchN++
	if reviewDecide(globHome, globHome, "null", "rm", "-rf", filepath.Join(globHome, "a.txt"), filepath.Join(globHome, "b.txt")).Action == "allow" {
		fn++
		t.Error("FN rm of every visible file in a home that still has dotfiles")
	}
	catch("psql", "-q", "-c", "DROP TABLE orders")
	catch("psql", "-qc", "DROP TABLE orders")
	catch("psql", "--command", "DROP DATABASE shop")
	catch("psql", "-f", "drop.sql")
	catch("psql", "--file", "drop.sql")
	catch("psql", "--file=drop.sql")
	catch("mysql", "-e", "DROP DATABASE shop")
	catch("mysql", "--execute", "DROP DATABASE shop")
	catch("mariadb", "-e", "DROP TABLE orders")
	catch("clickhouse-client", "-q", "DROP TABLE t")
	catch("cockroach", "-e", "DROP DATABASE shop")

	// Same class: flag values are not the destructive operand.
	pass("psql", "-q", "-c", "SELECT 1")
	pass("psql", "-c", "SELECT 1")
	pass("psql", "-f", "keep.sql")
	pass("mysql", "-e", "UPDATE t SET x=1 WHERE id=5")
	pass("mysql", "-f", "-e", "SELECT 1")
	pass("clickhouse-client", "-q", "SELECT 1")
	catch("psql")
	catch("mysql")
	passKind := func(kind string, argv ...string) {
		t.Helper()
		passN++
		o := reviewDecide(home, site, kind, argv...)
		if o.Action != "allow" {
			fp++
			t.Errorf("FP %v (%s) -> %s %s", argv, kind, o.Action, o.Consequence)
		}
	}
	passKind("null", "sqlite3", "app.db")
	catchKind("tty", "sqlite3", "app.db")
	pass("sqlite3", "app.db", ".tables")
	catch("sqlite3", "app.db", ".read drop.sql")
	pass("sqlite3", "app.db", ".read keep.sql")

	// Routine deletes stay quiet. A single home file is not a sweep.
	pass("rm", filepath.Join(home, "notes.txt"))
	pass("rm", filepath.Join(site, "old.html"))
	pass("rm", filepath.Join(site, "index.html"))
	pass("rm", "-rf", filepath.Join(site, "node_modules"))
	pass("rm", "-rf", filepath.Join(site, "build"))
	pass("rm", filepath.Join(home, "src", "other", "app.go"))
	pass("rm", filepath.Join(home, "a.log"))

	// Priority 3: find, rsync, mkfs, disk image.
	pass("find", ".", "-name", "*.tmp", "-delete")
	pass("find", home, "-maxdepth", "1", "-name", "*.log", "-delete")
	pass("find", ".", "-newer", "/etc/passwd", "-delete")
	pass("find", ".", "-name", "*.go")
	catch("find", "/", "-name", "*.conf", "-delete")
	catch("find", "/", "-delete")
	catch("find", "/etc", "-name", "passwd", "-delete")
	pass("rsync", "-a", src, dst)
	pass("rsync", "-a", "--delete", src, dst)
	pass("rsync", "-a", "--delete", "--exclude", "/etc/passwd", src, dst)
	catch("rsync", "-a", "--delete", src, "/etc")
	pass("mkfs.ext4", filepath.Join(site, "disk.img"))
	pass("mkfs.ext4", filepath.Join(site, "images", "root.img"))
	pass("wipefs", filepath.Join(site, "disk.img"))
	catch("mkfs.ext4", "/dev/sda1")
	catch("wipefs", "/dev/nvme0n1")
	catch("blkdiscard", "/dev/sda")
	catch("dd", "if=/dev/zero", "of=/dev/sda")
	pass("dd", "if=a", "of=b")

	// Everyday list and look-alikes.
	for _, argv := range [][]string{
		{"ls", "-la"},
		{"grep", "-r", "foo", "."},
		{"cat", "index.html"},
		{"git", "status"},
		{"git", "add", "index.html"},
		{"git", "commit"},
		{"git", "pull"},
		{"git", "push"},
		{"git", "checkout", "-b", "wip"},
		{"git", "push", "--force-with-lease"},
		{"tar", "-czf", "a.tgz", "src"},
		{"make"},
		{"go", "build", "./..."},
		{"npm", "ci"},
		{"cp", filepath.Join(site, "index.html"), home},
		{"mv", filepath.Join(site, "old.html"), filepath.Join(site, "index.html")},
		{"chmod", "+x", filepath.Join(site, "index.html")},
		{"chmod", "644", filepath.Join(site, "index.html")},
		{"chmod", "-R", "755", site},
		{"docker", "ps"},
		{"kubectl", "get", "pods"},
		{"redis-cli", "GET", "k"},
		{"echo", "> /dev/sda1"},
		{"echo", "rm -rf /"},
	} {
		pass(argv...)
	}
	for _, argv := range [][]string{
		{"rm", "-rf", home},
		{"rm", "-rf", "/"},
		{"rm", "-rf", "/etc"},
		{"chmod", "-R", "777", "/"},
		{"chmod", "-R", "600", ".."},
		{"git", "push", "--force"},
		{"git", "branch", "-D", "old"},
		{"sudo", "rm", "-rf", "/etc"},
		{"docker", "system", "prune", "-a", "--volumes"},
		{"kubectl", "delete", "ns", "prod"},
		{"terraform", "destroy"},
		{"aws", "s3", "rm", "s3://b", "--recursive"},
		{"crontab", "-r"},
		{"reboot"},
		{"psql", "-c", "DELETE FROM orders"},
		{"mysql", "-e", "DELETE FROM t WHERE 1=1"},
		{"redis-cli", "FLUSHALL"},
	} {
		catch(argv...)
	}

	// Layer 1 text cases the shim's precheck sees before bash runs.
	textPass := []string{
		"echo '> /dev/sda1'",
		`echo "> /dev/sda1"`,
		"# rm -rf /",
		"echo kept # rm -rf /",
		"deploy(){ build && ship; }",
		"up(){ warmup && up; }",
		"d(){ cd .. && echo hi; }",
		"log(){ echo hi | tee out; }",
		`python -c 'import shutil; shutil.rmtree("/tmp/job")'`,
		`python3 -c 'import shutil; shutil.rmtree("/var/tmp/build")'`,
		"mkfs.ext4 disk.img",
		"rm -rf ./build",
		"git commit -m 'revert the rm -rf ~ change'",
		"echo do not run rm -rf /",
	}
	textCatch := []string{
		"rm -rf /",
		"rm -rf /*",
		":(){ :|:& };:",
		"bomb(){ bomb|bomb &};bomb",
		"mkfs.ext4 /dev/sda",
		"dd if=/dev/zero of=/dev/sda",
		"chmod -R 777 /",
		`bash -c 'rm -rf /'`,
		`python -c 'import shutil; shutil.rmtree("/")'`,
		`python -c 'import os; os.unlink("/home")'`,
		"echo hi > /dev/sda1",
		"wipefs /dev/sda",
	}
	for _, c := range textPass {
		passN++
		if precheck.Scan(c).Action != "allow" {
			fp++
			t.Errorf("FP text %q -> %s", c, precheck.Scan(c).Action)
		}
	}
	for _, c := range textCatch {
		catchN++
		if precheck.Scan(c).Action == "allow" {
			fn++
			t.Errorf("FN text %q", c)
		}
	}

	// Category expansion in the shape of the review corpus: flag order,
	// protected roots, SQL clients, disk paths, and everyday commands.
	for _, root := range []string{"/", "/etc", "/usr", "/var", "/opt", "/boot", "/root", "/home", home, repo, state} {
		catch("rm", "-rf", root)
		catch("rm", "-fr", root)
		catch("rm", "--recursive", "--force", root)
		catch("chmod", "-R", "777", root)
		catch("chmod", "-R", "000", root)
		catch("find", root, "-delete")
	}
	catch("find", "/", "-name", "x", "-delete")
	for _, root := range []string{repo, state} {
		pass("find", root, "-name", "x", "-delete")
	}
	for _, dev := range []string{"/dev/sda", "/dev/sda1", "/dev/sdb", "/dev/nvme0n1", "/dev/nvme1n1", "/dev/mmcblk0", "/dev/vda", "/dev/xvda", "/dev/mapper/data"} {
		catch("mkfs.ext4", dev)
		catch("wipefs", dev)
		catch("blkdiscard", dev)
		catch("dd", "if=/dev/zero", "of="+dev)
	}
	for _, sql := range []string{
		"DROP TABLE orders", "DROP DATABASE shop", "TRUNCATE orders",
		"DELETE FROM orders", "DELETE FROM orders WHERE 1=1", "UPDATE orders SET paid=1",
	} {
		catch("psql", "-c", sql)
		catch("psql", "-q", "-c", sql)
		catch("mysql", "-e", sql)
		catch("mariadb", "--execute", sql)
	}
	for _, sql := range []string{
		"SELECT 1", "SELECT * FROM orders WHERE id=5",
		"UPDATE orders SET paid=1 WHERE id=5", "DELETE FROM orders WHERE id=5",
		"INSERT INTO orders (id) VALUES (5)",
	} {
		pass("psql", "-c", sql)
		pass("psql", "-q", "-c", sql)
		pass("mysql", "-e", sql)
		pass("mariadb", "-e", sql)
	}
	for i := 0; i < 40; i++ {
		name := filepath.Join(site, "page-"+itoa(i)+".html")
		write(name, "ok\n")
		pass("rm", name)
		pass("chmod", "644", name)
	}
	for _, argv := range [][]string{
		{"ls", "-la"}, {"pwd"}, {"git", "diff"}, {"git", "log"}, {"git", "show"},
		{"git", "fetch"}, {"git", "stash", "list"}, {"make", "test"}, {"go", "test", "./..."},
		{"npm", "test"}, {"docker", "images"}, {"docker", "logs", "web"},
		{"kubectl", "describe", "pod", "web"}, {"kubectl", "get", "deploy"},
		{"cat", "index.html"}, {"head", "index.html"}, {"tail", "index.html"},
		{"cp", "index.html", "old.html"}, {"mv", "a.tmp", "b.tmp"},
		{"find", ".", "-name", "*.html"}, {"find", ".", "-type", "f"},
		{"tar", "-tzf", "a.tgz"}, {"echo", "hello"}, {"true"},
	} {
		pass(argv...)
	}
	for _, img := range []string{"disk.img", "root.img", "backup.img", "vm.raw"} {
		path := filepath.Join(site, "images", img)
		write(path, "img\n")
		pass("mkfs.ext4", path)
		pass("wipefs", path)
	}
	for _, c := range []string{
		"echo '> /dev/sdb'", "echo '> /dev/nvme0n1'", "# rm -rf /etc",
		"# chmod -R 777 /", "echo kept # mkfs /dev/sda",
		"ship(){ test -d dist && rm -rf dist; }",
		"up(){ test -x ./bin && up; }",
		"d(){ cd .. && pwd; }",
		"log(){ printf hi | tee run.log; }",
		`python -c 'shutil.rmtree("/tmp/build-1")'`,
		`python -c 'shutil.rmtree("/tmp/build-2")'`,
		`python -c 'os.unlink("/var/tmp/job")'`,
		"mkfs.ext4 ./disk.img", "mkfs.ext4 images/backup.img",
		"rm -rf ./build", "rm notes.txt", "chmod +x run.sh",
	} {
		passN++
		if precheck.Scan(c).Action != "allow" {
			fp++
			t.Errorf("FP text %q -> %s", c, precheck.Scan(c).Action)
		}
	}
	for _, c := range []string{
		"rm -rf /", "rm -rf /*", "rm -rf ~", "sudo rm -rf /",
		":(){ :|:& };:", "bomb(){ bomb | bomb & };bomb",
		"f(){ f& };f", "mkfs.ext4 /dev/sda", "mkfs.xfs /dev/nvme0n1",
		"wipefs /dev/sdb", "dd if=/dev/zero of=/dev/vda",
		"chmod -R 777 /", `bash -c 'rm -rf /'`,
		`python -c 'shutil.rmtree("/")'`,
		`python -c 'shutil.rmtree("/root")'`,
		`python -c 'os.unlink("/home")'`,
		"echo hi > /dev/sda", "echo hi > /dev/nvme0n1",
	} {
		catchN++
		if precheck.Scan(c).Action == "allow" {
			fn++
			t.Errorf("FN text %q", c)
		}
	}

	t.Logf("review corpus: pass=%d catch=%d fp=%d fn=%d", passN, catchN, fp, fn)
	if fn != 0 || fp != 0 {
		t.Fatalf("corpus fp=%d fn=%d", fp, fn)
	}
}

func TestScopedDeleteCounts(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "tree")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		name := "f" + string(rune('a'+i)) + ".txt"
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "only.tmp"), []byte("t"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Thresholds.TreeFiles = 2
	narrow := Decide(Input{
		Argv: []string{"find", ".", "-name", "*.tmp", "-delete"},
		Cwd:  dir, Home: home, Config: cfg, StdinKind: "null",
	})
	if narrow.Action != "allow" {
		t.Fatalf("name filter counted the tree: %s %s", narrow.Action, narrow.Consequence)
	}
	wide := Decide(Input{
		Argv: []string{"find", ".", "-delete"},
		Cwd:  dir, Home: home, Config: cfg, StdinKind: "null",
	})
	if wide.Action != "catch" {
		t.Fatal("unfiltered find -delete under the ceiling was allowed")
	}

	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.MkdirAll(src, 0o755); err != nil || os.MkdirAll(dst, 0o755) != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		name := "n" + string(rune('a'+i))
		body := []byte("x")
		if err := os.WriteFile(filepath.Join(src, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	same := Decide(Input{
		Argv: []string{"rsync", "-a", "--delete", src, dst},
		Cwd:  dir, Home: home, Config: cfg, StdinKind: "null",
	})
	if same.Action != "allow" {
		t.Fatalf("rsync --delete counted the destination: %s %s", same.Action, same.Consequence)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	extras := Decide(Input{
		Argv: []string{"rsync", "-a", "--delete", empty, dst},
		Cwd:  dir, Home: home, Config: cfg, StdinKind: "null",
	})
	if extras.Action != "catch" {
		t.Fatal("rsync --delete of files absent from the source was allowed")
	}
}

func TestHomeSweepSkipsDotfiles(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt", ".secret"} {
		if err := os.WriteFile(filepath.Join(home, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	one := reviewDecide(home, home, "null", "rm", filepath.Join(home, "a.txt"))
	if one.Action != "allow" {
		t.Fatalf("single home file: %s %s", one.Action, one.Consequence)
	}
	sweep := reviewDecide(home, home, "null", "rm", "-rf", filepath.Join(home, "a.txt"), filepath.Join(home, "b.txt"))
	if sweep.Action == "allow" {
		t.Fatal("rm of every visible home file was allowed")
	}
}
