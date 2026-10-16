// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package shim_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gtwy/spotter-sh/hook"
)

func TestBashShims(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash")
	}
	root := moduleRoot(t)
	home := t.TempDir()
	bin := filepath.Join(home, "spotter-sh")
	build := exec.Command("go", "build", "-o", bin, "./cmd/spotter-sh")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	logPath := filepath.Join(home, "ran")
	env := []string{
		"HOME=" + home,
		"PATH=/usr/bin:/bin",
		"SPOTTER_SH_HOME=" + filepath.Join(home, ".local", "state", "spotter-sh"),
		"REC_LOG=" + logPath,
	}
	inst := exec.Command(bin, "install", "--user")
	inst.Env = env
	if out, err := inst.CombinedOutput(); err != nil {
		t.Fatalf("install: %v %s", err, out)
	}
	shimDir := filepath.Join(home, ".local", "lib", "spotter-sh", "shims")
	rec := filepath.Join(home, "rec")
	if err := os.MkdirAll(rec, 0o755); err != nil {
		t.Fatal(err)
	}
	buildRecorder(t, home, filepath.Join(rec, "rm"))
	work := filepath.Join(home, "work")
	os.MkdirAll(work, 0o755)
	os.WriteFile(filepath.Join(work, "keep.txt"), []byte("ok"), 0o644)
	run := func(script string) (string, int) {
		os.Remove(logPath)
		cmd := exec.Command("bash", "--noprofile", "--norc", "-c", holdBash(script))
		cmd.Dir = work
		cmd.Env = sealEnv(append(env, "PATH="+shimDir+":"+rec+":/usr/bin:/bin"))
		out, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		return string(out), code
	}
	out, code := run("rm -rf /")
	if code != 121 || ran(logPath) {
		t.Fatalf("rm -rf / code %d out %s ran %v", code, out, ran(logPath))
	}
	if _, err := os.Stat(filepath.Join(work, "keep.txt")); err != nil {
		t.Fatal("canary gone")
	}
	out, code = run("rm keep.txt")
	if code != 0 || !ran(logPath) {
		t.Fatalf("allow rm code %d out %s", code, out)
	}
	if !strings.Contains(string(mustRead(logPath)), "keep.txt") {
		t.Fatalf("argv %q", mustRead(logPath))
	}
	out, code = run("echo hello")
	if code != 0 || strings.Contains(out, "spotter-sh") {
		t.Fatalf("echo %d %s", code, out)
	}

	spaced := filepath.Join(work, "a b")
	if err := os.WriteFile(spaced, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code = run("rm -- 'a b'")
	if code != 0 {
		t.Fatalf("spaced rm %d %s", code, out)
	}
	fields := bytes.Split(mustRead(logPath), []byte{0})
	if !hasField(fields, "a b") || !hasField(fields, "--") {
		t.Fatalf("argv mangled: %q", mustRead(logPath))
	}

	list := filepath.Join(work, "list")
	if err := os.WriteFile(filepath.Join(work, "one"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "two"), []byte("2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(list, []byte("one\ntwo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code = run("{ read -r a; rm -- \"$a\"; read -r b; printf '%s' \"$b\"; } < list")
	if code != 0 || !strings.Contains(out, "two") {
		t.Fatalf("stdin rewind code %d out %q", code, out)
	}
	hung, out, code := runLimit(t, work, append(env, "PATH="+shimDir+":"+rec+":/usr/bin:/bin"), "while read -r item; do rm -- \"$item\"; done < list", 5*time.Second)
	if hung {
		t.Fatal("while read looped; stdin was rewound")
	}
	if code != 0 {
		t.Fatalf("while read code %d %s", code, out)
	}

	if err := os.WriteFile(filepath.Join(work, "three"), []byte("3"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code = run("bash --noprofile --norc -c " + shellQuote("exec -a foobar rm -- three"))
	if code != 0 {
		t.Fatalf("exec -a code %d out %s", code, out)
	}
	fields = bytes.Split(mustRead(logPath), []byte{0})
	if !hasField(fields, "foobar") || !hasField(fields, "three") {
		t.Fatalf("exec -a argv %q", mustRead(logPath))
	}
	out, code = run("bash --noprofile --norc -c " + shellQuote("exec -a foobar rm -rf /"))
	if code != 121 || ran(logPath) {
		t.Fatalf("exec -a rm -rf / code %d ran %v out %s", code, ran(logPath), out)
	}
}

func hasField(fields [][]byte, want string) bool {
	for _, f := range fields {
		if string(f) == want {
			return true
		}
	}
	return false
}

func runLimit(t *testing.T, dir string, env []string, script string, limit time.Duration) (bool, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-c", holdBash(script))
	cmd.Dir = dir
	cmd.Env = sealEnv(env)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if ctx.Err() == nil {
			t.Fatal(err)
		}
	}
	return ctx.Err() == context.DeadlineExceeded, string(out), code
}

// holdBash keeps the bash process in the tree. bash -c execs a lone
// simple command, and that replacement drops the sealed environment
// the shim reads from the parent. The extra lines preserve the exit code.
func holdBash(script string) string {
	return script + "\n__ss_status=$?\nexit $__ss_status\n"
}

// sealEnv puts the rollout mode in bash's initial environment.
// The shim reads that. A command cannot change it afterward.
func sealEnv(env []string) []string {
	mode := os.Getenv("SPOTTER_SH_MODE")
	if mode == "" {
		mode = "enforce"
	}
	drop := map[string]bool{
		"SPOTTER_SH_HOST": true, "SPOTTER_SH_MODE": true,
		"SPOTTER_SH_JUDGE_DELAY": true, "SPOTTER_SH_SILENT_LOG": true,
		"SPOTTER_SH_SESSION": true, "SPOTTER_SH_TURN": true,
		"SPOTTER_SH_SURFACE": true, "SPOTTER_SH_SENDER": true,
		"SPOTTER_SH_TRUST": true,
	}
	out := make([]string, 0, len(env)+8)
	for _, e := range env {
		k, _, ok := strings.Cut(e, "=")
		if ok && drop[k] {
			continue
		}
		out = append(out, e)
	}
	out = append(out, "SPOTTER_SH_HOST=1", "SPOTTER_SH_MODE="+mode)
	for _, k := range []string{"SPOTTER_SH_JUDGE_DELAY", "SPOTTER_SH_SILENT_LOG", "SPOTTER_SH_SESSION", "SPOTTER_SH_TURN", "SPOTTER_SH_SURFACE", "SPOTTER_SH_SENDER", "SPOTTER_SH_TRUST"} {
		if v, ok := os.LookupEnv(k); ok && v != "" {
			out = append(out, k+"="+v)
		}
	}
	return out
}

func ran(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Size() > 0
}

func mustRead(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func buildRecorder(t *testing.T, home, dest string) {
	t.Helper()
	dir := filepath.Join(home, "recorder")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "package main\nimport \"os\"\nfunc main() {\n" +
		"f, err := os.OpenFile(os.Getenv(\"REC_LOG\"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)\n" +
		"if err != nil { os.Exit(1) }\n" +
		"defer f.Close()\n" +
		"for i, a := range os.Args {\n" +
		"if i > 0 { _, _ = f.Write([]byte{0}) }\n" +
		"_, _ = f.WriteString(a)\n" +
		"}\n" +
		"_, _ = f.Write([]byte{0})\n" +
		"}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module rec\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", dest, ".")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("recorder: %v %s", err, out)
	}
}

func TestBashSecretsAndArgv(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash")
	}
	root := moduleRoot(t)
	home := t.TempDir()
	bin := filepath.Join(home, "spotter-sh")
	build := exec.Command("go", "build", "-o", bin, "./cmd/spotter-sh")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	env := []string{
		"HOME=" + home,
		"PATH=/usr/bin:/bin",
		"SPOTTER_SH_HOME=" + filepath.Join(home, ".local", "state", "spotter-sh"),
	}
	inst := exec.Command(bin, "install", "--user")
	inst.Env = env
	if out, err := inst.CombinedOutput(); err != nil {
		t.Fatalf("install: %v %s", err, out)
	}
	shimDir := filepath.Join(home, ".local", "lib", "spotter-sh", "shims")
	rec := filepath.Join(home, "rec")
	if err := os.MkdirAll(rec, 0o755); err != nil {
		t.Fatal(err)
	}
	buildRecorder(t, home, filepath.Join(rec, "redis-cli"))
	buildRecorder(t, home, filepath.Join(rec, "mysql"))
	for _, name := range []string{"redis-cli", "mysql"} {
		dest := filepath.Join(shimDir, name)
		_ = os.Remove(dest)
		if err := os.Symlink(bin, dest); err != nil {
			t.Fatal(err)
		}
	}
	logPath := filepath.Join(home, "ran")
	work := filepath.Join(home, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := "hunter2secret"
	token := "ghp_abcdefghijklmnopqrstuvwxyz012345"
	slack := "xoxb-1234567890-abcdefghij"
	run := func(extra []string, script string) (string, int) {
		t.Helper()
		cmd := exec.Command("bash", "--noprofile", "--norc", "-c", holdBash(script))
		cmd.Dir = work
		cmd.Env = sealEnv(append(append(append([]string{}, env...), extra...), "PATH="+shimDir+":"+rec+":/usr/bin:/bin", "REC_LOG="+logPath))
		out, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		return string(out), code
	}
	out, code := run(nil, "redis-cli -a "+secret+" FLUSHALL")
	if code != 120 {
		t.Fatalf("redis code %d %s", code, out)
	}
	spot := filepath.Join(home, ".local", "state", "spotter-sh", "spotter.log")
	logged := string(mustRead(spot))
	if strings.Contains(out, secret) || strings.Contains(logged, secret) {
		t.Fatalf("secret leaked stderr=%s log=%s", out, logged)
	}
	out, code = run(nil, "mysql -e "+shellQuote("DROP TABLE t; -- "+token+" "+slack))
	if code != 120 {
		t.Fatalf("mysql code %d %s", code, out)
	}
	logged = string(mustRead(spot))
	if strings.Contains(out, token) || strings.Contains(out, slack) || strings.Contains(logged, token) || strings.Contains(logged, "xoxb-") {
		t.Fatalf("token leaked stderr=%s log=%s", out, logged)
	}
	sock := filepath.Join(home, "decide.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = hook.Serve(ctx, sock, hook.HandlerFunc(func(context.Context, hook.Catch) (hook.Decision, error) {
			return hook.Decision{Action: "proceed"}, nil
		}))
	}()
	time.Sleep(30 * time.Millisecond)
	os.Remove(logPath)
	out, code = run([]string{"SPOTTER_SH_HOOK=" + sock}, "mysql </dev/null")
	if code != 0 {
		t.Fatalf("proceed mysql %d %s", code, out)
	}
	got := string(mustRead(logPath))
	if strings.Contains(got, "--safe-updates") || strings.Contains(got, "PGOPTIONS") {
		t.Fatalf("argv changed %q", got)
	}
	if !strings.Contains(got, "mysql") {
		t.Fatalf("argv %q", got)
	}
}

func TestBashRound3(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash")
	}
	root := moduleRoot(t)
	home := t.TempDir()
	bin := filepath.Join(home, "spotter-sh")
	build := exec.Command("go", "build", "-o", bin, "./cmd/spotter-sh")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	env := []string{
		"HOME=" + home,
		"PATH=/usr/bin:/bin",
		"SPOTTER_SH_HOME=" + filepath.Join(home, ".local", "state", "spotter-sh"),
	}
	inst := exec.Command(bin, "install", "--user")
	inst.Env = env
	if out, err := inst.CombinedOutput(); err != nil {
		t.Fatalf("install: %v %s", err, out)
	}
	shimDir := filepath.Join(home, ".local", "lib", "spotter-sh", "shims")
	work := filepath.Join(home, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(script string) (string, int) {
		t.Helper()
		cmd := exec.Command("bash", "--noprofile", "--norc", "-c", holdBash(script))
		cmd.Dir = work
		cmd.Env = sealEnv(append(env, "PATH="+shimDir+":/usr/bin:/bin"))
		out, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		return string(out), code
	}
	plain := filepath.Join(work, "plain.txt")
	if err := os.WriteFile(plain, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(home, "emptyhome")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("env", "-i", "HOME="+empty, "PATH="+shimDir+":/usr/bin:/bin", "rm", "--", plain)
	cmd.Dir = work
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	if code == 122 || strings.Contains(string(out), "Shell Spotter failed") {
		t.Fatalf("env -i rm %d %s", code, out)
	}
	if _, err := os.Stat(plain); !os.IsNotExist(err) {
		t.Fatal("env -i did not run rm")
	}

	small := filepath.Join(work, "small")
	if err := os.MkdirAll(filepath.Join(small, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(small, "a.tmp")
	if err := os.WriteFile(tmp, []byte("t"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(small, "sub", ".spotter-sh-protect"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	outS, code := run("find -- " + shellQuote(small) + " -maxdepth 1 -name '*.tmp' -delete")
	if code != 0 {
		t.Fatalf("find -maxdepth %d %s", code, outS)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("maxdepth did not delete the tmp file")
	}
	outS, code = run("find -- " + shellQuote(small) + " -delete")
	if code != 120 {
		t.Fatalf("find -delete marker %d %s", code, outS)
	}

	if err := os.WriteFile(filepath.Join(work, "linksrc"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	outS, code = run("ln -s -- linksrc linkdest")
	if code != 0 {
		t.Fatalf("ln -s %d %s", code, outS)
	}
	if st, err := os.Lstat(filepath.Join(work, "linkdest")); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("ln -s did not create a symlink")
	}

	if _, err := exec.LookPath("rsync"); err == nil {
		src := filepath.Join(work, "rsrc")
		dst := filepath.Join(work, "rdst")
		if err := os.MkdirAll(src, 0o755); err != nil || os.MkdirAll(dst, 0o755) != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("a"), 0o644); err != nil {
			t.Fatal(err)
		}
		outS, code = run("rsync -n -a -- " + shellQuote(src+"/") + " " + shellQuote(dst+"/"))
		if code != 0 {
			t.Fatalf("rsync -n %d %s", code, outS)
		}
		if _, err := os.Stat(filepath.Join(dst, "a.txt")); !os.IsNotExist(err) {
			t.Fatal("rsync -n wrote a file")
		}
	}

	mode, err := os.Stat("/bin/chmod")
	if err != nil {
		t.Fatal(err)
	}
	before := mode.Mode()
	t.Cleanup(func() { _ = os.Chmod("/bin/chmod", before) })
	outS, code = run("chmod -x -- /bin/chmod")
	if code != 120 {
		t.Fatalf("chmod /bin/chmod %d %s", code, outS)
	}
	after, err := os.Stat("/bin/chmod")
	if err != nil || after.Mode().Perm()&0o111 == 0 {
		t.Fatal("chmod /bin/chmod changed the binary")
	}

	outS, code = run("dd if=/dev/zero of=/dev/hda bs=1 count=1")
	if code != 121 {
		t.Fatalf("dd hda %d %s", code, outS)
	}
	outS, code = run("find -- /var/log -delete")
	if code != 120 {
		t.Fatalf("find /var/log -delete %d %s", code, outS)
	}
	if _, err := os.Stat("/var/log"); err != nil {
		t.Fatal("/var/log missing")
	}

	outS, code = run("find -- /var/log -type f -delete")
	if code != 120 {
		t.Fatalf("find log -type f %d %s", code, outS)
	}
	outS, code = run("find -- /var/log -mindepth 1 -delete")
	if code != 120 {
		t.Fatalf("find log -mindepth %d %s", code, outS)
	}
	if _, err := os.Stat("/var/log"); err != nil {
		t.Fatal("/var/log missing after filtered delete")
	}

	many := filepath.Join(work, "many")
	if err := os.MkdirAll(many, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 120; i++ {
		name := "f" + strconvI(i) + ".txt"
		if err := os.WriteFile(filepath.Join(many, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	outS, code = run("find -- " + shellQuote(many) + " -exec rm {} +")
	if code != 120 {
		t.Fatalf("bulk find -exec rm %d %s", code, outS)
	}
	left, err := os.ReadDir(many)
	if err != nil || len(left) < 100 {
		t.Fatalf("bulk find deleted files: %d %v", len(left), err)
	}
	one := filepath.Join(work, "one")
	if err := os.MkdirAll(one, 0o755); err != nil {
		t.Fatal(err)
	}
	tmp = filepath.Join(one, "a.tmp")
	if err := os.WriteFile(tmp, []byte("t"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(one, "keep.txt"), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	outS, code = run("find -- " + shellQuote(one) + " -name '*.tmp' -exec rm {} +")
	if code != 0 {
		t.Fatalf("small find -exec %d %s", code, outS)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("small find left the tmp file")
	}
	if _, err := os.Stat(filepath.Join(one, "keep.txt")); err != nil {
		t.Fatal("small find removed keep.txt")
	}

	brc := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(brc, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	outS, code = run("find -- " + shellQuote(home) + " -maxdepth 1 -name .bashrc -delete")
	if code != 120 {
		t.Fatalf("find bashrc %d %s", code, outS)
	}
	buf, err := os.ReadFile(brc)
	if err != nil || string(buf) != "keep" {
		t.Fatal("find removed bashrc")
	}

	target := filepath.Join(one, "keep.txt")
	link := filepath.Join(one, "the-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	outS, code = run("rm -- " + shellQuote(link))
	if code != 0 {
		t.Fatalf("rm symlink %d %s", code, outS)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("rm symlink removed the target")
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatal("rm symlink left the link")
	}

	// The outer shell also has no HOME, so bash expands ~ from the passwd
	// entry and env -i then clears the environment the shim would read.
	who, err := user.Current()
	if err != nil || who.HomeDir == "" {
		t.Fatal(err)
	}
	probe := filepath.Join(who.HomeDir, ".ssh", "spotter-sh-env-i-probe")
	if _, err := os.Lstat(probe); err == nil {
		t.Fatal("ssh probe path exists; refusing the env -i probe")
	}
	bare := exec.Command("bash", "--noprofile", "--norc", "-c", holdBash(`env -i PATH="$PATH" rm -rf -- ~/.ssh/spotter-sh-env-i-probe`))
	bare.Dir = work
	bare.Env = sealEnv([]string{"PATH=" + shimDir + ":/usr/bin:/bin"})
	bout, berr := bare.CombinedOutput()
	bcode := 0
	if berr != nil {
		if ee, ok := berr.(*exec.ExitError); ok {
			bcode = ee.ExitCode()
		} else {
			t.Fatal(berr)
		}
	}
	if bcode != 120 && bcode != 122 {
		t.Fatalf("env -i home delete %d %s", bcode, bout)
	}
	if _, err := os.Lstat(probe); err == nil {
		t.Fatal("env -i removed or created the ssh probe path")
	}
}

func TestBashRound5(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash")
	}
	root := moduleRoot(t)
	home := t.TempDir()
	bin := filepath.Join(home, "spotter-sh")
	build := exec.Command("go", "build", "-o", bin, "./cmd/spotter-sh")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	env := []string{
		"HOME=" + home,
		"PATH=/usr/bin:/bin",
		"SPOTTER_SH_HOME=" + filepath.Join(home, ".local", "state", "spotter-sh"),
	}
	inst := exec.Command(bin, "install", "--user")
	inst.Env = env
	if out, err := inst.CombinedOutput(); err != nil {
		t.Fatalf("install: %v %s", err, out)
	}
	shimDir := filepath.Join(home, ".local", "lib", "spotter-sh", "shims")
	work := filepath.Join(home, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(home, "canary.txt")
	if err := os.WriteFile(canary, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := func(name, target string) {
		t.Helper()
		p := filepath.Join(work, name)
		_ = os.Remove(p)
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	run := func(script string) (string, int) {
		t.Helper()
		cmd := exec.Command("bash", "--noprofile", "--norc", "-c", holdBash(script))
		cmd.Dir = work
		cmd.Env = sealEnv(append(env, "PATH="+shimDir+":/usr/bin:/bin"))
		out, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		return string(out), code
	}
	link("homelink", home)
	out, code := run("rm -rf -- homelink")
	if code != 0 {
		t.Fatalf("bare homelink %d %s", code, out)
	}
	if _, err := os.Lstat(filepath.Join(work, "homelink")); !os.IsNotExist(err) {
		t.Fatal("bare rm left the symlink")
	}
	if _, err := os.Stat(canary); err != nil {
		t.Fatal("bare rm followed the link")
	}
	for _, script := range []string{
		`rm -rf -- homelink/`,
		`rm -rf -- "homelink/"`,
		`rm -rf -- homelink/.`,
		`rm -rf -- ./rootlink/`,
		`rm -rf -- etclink/`,
		`rm -rf -- biglink/`,
		`env -i PATH="$PATH" rm -rf -- etclink/`,
	} {
		link("homelink", home)
		link("rootlink", "/")
		link("etclink", "/etc")
		link("biglink", "/usr")
		out, code = run(script)
		if code == 0 {
			t.Fatalf("%s ran: %s", script, out)
		}
		if _, err := os.Stat(canary); err != nil {
			t.Fatalf("%s removed the home canary", script)
		}
		if _, err := os.Stat("/etc/passwd"); err != nil {
			t.Fatalf("%s removed /etc/passwd", script)
		}
	}
	out, code = run("chmod 755 -- /")
	if code != 121 {
		t.Fatalf("chmod / %d %s", code, out)
	}
	if err := os.WriteFile(filepath.Join(work, "plain"), []byte("p"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code = run("mv -- plain /")
	if code != 121 {
		t.Fatalf("mv onto / %d %s", code, out)
	}
	if _, err := os.Stat(filepath.Join(work, "plain")); err != nil {
		t.Fatal("mv / removed plain")
	}
	pre := exec.Command(bin, "precheck", "--", `echo ":(){ :|:& };:"`)
	pre.Dir = work
	pre.Env = sealEnv(env)
	if out, err := pre.CombinedOutput(); err != nil {
		t.Fatalf("quoted bomb %v %s", err, out)
	}
	pre = exec.Command(bin, "precheck", "--", `rm -rf "~"`)
	pre.Env = sealEnv(env)
	if out, err := pre.CombinedOutput(); err != nil {
		t.Fatalf("quoted tilde %v %s", err, out)
	}
}

func TestBashRound6(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash")
	}
	root := moduleRoot(t)
	home := t.TempDir()
	bin := filepath.Join(home, "spotter-sh")
	build := exec.Command("go", "build", "-o", bin, "./cmd/spotter-sh")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	env := []string{
		"HOME=" + home,
		"PATH=/usr/bin:/bin",
		"SPOTTER_SH_HOME=" + filepath.Join(home, ".local", "state", "spotter-sh"),
	}
	inst := exec.Command(bin, "install", "--user")
	inst.Env = env
	if out, err := inst.CombinedOutput(); err != nil {
		t.Fatalf("install: %v %s", err, out)
	}
	shimDir := filepath.Join(home, ".local", "lib", "spotter-sh", "shims")
	work := filepath.Join(home, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(ssh, "id_ed25519")
	if err := os.WriteFile(key, []byte("secret-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(home, "canary.txt")
	if err := os.WriteFile(canary, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(script string) (string, int) {
		t.Helper()
		cmd := exec.Command("bash", "--noprofile", "--norc", "-c", holdBash(script))
		cmd.Dir = work
		cmd.Env = sealEnv(append(env, "PATH="+shimDir+":/usr/bin:/bin"))
		out, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		return string(out), code
	}
	out, code := run("rm --drop-exec /bin/rm rm -rf -- " + ssh)
	if code == 0 {
		t.Fatalf("drop-exec rm ran: %s", out)
	}
	if buf, err := os.ReadFile(key); err != nil || string(buf) != "secret-key" {
		t.Fatalf("drop-exec rm changed the key %q %v", buf, err)
	}
	mode := func() os.FileMode {
		t.Helper()
		st, err := os.Stat(key)
		if err != nil {
			t.Fatal(err)
		}
		return st.Mode()
	}
	before := mode()
	out, code = run("chmod --drop-exec /bin/chmod 777 -- " + key)
	if code == 0 {
		t.Fatalf("drop-exec chmod ran: %s", out)
	}
	if mode() != before {
		t.Fatalf("drop-exec chmod changed mode %v", mode())
	}
	out, code = run(`find "$HOME" -delete -name '*ar'`)
	if code == 0 {
		t.Fatalf("find -delete before -name ran: %s", out)
	}
	if _, err := os.Stat(canary); err != nil {
		t.Fatal("find -delete removed the canary")
	}
	out, code = run(`find "$HOME/.ssh" -name "*" -exec cp /dev/null {} +`)
	if code == 0 {
		t.Fatalf("find cp ran: %s", out)
	}
	if buf, err := os.ReadFile(key); err != nil || string(buf) != "secret-key" {
		t.Fatalf("find cp emptied the key %q %v", buf, err)
	}
	out, code = run(`find "$HOME/.ssh" -name "*" -exec truncate -s 0 {} +`)
	if code == 0 {
		t.Fatalf("find truncate ran: %s", out)
	}
	if buf, err := os.ReadFile(key); err != nil || string(buf) != "secret-key" {
		t.Fatalf("find truncate emptied the key %q %v", buf, err)
	}
	pre := exec.Command(bin, "precheck", "--", `sh -c 'rm -rf ~'`)
	pre.Env = sealEnv(env)
	outb, err := pre.CombinedOutput()
	if err == nil {
		t.Fatalf("sh -c rm -rf ~ allowed: %s", outb)
	}
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 121 {
		t.Fatalf("sh -c exit %v %s", err, outb)
	}
}

func strconvI(n int) string {
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

func TestBashRound7(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash")
	}
	root := moduleRoot(t)
	home := t.TempDir()
	bin := filepath.Join(home, "spotter-sh")
	build := exec.Command("go", "build", "-o", bin, "./cmd/spotter-sh")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	env := []string{
		"HOME=" + home,
		"PATH=/usr/bin:/bin",
		"SPOTTER_SH_HOME=" + filepath.Join(home, ".local", "state", "spotter-sh"),
	}
	inst := exec.Command(bin, "install", "--user")
	inst.Env = env
	if out, err := inst.CombinedOutput(); err != nil {
		t.Fatalf("install: %v %s", err, out)
	}
	shimDir := filepath.Join(home, ".local", "lib", "spotter-sh", "shims")
	work := filepath.Join(home, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(script string) (string, int) {
		t.Helper()
		cmd := exec.Command("bash", "--noprofile", "--norc", "-c", holdBash(script))
		cmd.Dir = work
		cmd.Env = sealEnv(append(env, "PATH="+shimDir+":/usr/bin:/bin"))
		out, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		return string(out), code
	}
	blocked := []string{
		`rm -rf $(echo /)`,
		`R=/; rm -rf $R`,
		`rm -rf "$(printf /)"`,
		`rm -rf $(echo /)/*`,
		`find / -delete`,
		`rm -rf /bin /etc /usr /home /var /lib /sbin /opt /root /boot`,
		`chmod -R 777 $(echo /)`,
		`chown -R root $(echo /)`,
	}
	for _, script := range blocked {
		out, code := run(script)
		if code != 121 {
			t.Errorf("%s code %d %s", script, code, out)
		}
		if _, err := os.Stat("/etc/passwd"); err != nil {
			t.Fatalf("%s removed /etc/passwd", script)
		}
	}
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(ssh, "id_ed25519")
	if err := os.WriteFile(key, []byte("secret-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := run(`find "$HOME/.ssh" -exec sh -c 'cat /dev/null > "$1"' _ {} \;`)
	if code == 0 {
		t.Fatalf("ssh redirect ran %s", out)
	}
	buf, err := os.ReadFile(key)
	if err != nil || string(buf) != "secret-key" {
		t.Fatalf("ssh key changed %q %v", buf, err)
	}
	payload := filepath.Join(work, "payload")
	if err := os.WriteFile(payload, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	lib := "/usr/lib"
	if st, err := os.Lstat(lib); err == nil && st.IsDir() {
		out, code = run("cp -t /usr/lib -- " + shellQuote(payload))
		if code == 0 {
			t.Fatalf("cp -t /usr/lib ran %s", out)
		}
		if _, err := os.Lstat(filepath.Join(lib, "payload")); err == nil {
			t.Fatal("cp -t created /usr/lib/payload")
		}
		out, code = run("install -t /usr/lib -- " + shellQuote(payload))
		if code == 0 {
			t.Fatalf("install -t /usr/lib ran %s", out)
		}
	}
	few := filepath.Join(work, "few")
	if err := os.MkdirAll(few, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(filepath.Join(few, "f"+strconvI(i)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, code = run("find -- " + shellQuote(few) + " -delete")
	if code != 0 {
		t.Fatalf("few find -delete %d %s", code, out)
	}
	many := filepath.Join(work, "perm600")
	if err := os.MkdirAll(many, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 101; i++ {
		if err := os.WriteFile(filepath.Join(many, "f"+strconvI(i)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, code = run("find -- " + shellQuote(many) + " -delete")
	if code == 0 {
		t.Fatalf("perm600 find -delete ran %s", out)
	}
	if _, err := os.Stat(filepath.Join(many, "f0")); err != nil {
		t.Fatal("perm600 deleted a file")
	}
	if err := os.WriteFile(filepath.Join(work, "keep.txt"), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(work, "old.tmp")
	if err := os.WriteFile(old, []byte("o"), 0o644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-30 * 24 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "new.tmp"), []byte("n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code = run(`find . -name '*.tmp' -mtime +7 -delete`)
	if code != 0 {
		t.Fatalf("tmp mtime %d %s", code, out)
	}
	if _, err := os.Stat(filepath.Join(work, "keep.txt")); err != nil {
		t.Fatal("tmp mtime removed keep.txt")
	}
	if _, err := os.Stat(filepath.Join(work, "new.tmp")); err != nil {
		t.Fatal("tmp mtime removed new.tmp")
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("tmp mtime left old.tmp")
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
