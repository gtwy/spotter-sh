// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package shim_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// Existing bash tests expect enforce. The sealed host is this process,
	// so a command inside bash cannot switch the mode.
	os.Setenv("SPOTTER_SH_HOST", "1")
	os.Setenv("SPOTTER_SH_MODE", "enforce")
	os.Exit(m.Run())
}

func TestBashSilentMode(t *testing.T) {
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
	buildRecorder(t, home, filepath.Join(rec, "rm"))
	buildRecorder(t, home, filepath.Join(rec, "find"))
	logPath := filepath.Join(home, "ran")
	work := filepath.Join(home, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	silentLog := filepath.Join(home, ".local", "state", "spotter-sh", "silent.jsonl")
	t.Setenv("SPOTTER_SH_SILENT_LOG", silentLog)
	t.Setenv("SPOTTER_SH_SESSION", "sess-1")
	t.Setenv("SPOTTER_SH_TURN", "turn-9")
	t.Setenv("SPOTTER_SH_SURFACE", "chat")
	t.Setenv("SPOTTER_SH_SENDER", "ada")
	t.Setenv("SPOTTER_SH_TRUST", "admin")

	run := func(script string) (string, int) {
		t.Helper()
		os.Remove(logPath)
		cmd := exec.Command("bash", "--noprofile", "--norc", "-c", holdBash(script))
		cmd.Dir = work
		cmd.Env = sealEnv(append(env,
			"PATH="+shimDir+":"+rec+":/usr/bin:/bin",
			"REC_LOG="+logPath,
		))
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

	// A shell command cannot leave enforce.
	if err := os.WriteFile(filepath.Join(work, ".spotter-sh.toml"), []byte("mode = \"silent\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".config", "spotter-sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".config", "spotter-sh", "config.toml"), []byte("mode = \"silent\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := run("SPOTTER_SH_MODE=silent rm -rf /")
	if code != 121 || ran(logPath) || strings.Contains(out, "BLOCKED") == false && code == 0 {
		t.Fatalf("prefix flip code %d ran %v", code, ran(logPath))
	}
	out, code = run("export SPOTTER_SH_HOST=1; export SPOTTER_SH_MODE=silent; rm -rf /")
	if code != 121 || ran(logPath) {
		t.Fatalf("export flip code %d ran %v out %s", code, ran(logPath), out)
	}
	_ = os.Remove(filepath.Join(work, ".spotter-sh.toml"))

	// Silent: hard blocks run in the recorder sandbox, including find / -delete.
	t.Setenv("SPOTTER_SH_MODE", "silent")
	os.Remove(silentLog)
	out, code = run("rm -rf /")
	if code != 0 || !ran(logPath) {
		t.Fatalf("silent rm -rf / code %d ran %v out %s", code, ran(logPath), out)
	}
	if strings.Contains(out, "BLOCKED") || strings.Contains(out, "spotter-sh") {
		t.Fatalf("silent rm printed a block: %s", out)
	}
	out, code = run("SPOTTER_SH_MODE=enforce rm -rf /bin /etc /usr")
	if code != 0 || !ran(logPath) {
		t.Fatalf("cannot enter enforce from a command: %d %s", code, out)
	}
	out, code = run("find / -delete")
	if code != 0 || !ran(logPath) {
		t.Fatalf("silent find / -delete code %d ran %v", code, ran(logPath))
	}

	link := filepath.Join(work, "rootlink")
	if err := os.Symlink("/", link); err != nil {
		t.Fatal(err)
	}
	out, code = run("rm -rf -- " + shellQuote(link))
	if code != 0 || !ran(logPath) {
		t.Fatalf("symlink rm %d %s", code, out)
	}

	keep := filepath.Join(work, "keep.txt")
	if err := os.WriteFile(keep, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Real rm, so the exit code is the command's, and the file actually goes.
	out, code = runWithPath(t, work, env, shimDir+":/usr/bin:/bin", "rm -- "+shellQuote(keep))
	if code != 0 {
		t.Fatalf("allow rm %d %s", code, out)
	}
	if _, err := os.Stat(keep); !os.IsNotExist(err) {
		t.Fatal("allow rm did not delete")
	}
	out, code = runWithPath(t, work, env, shimDir+":/usr/bin:/bin", "rm -- "+shellQuote(filepath.Join(work, "missing-file")))
	if code == 0 {
		t.Fatalf("missing rm exited 0: %s", out)
	}

	token := "ghp_abcdefghijklmnopqrstuvwxyz012345"
	out, code = run("rm --token " + token + " -- " + shellQuote(keep))
	if code != 0 {
		t.Fatalf("secret rm %d %s", code, out)
	}

	text := waitLog(t, silentLog, `"verdict":"hardblock"`)
	if strings.Contains(text, token) || strings.Contains(text, "hunter2") {
		t.Fatal("secret in silent log")
	}
	var sawBlock, sawPass, sawLink, sawExit bool
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			t.Fatal("bad record")
		}
		for _, key := range []string{"schema", "ts_utc", "ts_local", "session_id", "turn_id", "surface", "sender", "trust", "cwd", "raw", "argv", "layer", "verdict", "rule", "catch_id", "reason", "targets", "files", "dirs", "protected", "symlink", "judge_ms", "timeout", "error", "exit_code", "version", "commit"} {
			if _, ok := rec[key]; !ok {
				t.Fatalf("record missing %s", key)
			}
		}
		if rec["schema"] != float64(1) {
			t.Fatalf("schema %v", rec["schema"])
		}
		if rec["trust"] != "admin" || rec["sender"] != "ada" || rec["surface"] != "chat" {
			t.Fatalf("identity %v %v %v", rec["trust"], rec["sender"], rec["surface"])
		}
		if rec["verdict"] == "hardblock" {
			sawBlock = true
			if id, _ := rec["catch_id"].(string); !strings.HasPrefix(id, "would-") {
				t.Fatal("hard block minted a real catch id")
			}
		}
		if rec["verdict"] == "pass" {
			sawPass = true
		}
		if rec["symlink"] == true {
			sawLink = true
		}
		if rec["exit_code"] != nil && rec["exit_code"] != float64(0) {
			sawExit = true
		}
		if layer, _ := rec["layer"].(string); layer != "precheck" && layer != "engine" {
			t.Fatalf("layer %s", layer)
		}
	}
	if !sawBlock || !sawPass || !sawLink || !sawExit {
		t.Fatalf("block %v pass %v link %v exit %v", sawBlock, sawPass, sawLink, sawExit)
	}
	st, err := os.Stat(silentLog)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o007 != 0 {
		t.Fatalf("log is world-readable %o", st.Mode().Perm())
	}

	rep := exec.Command(bin, "report", "--log", silentLog, "--export", filepath.Join(home, "held.jsonl"))
	rep.Env = env
	repOut, err := rep.CombinedOutput()
	if err != nil {
		t.Fatalf("report: %v %s", err, repOut)
	}
	summary := string(repOut)
	if !strings.Contains(summary, "verdict hardblock") || !strings.Contains(summary, "verdict pass") || !strings.Contains(summary, "trust admin") || !strings.Contains(summary, "p50_ms") || !strings.Contains(summary, "p99_ms") {
		t.Fatalf("report %s", summary)
	}
	held, err := os.ReadFile(filepath.Join(home, "held.jsonl"))
	if err != nil || !strings.Contains(string(held), `"verdict":"hardblock"`) || strings.Contains(string(held), `"verdict":"pass"`) {
		t.Fatal("export did not keep only holds")
	}

	// A blocked logger must not stop the command.
	fifo := filepath.Join(home, "block.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			f.Close()
		}
	})
	t.Setenv("SPOTTER_SH_SILENT_LOG", fifo)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-c", holdBash("rm -- "+shellQuote(filepath.Join(work, "no-such"))))
	cmd.Dir = work
	cmd.Env = sealEnv(append(env, "PATH="+shimDir+":/usr/bin:/bin"))
	_, err = cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("command waited on the logger")
	}
	if err == nil {
		t.Fatal("missing file rm should be non-zero")
	}
}

func TestBashSilentLatency(t *testing.T) {
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
	env := []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	inst := exec.Command(bin, "install", "--user")
	inst.Env = append(env, "SPOTTER_SH_HOME="+filepath.Join(home, ".local", "state", "spotter-sh"))
	if out, err := inst.CombinedOutput(); err != nil {
		t.Fatalf("install: %v %s", err, out)
	}
	shimDir := filepath.Join(home, ".local", "lib", "spotter-sh", "shims")
	work := filepath.Join(home, "lat")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	sample := func(path, script string) time.Duration {
		t.Helper()
		file := filepath.Join(work, "f")
		if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		cmd := exec.Command("bash", "--noprofile", "--norc", "-c", holdBash(script))
		cmd.Dir = work
		cmd.Env = sealEnv(append(env, "PATH="+path))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sample: %v %s", err, out)
		}
		return time.Since(start)
	}
	const n = 21
	warmup := func(path, script string) {
		for i := 0; i < 3; i++ {
			sample(path, script)
		}
	}
	collect := func(path, script string) []time.Duration {
		warmup(path, script)
		got := make([]time.Duration, 0, n)
		for i := 0; i < n; i++ {
			got = append(got, sample(path, script))
		}
		sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
		return got
	}
	script := "rm -- f"
	base := collect("/usr/bin:/bin", script)
	t.Setenv("SPOTTER_SH_MODE", "silent")
	silent := collect(shimDir+":/usr/bin:/bin", script)
	t.Setenv("SPOTTER_SH_MODE", "enforce")
	enforced := collect(shimDir+":/usr/bin:/bin", script)
	p50 := func(s []time.Duration) time.Duration { return s[len(s)/2] }
	p99 := func(s []time.Duration) time.Duration { return s[len(s)-1] }
	t.Logf("latency baseline p50=%s p99=%s silent p50=%s p99=%s enforce p50=%s p99=%s",
		p50(base), p99(base), p50(silent), p99(silent), p50(enforced), p99(enforced))
	// Silent pays for the shim process. It must not pay for a judge on top of enforce.
	if p99(silent) > p99(enforced)+80*time.Millisecond {
		t.Fatalf("silent p99 %s slower than enforce p99 %s", p99(silent), p99(enforced))
	}
	if p99(silent) > p99(base)+120*time.Millisecond {
		t.Fatalf("silent p99 %s added more than 120ms over baseline %s", p99(silent), p99(base))
	}

	// A slow judge is off the command path only in silent mode.
	t.Setenv("SPOTTER_SH_JUDGE_DELAY", "400ms")
	t.Setenv("SPOTTER_SH_MODE", "enforce")
	var slowEnforce []time.Duration
	for i := 0; i < 5; i++ {
		slowEnforce = append(slowEnforce, sample(shimDir+":/usr/bin:/bin", script))
	}
	sort.Slice(slowEnforce, func(i, j int) bool { return slowEnforce[i] < slowEnforce[j] })
	t.Setenv("SPOTTER_SH_MODE", "silent")
	var slowSilent []time.Duration
	for i := 0; i < 5; i++ {
		slowSilent = append(slowSilent, sample(shimDir+":/usr/bin:/bin", script))
	}
	sort.Slice(slowSilent, func(i, j int) bool { return slowSilent[i] < slowSilent[j] })
	t.Logf("judge delay enforce p50=%s silent p50=%s", slowEnforce[len(slowEnforce)/2], slowSilent[len(slowSilent)/2])
	if slowEnforce[len(slowEnforce)/2] < 350*time.Millisecond {
		t.Fatalf("enforce did not wait for the judge: %s", slowEnforce[len(slowEnforce)/2])
	}
	if slowSilent[len(slowSilent)/2] > 200*time.Millisecond {
		t.Fatalf("silent waited for the judge: %s", slowSilent[len(slowSilent)/2])
	}
}

func runWithPath(t *testing.T, work string, env []string, path, script string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", "--noprofile", "--norc", "-c", holdBash(script))
	cmd.Dir = work
	cmd.Env = sealEnv(append(env, "PATH="+path))
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

func waitLog(t *testing.T, path, want string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err == nil {
			last = string(b)
			if strings.Contains(last, want) && strings.Contains(last, `"verdict":"pass"`) {
				return last
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal("silent log did not record the commands")
	return ""
}
