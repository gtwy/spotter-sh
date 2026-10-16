// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package shim

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gtwy/spotter-sh/internal/envx"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gtwy/spotter-sh/internal/config"
	"github.com/gtwy/spotter-sh/internal/engine"
	"github.com/gtwy/spotter-sh/internal/precheck"
	"github.com/gtwy/spotter-sh/internal/redact"
	"github.com/gtwy/spotter-sh/internal/rollout"
	"github.com/gtwy/spotter-sh/internal/silentlog"
)

// job is the snapshot the detached judge reads. It does not carry the
// environment. The judge process inherited that, and the log must not.
type job struct {
	Argv      []string  `json:"argv"`
	Cwd       string    `json:"cwd"`
	Home      string    `json:"home"`
	Raw       string    `json:"raw"`
	SessionID string    `json:"session_id"`
	TurnID    string    `json:"turn_id"`
	Surface   string    `json:"surface"`
	Sender    string    `json:"sender"`
	Trust     string    `json:"trust"`
	LogPath   string    `json:"log_path"`
	MaxBytes  int64     `json:"max_bytes"`
	MaxAgeSec int64     `json:"max_age_sec"`
	Deadline  time.Time `json:"deadline"`
}

// runSilent starts the real command immediately. A detached copy of this
// binary judges and appends the log. If that copy fails to start, the
// command still runs.
func runSilent(argv []string, cwd, home string) int {
	name := invokedName(argv[0])
	judgeArgv := append([]string(nil), argv...)
	if got := filepath.Base(argv[0]); got != name && name != "" {
		judgeArgv[0] = name
	}
	real, err := resolveReal(name, argv[0])
	j := snapshot(judgeArgv, cwd, home)
	exitW := startJudge(j)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Shell Spotter: %s: command not found\n", name)
		finishJudge(exitW, 127)
		return 127
	}
	code := runChild(real, argv, childEnv(name, stripOK(os.Environ())))
	finishJudge(exitW, code)
	return code
}

func snapshot(argv []string, cwd, home string) job {
	cfg, _ := config.Load(config.DefaultLocations(cwd))
	path := rollout.Var("SPOTTER_SH_SILENT_LOG")
	if path == "" {
		path = cfg.Log.SilentPath
	}
	if path == "" {
		path = filepath.Join(home, ".local", "state", "spotter-sh", "silent.jsonl")
	}
	maxBytes := int64(cfg.Log.SilentMaxMB) << 20
	if maxBytes <= 0 {
		maxBytes = 32 << 20
	}
	age := cfg.Log.SilentMaxAge
	if age <= 0 {
		age = 14 * 24 * time.Hour
	}
	trust := firstSet(envx.Get("TRUST"), rollout.Var("SPOTTER_SH_TRUST"))
	if trust == "" {
		trust = "none"
	}
	deadline := time.Now().Add(cfg.FailTimeout)
	if cfg.FailTimeout <= 0 {
		deadline = time.Now().Add(2 * time.Second)
	}
	return job{
		Argv:      argv,
		Cwd:       cwd,
		Home:      home,
		Raw:       rawCommand(argv),
		SessionID: firstSet(envx.Get("SESSION"), rollout.Var("SPOTTER_SH_SESSION")),
		TurnID:    firstSet(envx.Get("TURN"), rollout.Var("SPOTTER_SH_TURN")),
		Surface:   firstSet(envx.Get("SURFACE"), rollout.Var("SPOTTER_SH_SURFACE")),
		Sender:    firstSet(envx.Get("SENDER"), rollout.Var("SPOTTER_SH_SENDER")),
		Trust:     trust,
		LogPath:   path,
		MaxBytes:  maxBytes,
		MaxAgeSec: int64(age / time.Second),
		Deadline:  deadline,
	}
}

func rawCommand(argv []string) string {
	if s := parentScript(); s != "" {
		return s
	}
	if s := envx.Get("LINE"); s != "" {
		return s
	}
	return strings.Join(argv, " ")
}

func parentScript() string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(os.Getppid()) + "/cmdline")
	if err != nil {
		return ""
	}
	var parts []string
	start := 0
	for i := 0; i <= len(b); i++ {
		if i != len(b) && b[i] != 0 {
			continue
		}
		if i > start {
			parts = append(parts, string(b[start:i]))
		}
		start = i + 1
	}
	if len(parts) < 3 {
		return ""
	}
	base := filepath.Base(parts[0])
	if (base == "bash" || base == "sh" || base == "dash") && (parts[1] == "-c" || parts[1] == "-lc") {
		return parts[2]
	}
	return ""
}

// startJudge forks the logger and returns the exit-code pipe.
// A nil pipe means the logger did not start. The command still runs.
func startJudge(j job) *os.File {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	snapR, snapW, err := os.Pipe()
	if err != nil {
		return nil
	}
	exitR, exitW, err := os.Pipe()
	if err != nil {
		snapR.Close()
		snapW.Close()
		return nil
	}
	cmd := exec.Command(exe, "__silent")
	cmd.Stdin = snapR
	cmd.ExtraFiles = []*os.File{exitR}
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		snapR.Close()
		snapW.Close()
		exitR.Close()
		exitW.Close()
		return nil
	}
	snapR.Close()
	exitR.Close()
	go func() { _ = cmd.Wait() }()
	if err := json.NewEncoder(snapW).Encode(j); err != nil {
		snapW.Close()
		exitW.Close()
		return nil
	}
	snapW.Close()
	return exitW
}

func finishJudge(w *os.File, code int) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, "%d\n", code)
	w.Close()
}

func runChild(real string, argv, env []string) int {
	if len(argv) > 0 {
		env = childEnv(argv[0], env)
	}
	runtime.LockOSThread()
	_ = engine.DropThread()
	proc, err := os.StartProcess(real, argv, &os.ProcAttr{
		Env:   env,
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
			fmt.Fprintf(os.Stderr, "Shell Spotter: %s: command not found\n", argv[0])
			return 127
		}
		return 127
	}
	st, err := proc.Wait()
	if err != nil {
		return 1
	}
	if st.Success() {
		return 0
	}
	ws, ok := st.Sys().(syscall.WaitStatus)
	if !ok {
		return 1
	}
	if ws.Exited() {
		return ws.ExitStatus()
	}
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return 1
}

// SilentWorker is the detached judge. It never affects the command's exit.
func SilentWorker() int {
	var j job
	if err := json.NewDecoder(os.Stdin).Decode(&j); err != nil {
		return 0
	}
	exitCh := make(chan int, 1)
	go func() {
		f := os.NewFile(3, "exit")
		if f == nil {
			exitCh <- -1
			return
		}
		defer f.Close()
		var n int
		if _, err := fmt.Fscan(f, &n); err != nil {
			exitCh <- -1
			return
		}
		exitCh <- n
	}()
	if d := rollout.JudgeDelay(); d > 0 {
		time.Sleep(d)
	}
	start := time.Now()
	rec := judgeJob(j)
	rec.JudgeMS = time.Since(start).Milliseconds()
	code := <-exitCh
	if code < 0 {
		rec.Error = joinErr(rec.Error, "exit unknown")
	} else {
		rec.ExitCode = &code
	}
	opt := silentlog.Options{Path: j.LogPath, MaxBytes: j.MaxBytes, MaxAge: time.Duration(j.MaxAgeSec) * time.Second}
	_ = silentlog.Write(rec, opt)
	return 0
}

func judgeJob(j job) silentlog.Record {
	cfg, err := config.Load(config.DefaultLocations(j.Cwd))
	rec := silentlog.Record{
		SessionID: j.SessionID,
		TurnID:    j.TurnID,
		Surface:   j.Surface,
		Sender:    j.Sender,
		Trust:     j.Trust,
		Cwd:       j.Cwd,
		Raw:       j.Raw,
		Argv:      append([]string{}, j.Argv...),
		Layer:     "engine",
		Verdict:   "pass",
	}
	if err != nil {
		rec.Error = "invalid config"
		rec.Verdict = "catch"
		rec.Rule = "spotter-error"
		rec.CatchID = wouldID()
		return rec
	}
	if j.Home == "" {
		j.Home = engine.HomeDir()
	}
	deadline := j.Deadline
	if deadline.IsZero() {
		deadline = time.Now().Add(cfg.FailTimeout)
	}
	in := engine.Input{
		Argv: j.Argv, Cwd: j.Cwd, Env: os.Environ(), Home: j.Home, Config: cfg,
		StdinKind: "null", Hostname: hostname(), Deadline: deadline,
	}
	out := engine.Decide(in)
	rec.Verdict = verdictOf(out.Action)
	rec.Rule = out.Case
	rec.Reason = firstText(out.Message, out.Consequence, out.Report)
	rec.Timeout = out.Affected.TimedOut
	rec.Targets = append([]string{}, out.Affected.Top...)
	if out.Action == "fail" {
		rec.Error = joinErr(rec.Error, "spotter error")
		rec.Rule = "spotter-error"
	}
	pre := precheck.ScanAt(j.Raw, j.Cwd, j.Home)
	if pre.Action == "hardblock" || pre.Action == "catch" {
		rec.Layer = "precheck"
		if pre.Action == "hardblock" || rec.Verdict == "pass" {
			rec.Verdict = verdictOf(pre.Action)
			if pre.Case != "" {
				rec.Rule = pre.Case
			}
			if pre.Message != "" {
				rec.Reason = pre.Message
			}
		}
	}
	files, dirs, link, protected, targets := describeTargets(j.Cwd, j.Argv, out)
	rec.Files = files
	rec.Dirs = dirs
	rec.Symlink = link
	rec.Protected = protected
	if len(targets) > 0 {
		rec.Targets = targets
	}
	if rec.Verdict != "pass" && rec.CatchID == "" {
		rec.CatchID = wouldID()
	}
	red := redact.New(cfg.RedactExtra)
	vals := red.SecretValues(j.Argv)
	rec.Raw = red.MaskValues(red.Apply(rec.Raw), vals)
	rec.Reason = red.MaskValues(red.Apply(rec.Reason), vals)
	rec.Argv = red.Argv(rec.Argv)
	rec.Targets = red.Argv(rec.Targets)
	rec.Protected = red.Argv(rec.Protected)
	return rec
}

func verdictOf(action string) string {
	switch action {
	case "catch", "fail":
		return "catch"
	case "hardblock":
		return "hardblock"
	default:
		return "pass"
	}
}

func firstText(parts ...string) string {
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			return p
		}
	}
	return ""
}

func firstSet(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func joinErr(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + "; " + b
}

func wouldID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	const hexd = "0123456789abcdef"
	out := make([]byte, 16)
	for i, c := range b {
		out[i*2] = hexd[c>>4]
		out[i*2+1] = hexd[c&0xf]
	}
	return "would-" + string(out)
}

func describeTargets(cwd string, argv []string, out engine.Outcome) (files, dirs int, link bool, protected, targets []string) {
	targets = append([]string{}, out.Affected.Top...)
	if len(targets) == 0 {
		targets = pathArgs(cwd, argv)
	}
	protected = []string{}
	for _, p := range targets {
		if p == "" {
			continue
		}
		if markerAbove(p) || out.Affected.Protected {
			protected = append(protected, p)
		}
		st, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if st.Mode()&os.ModeSymlink != 0 {
			link = true
		}
		if skipWalk(p) {
			if st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
				dirs++
			} else {
				files++
			}
			continue
		}
		if st.IsDir() {
			f, d := countTree(p, 64, time.Now().Add(200*time.Millisecond))
			files += f
			dirs += d
			continue
		}
		files++
	}
	if files+dirs == 0 && out.Affected.Count > 0 {
		files = out.Affected.Count
	}
	return files, dirs, link, protected, targets
}

func pathArgs(cwd string, argv []string) []string {
	if len(argv) == 0 {
		return nil
	}
	var out []string
	skip := false
	for i, a := range argv {
		if i == 0 || skip {
			skip = false
			continue
		}
		if a == "--" {
			continue
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			continue
		}
		if !filepath.IsAbs(a) {
			a = filepath.Join(cwd, a)
		}
		out = append(out, filepath.Clean(a))
	}
	return out
}

func skipWalk(p string) bool {
	c := filepath.Clean(p)
	switch c {
	case "/", "/bin", "/etc", "/usr", "/home", "/var", "/lib", "/lib64", "/sbin", "/opt", "/root", "/boot":
		return true
	default:
		return false
	}
}

func markerAbove(path string) bool {
	dir := path
	for i := 0; i < 32; i++ {
		if _, err := os.Stat(filepath.Join(dir, ".spotter-sh-protect")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
	return false
}

func countTree(root string, left int, deadline time.Time) (files, dirs int) {
	if left <= 0 || time.Now().After(deadline) {
		return 0, 1
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, 1
	}
	dirs = 1
	for _, e := range entries {
		if time.Now().After(deadline) || left <= 0 {
			break
		}
		left--
		p := filepath.Join(root, e.Name())
		if e.IsDir() {
			f, d := countTree(p, left, deadline)
			files += f
			dirs += d
			continue
		}
		files++
	}
	return files, dirs
}
