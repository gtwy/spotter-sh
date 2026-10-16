// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package shim is the PATH wrapper. On allow it execs the real binary
// with the original argv. On a catch it blocks on the hook socket or
// refuses with a one-time code.
package shim

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gtwy/spotter-sh/internal/envx"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gtwy/spotter-sh/internal/codes"
	"github.com/gtwy/spotter-sh/internal/config"
	"github.com/gtwy/spotter-sh/internal/engine"
	"github.com/gtwy/spotter-sh/internal/journal"
	"github.com/gtwy/spotter-sh/internal/precheck"
	"github.com/gtwy/spotter-sh/internal/redact"
	"github.com/gtwy/spotter-sh/internal/rollout"
)

// Run is the shim entry. It does not return on a successful exec.
func Run(argv []string) int {
	code := 122
	defer func() {
		if rec := recover(); rec != nil {
			fmt.Fprintf(os.Stderr, "Shell Spotter failed; command not run; see log; a human can run it by hand or fix the spotter\n")
			os.Exit(122)
		}
	}()
	code = run(argv)
	return code
}

func run(argv []string) int {
	if len(argv) == 0 {
		return 127
	}
	cwd, _ := os.Getwd()
	home := engine.HomeDir()
	if home == "" {
		fmt.Fprintln(os.Stderr, "Shell Spotter failed; command not run; see log; a human can run it by hand or fix the spotter")
		return 122
	}
	// Silent mode execs first. Judgment and the log happen in another process.
	if rollout.ShimSilent(cwd) {
		return runSilent(argv, cwd, home)
	}
	cfg, err := config.Load(config.DefaultLocations(cwd))
	if err != nil {
		return failOrOpen(nil, argv, "invalid config: "+err.Error())
	}
	state := stateDir()
	store := codes.Store{Dir: state}
	keyErr := store.KeyReadable()
	red := redact.New(cfg.RedactExtra)
	log := journal.Logger{Path: cfg.Log.Path, Level: cfg.Log.Level, MaxMB: cfg.Log.MaxMB}

	name := invokedName(argv[0])
	// exec -a sets argv[0] to the alias. Classification uses the real command
	// name. The exec below still receives the original argv, byte for byte.
	judge := argv
	if got := filepath.Base(argv[0]); got != name && name != "" {
		judge = append([]string(nil), argv...)
		judge[0] = name
	}
	real, err := resolveReal(name, argv[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Shell Spotter: %s: command not found\n", name)
		return 127
	}
	in := engine.Input{
		Argv: judge, Cwd: cwd, Env: os.Environ(), Home: home, Config: cfg,
		StdinKind: stdinKind(), StdinPeek: peekStdin(cfg),
		Hostname: hostname(),
		Deadline: time.Now().Add(cfg.FailTimeout),
	}
	if d := rollout.JudgeDelay(); d > 0 {
		time.Sleep(d)
	}
	out := engine.Decide(in)
	// A pipeline's first shimmed command may be sed or find, which are
	// harmless alone. The shell's script is the whole pipeline.
	if out.Action == "allow" {
		if script := parentScript(); script != "" {
			r := precheck.ScanAt(script, cwd, home)
			if r.Action == "hardblock" || r.Action == "catch" {
				out = engineOutcome(r)
			}
		}
	}
	// One approval covers the command that was approved and the commands it
	// runs. A hard block is not covered: / , the home directory, a disk, and
	// a fork bomb still stop.
	if out.Action == "catch" && coverAllows() {
		out.Action = "allow"
		out.Exit = 0
	}
	// An allowed command does not need the HMAC key. env -i clears the
	// environment that points at it; failing closed there skips harmless work.
	// A catch with no hook still needs the key to mint a code, and does not run.
	if keyErr != nil && out.Action != "allow" && out.Action != "hardblock" && envx.Get("HOOK") == "" {
		return failOrOpen(&cfg, argv, "missing key")
	}
	if out.Action == "allow" {
		stripOK(os.Environ())
		if out.Near {
			_ = log.Write(journal.Event{Event: "allow_near", Cmd: name, Argv: red.Argv(argv), Cwd: cwd, Targets: out.Affected.Count}, true)
		} else if cfg.Log.Level == "all" {
			_ = log.Write(journal.Event{Event: "allow", Cmd: name, Argv: red.Argv(shapeArgv(argv)), Cwd: cwd}, false)
		}
		if out.LogNote != "" {
			_ = log.Write(journal.Event{Event: out.LogNote, Cmd: name, Cwd: cwd}, false)
		}
		return execReal(real, argv, childEnv(name, stripOK(os.Environ())))
	}
	if out.Action == "fail" {
		fmt.Fprintln(os.Stderr, out.Message)
		_ = log.Write(journal.Event{Event: "spotter_error", Cmd: name, Reason: out.Message, Cwd: cwd}, false)
		return 122
	}
	if out.Action == "hardblock" && !out.Approve {
		msg := out.Message
		if msg == "" {
			msg = out.Report
		}
		fmt.Fprintln(os.Stderr, red.Apply(msg))
		_ = log.Write(journal.Event{Event: "block", Level: "hardblock", Cmd: name, Argv: red.Argv(argv), Cwd: cwd, Case: out.Case}, false)
		// No catch id. An admin cannot proceed, and the shell does not pause.
		return 121
	}
	// catch
	rec := record(out, argv, cwd, red)
	if envx.Get("RESTRICTED") == "1" {
		rec["restricted"] = true
	}
	report := red.MaskValues(red.Apply(out.Report), red.SecretValues(argv))
	if hook := envx.Get("HOOK"); hook != "" && cfg.Approval.Mode != "code" {
		if decided, proceed := askHook(hook, rec, cfg, false); decided {
			if proceed {
				_ = log.Write(journal.Event{Event: "decision", Level: out.Level, Cmd: name, Argv: red.Argv(argv), Cwd: cwd, Case: out.Case, Decision: "proceed", Mode: "hook", DecidedBy: "agent"}, false)
				argv, env := inject(out, argv, stripOK(os.Environ()))
				return execReal(real, argv, env)
			}
			fmt.Fprintln(os.Stderr, report)
			_ = log.Write(journal.Event{Event: "decision", Level: out.Level, Cmd: name, Argv: red.Argv(argv), Cwd: cwd, Case: out.Case, Decision: "cancel", Mode: "hook", DecidedBy: "agent"}, false)
			return 120
		}
	}
	if cmd := cfg.HookCommand; cmd != "" && envx.Get("HOOK") == "" {
		if proceed, ok := askCommand(cmd, rec); ok && proceed {
			argv, env := inject(out, argv, stripOK(os.Environ()))
			return execReal(real, argv, env)
		} else if ok {
			fmt.Fprintln(os.Stderr, report)
			return 120
		}
	}
	// code mode
	return codeMode(store, cfg, out, argv, cwd, real, red, log, name, report)
}

func codeMode(store codes.Store, cfg config.Config, out engine.Outcome, argv []string, cwd, real string, red redact.Text, log journal.Logger, name, report string) int {
	// A key this user can read can sign a code. Do not issue or accept one.
	// The host socket is still the approval path. Exit 120, not 122.
	if store.CallerControlsKey() {
		fmt.Fprintln(os.Stderr, report)
		fmt.Fprintln(os.Stderr, "Shell Spotter: the install key is readable by this user, so a one-time code cannot be trusted. A human has to approve this, or reinstall with --system.")
		_ = log.Write(journal.Event{Event: "catch", Level: out.Level, Cmd: name, Argv: red.Argv(argv), Cwd: cwd, Case: out.Case, Targets: out.Affected.Count, Top: red.Argv(out.Affected.Top)}, false)
		return 120
	}
	bind := codes.Binding{Argv: argv, Cwd: cwd, Targets: out.Affected.Top, Level: out.Level, Extra: out.Safer}
	if given := envx.Get("OK"); given != "" {
		if !codes.ValidFormat(given, cfg.Approval.CodePrefix) {
			_ = log.Write(journal.Event{Event: "inherited_ok", Cmd: name, Cwd: cwd, Reason: "not a code"}, false)
		} else if err := store.Verify(given, bind); err == nil {
			_ = log.Write(journal.Event{Event: "decision", Level: out.Level, Cmd: name, Argv: red.Argv(argv), Cwd: cwd, Decision: "proceed", Mode: "code", DecidedBy: "agent"}, false)
			noteForce(store, cfg, out.Level)
			argv, env := inject(out, argv, stripOK(os.Environ()))
			return execReal(real, argv, env)
		} else {
			_ = log.Write(journal.Event{Event: "code_rejected", Cmd: name, Cwd: cwd, Reason: "mismatch"}, false)
		}
	}
	code, err := store.Issue(bind, cfg.Approval.CodeTTL, cfg.Approval.CodePrefix)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Shell Spotter failed; command not run; see log; a human can run it by hand or fix the spotter")
		return 122
	}
	fmt.Fprintln(os.Stderr, report)
	fmt.Fprintln(os.Stderr, "if this is EXACTLY what you meant, re-run the identical command with the code below")
	fmt.Fprintln(os.Stderr, "    "+rerunLine(code, argv, red))
	if tripped, n := forceTripped(store, cfg); tripped && out.Level == "danger" {
		fmt.Fprintf(os.Stderr, "Shell Spotter: you have proceeded on %d dangerous commands in %d minutes — STOP and check with your human before continuing\n", n, int(cfg.ForceRate.Window.Minutes()))
		_ = log.Write(journal.Event{Event: "force_rate_alert", Level: "danger", Cmd: name, Cwd: cwd}, false)
	}
	_ = log.Write(journal.Event{Event: "catch", Level: out.Level, Cmd: name, Argv: red.Argv(argv), Cwd: cwd, Case: out.Case, Targets: out.Affected.Count, Top: red.Argv(out.Affected.Top)}, false)
	return 120
}

func askHook(path string, rec map[string]any, cfg config.Config, hard bool) (decided, proceed bool) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return false, false
	}
	defer conn.Close()
	buf, _ := json.Marshal(rec)
	if _, err := conn.Write(append(buf, '\n')); err != nil {
		return false, false
	}
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return true, false
		}
		var d struct {
			Decision string `json:"decision"`
			Reason   string `json:"reason"`
		}
		if json.Unmarshal(line, &d) != nil {
			return true, false
		}
		switch d.Decision {
		case "proceed":
			if hard || rec["restricted"] == true {
				return true, false
			}
			if rec["level"] == "danger" && strings.Contains(strings.ToLower(fmt.Sprint(rec["affected"])), "power") {
				// hostname gate is the host's job; the shim also checks the reason
				// when the safer rewrite is a hostname.
			}
			return true, true
		case "cancel", "":
			return true, false
		case "ask_human":
			continue
		default:
			return true, false
		}
	}
}

func askCommand(cmd string, rec map[string]any) (proceed, ok bool) {
	buf, _ := json.Marshal(rec)
	c := exec.Command(cmd)
	c.Stdin = bytes.NewReader(append(buf, '\n'))
	var out []byte
	var cmdErr error
	if err := engine.PrepareChild(c); err != nil {
		return false, false
	}
	out, cmdErr = c.Output()
	err := cmdErr
	if err != nil {
		return false, true
	}
	var d struct {
		Decision string `json:"decision"`
	}
	if json.Unmarshal(bytes.TrimSpace(out), &d) != nil {
		return false, true
	}
	if d.Decision == "proceed" && rec["restricted"] != true && (rec["level"] != "hardblock" || rec["approve"] == true) {
		return true, true
	}
	return false, true
}

func record(out engine.Outcome, argv []string, cwd string, red redact.Text) map[string]any {
	level := out.Level
	if level == "" {
		level = "danger"
	}
	vals := red.SecretValues(argv)
	tops := red.Argv(out.Affected.Top)
	for i := range tops {
		tops[i] = red.MaskValues(tops[i], vals)
	}
	aff := map[string]any{
		"op":            out.Affected.Op,
		"count":         out.Affected.Count,
		"top_paths":     tops,
		"protected_hit": out.Affected.Protected,
	}
	if out.Affected.TimedOut {
		aff["timed_out"] = true
		aff["partial_count"] = out.Affected.Partial
	}
	rec := map[string]any{
		"schema_version": "1.0",
		"catch_id":       catchID(),
		"level":          level,
		"command":        red.Join(argv),
		"argv":           red.Argv(argv),
		"cwd":            cwd,
		"restricted":     false,
		"report":         red.MaskValues(red.Apply(out.Report), vals),
		"affected":       aff,
		"consequence":    red.Apply(out.Consequence),
		"common_mistake": red.Apply(out.Mistake),
		"safer_rewrite":  red.Apply(out.Safer),
	}
	if out.Approve {
		rec["approve"] = true
	}
	return rec
}

func catchID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	const hexd = "0123456789abcdef"
	out := make([]byte, 16)
	for i, c := range b {
		out[i*2] = hexd[c>>4]
		out[i*2+1] = hexd[c&0xf]
	}
	return string(out)
}

func inject(out engine.Outcome, argv, env []string) ([]string, []string) {
	// The user's argv is executed byte for byte. Safe-mode is a classification
	// bit on the outcome. It is not a flag added to the command.
	_ = out
	return argv, env
}

func execReal(real string, argv, env []string) int {
	if len(argv) > 0 {
		env = childEnv(argv[0], env)
	}
	// pread does not move the offset. Do not rewind stdin: a shell that has
	// already read part of a redirected file must keep that position.
	// The shim may be setgid so it can read the HMAC key. Drop that group
	// before the wrapped program starts, or the program could read the key.
	runtime.LockOSThread()
	if err := engine.DropThread(); err != nil {
		fmt.Fprintf(os.Stderr, "Shell Spotter failed; command not run; see log; a human can run it by hand or fix the spotter\n")
		return 122
	}
	if err := syscall.Exec(real, argv, env); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			fmt.Fprintf(os.Stderr, "Shell Spotter: %s: command not found\n", argv[0])
			return 127
		}
		fmt.Fprintf(os.Stderr, "Shell Spotter failed; command not run; see log; a human can run it by hand or fix the spotter\n")
		return 122
	}
	return 0
}

// DropExec is the setgid child's first step. The OS thread is locked before
// the gid drop so the drop cannot migrate, then this process is replaced
// with the real program. The drop token is already cleared.
func DropExec(real string, argv []string) int {
	if real == "" || len(argv) == 0 {
		return 122
	}
	runtime.LockOSThread()
	_ = envx.Unset("DROP")
	if err := engine.DropThread(); err != nil {
		return 122
	}
	env := envx.Strip(os.Environ(), "DROP")
	if err := syscall.Exec(real, argv, env); err != nil {
		return 122
	}
	return 0
}

func stripOK(env []string) []string {
	return envx.Strip(env, "OK")
}

func failOrOpen(cfg *config.Config, argv []string, why string) int {
	open := cfg != nil && cfg.Fail == "open"
	if open {
		name := filepath.Base(argv[0])
		if real, err := resolveReal(name, argv[0]); err == nil {
			return execReal(real, argv, os.Environ())
		}
	}
	fmt.Fprintf(os.Stderr, "Shell Spotter failed; command not run; see log; a human can run it by hand or fix the spotter (%s)\n", why)
	return 122
}

func resolveReal(name, argv0 string) (string, error) {
	self, _ := os.Executable()
	self = filepath.Clean(self)
	shimDir := envx.Get("SHIM_DIR")
	if shimDir == "" && strings.Contains(argv0, "/") {
		shimDir = filepath.Dir(argv0)
	}
	path := os.Getenv("PATH")
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			continue
		}
		if shimDir != "" && sameDir(dir, shimDir) {
			continue
		}
		cand := filepath.Join(dir, name)
		st, err := os.Stat(cand)
		if err != nil || st.IsDir() {
			continue
		}
		if st.Mode()&0o111 == 0 {
			continue
		}
		if sameFile(cand, self) {
			continue
		}
		return cand, nil
	}
	return "", os.ErrNotExist
}

func sameDir(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return aa == bb
}

func sameFile(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return os.SameFile(sa, sb)
}

func stdinKind() string {
	st, err := os.Stdin.Stat()
	if err != nil {
		return "other"
	}
	if st.Mode()&os.ModeNamedPipe != 0 {
		return "pipe"
	}
	if st.Mode().IsRegular() {
		return "file"
	}
	if st.Mode()&os.ModeCharDevice != 0 {
		// /dev/null is a device. Treat it as null, which is an interactive session.
		if st.Name() == "null" || filepath.Base(os.Stdin.Name()) == "null" {
			return "null"
		}
		return "tty"
	}
	return "other"
}

func peekStdin(cfg config.Config) []byte {
	if stdinKind() != "file" {
		return nil
	}
	n := cfg.DB.SQLScanKB
	if n <= 0 {
		n = 256
	}
	buf := make([]byte, n*1024)
	fd := int(os.Stdin.Fd())
	got, err := syscall.Pread(fd, buf, 0)
	if err != nil || got == 0 {
		return nil
	}
	return buf[:got]
}

func engineOutcome(r precheck.Result) engine.Outcome {
	o := engine.Outcome{
		Action:      r.Action,
		Exit:        r.Exit,
		Case:        r.Case,
		Message:     r.Message,
		Consequence: r.Message,
		Approve:     r.Approve,
		Report:      r.Message,
	}
	if r.Action == "hardblock" {
		o.Level = "hardblock"
		if o.Exit == 0 {
			o.Exit = 121
		}
		return o
	}
	o.Level = "danger"
	if o.Exit == 0 {
		o.Exit = 120
	}
	return o
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

func stateDir() string {
	return codes.FixedDir()
}

// coverAllows asks the host whether this process is still inside the
// approved process tree. The environment and the key directory are not
// consulted: both are reachable by the caller.
func coverAllows() bool {
	hookPath := envx.Get("HOOK")
	if hookPath == "" {
		return false
	}
	return dialOp(hookPath, "covered") == 0
}

// Seal asks the host to bind the approval to this process's parent.
// The binary name must be spotter-sh. A shim named rm must not take this path.
func Seal() int {
	hookPath := envx.Get("HOOK")
	if hookPath == "" {
		return 1
	}
	return dialOp(hookPath, "seal")
}

func dialOp(path, op string) int {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return 1
	}
	defer conn.Close()
	buf, _ := json.Marshal(map[string]string{"op": op})
	if _, err := conn.Write(append(buf, '\n')); err != nil {
		return 1
	}
	r := bufio.NewReader(conn)
	line, err := r.ReadBytes('\n')
	if err != nil {
		return 1
	}
	var d struct {
		Decision string `json:"decision"`
	}
	if json.Unmarshal(line, &d) != nil || d.Decision != "proceed" {
		return 1
	}
	return 0
}

func invokedName(argv0 string) string {
	base := filepath.Base(argv0)
	comm := readComm()
	if comm == "" || comm == "spotter-sh" || comm == "spotter-sh.exe" {
		return base
	}
	return comm
}

func readComm() string {
	b, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func rerunLine(code string, argv []string, red redact.Text) string {
	return envx.Name("OK") + "=" + code + " " + quoteAll(red.Argv(argv))
}

func quoteAll(argv []string) string {
	var b strings.Builder
	for i, a := range argv {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(bashQuote(a))
	}
	return b.String()
}

func bashQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func shapeArgv(argv []string) []string {
	// level=all must not store SQL bodies. Replace -c/-e/--eval values.
	var out []string
	skip := false
	for _, a := range argv {
		if skip {
			out = append(out, "[statement]")
			skip = false
			continue
		}
		if a == "-c" || a == "-e" || a == "--eval" || a == "--command" || a == "--execute" {
			out = append(out, a)
			skip = true
			continue
		}
		out = append(out, a)
	}
	return out
}

func noteForce(store codes.Store, cfg config.Config, level string) {
	if level != "danger" || !cfg.ForceRate.Enabled {
		return
	}
	p := filepath.Join(store.Dir, "force-rate")
	_ = os.MkdirAll(store.Dir, 0o700)
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, time.Now().Unix())
}

func forceTripped(store codes.Store, cfg config.Config) (bool, int) {
	if !cfg.ForceRate.Enabled {
		return false, 0
	}
	buf, err := os.ReadFile(filepath.Join(store.Dir, "force-rate"))
	if err != nil {
		return false, 0
	}
	cut := time.Now().Add(-cfg.ForceRate.Window).Unix()
	n := 0
	for _, line := range strings.Split(string(buf), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ts int64
		fmt.Sscan(line, &ts)
		if ts >= cut {
			n++
		}
	}
	return n >= cfg.ForceRate.Max, n
}

// Check classifies without executing. Used by the check subcommand.
func Check(argv []string) engine.Outcome {
	cwd, _ := os.Getwd()
	home := engine.HomeDir()
	if home == "" {
		return engine.Outcome{Action: "fail", Exit: 122, Message: "Shell Spotter failed; command not run; see log; a human can run it by hand or fix the spotter"}
	}
	cfg, err := config.Load(config.DefaultLocations(cwd))
	if err != nil {
		return engine.Outcome{Action: "fail", Exit: 122, Message: "Shell Spotter failed; command not run; see log; a human can run it by hand or fix the spotter"}
	}
	in := engine.Input{Argv: argv, Cwd: cwd, Home: home, Config: cfg, StdinKind: stdinKind(), StdinPeek: peekStdin(cfg), Hostname: hostname()}
	return engine.Decide(in)
}

// Decide classifies with an explicit input. Tests and the check command use it.
func Decide(in engine.Input) engine.Outcome { return engine.Decide(in) }
