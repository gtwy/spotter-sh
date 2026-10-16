// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"github.com/gtwy/spotter-sh/internal/envx"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gtwy/spotter-sh"
	"github.com/gtwy/spotter-sh/hook"
	"github.com/gtwy/spotter-sh/internal/codes"
	"github.com/gtwy/spotter-sh/internal/config"
	"github.com/gtwy/spotter-sh/internal/engine"
	"github.com/gtwy/spotter-sh/internal/journal"
	"github.com/gtwy/spotter-sh/internal/precheck"
	"github.com/gtwy/spotter-sh/internal/rollout"
	"github.com/gtwy/spotter-sh/internal/shim"
	"github.com/gtwy/spotter-sh/internal/silentlog"
)

func main() {
	// The setgid child proves itself with an env token the parent signed.
	// A matching argv flag is not a mode: users can pass that to rm or chmod.
	if real, ok := engine.TakeDrop(os.Args); ok {
		os.Exit(shim.DropExec(real, os.Args))
	}
	// The detached judge re-execs this binary by its real name.
	// A shim named rm must not take this path: rm __silent is a filename.
	if len(os.Args) == 2 && os.Args[1] == "__silent" && spotterName(os.Args[0]) {
		os.Exit(shim.SilentWorker())
	}
	if len(os.Args) == 2 && os.Args[1] == "__seal" && spotterName(os.Args[0]) {
		os.Exit(shim.Seal())
	}
	base := filepath.Base(os.Args[0])
	if base != "spotter-sh" && base != "spotter-sh.exe" {
		os.Exit(shim.Run(os.Args))
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "exec":
		if len(args) == 0 {
			os.Exit(2)
		}
		os.Exit(shim.Run(args))
	case "precheck":
		os.Exit(cmdPrecheck(args))
	case "check":
		os.Exit(cmdCheck(args))
	case "explain":
		os.Exit(cmdExplain(args))
	case "test":
		fmt.Fprintln(os.Stderr, "Shell Spotter test: run go test ./... inside the spotter-sh module")
		os.Exit(0)
	case "install":
		os.Exit(cmdInstall(args))
	case "uninstall":
		os.Exit(cmdUninstall(args))
	case "doctor":
		os.Exit(cmdDoctor())
	case "log":
		os.Exit(cmdLog(args))
	case "report":
		os.Exit(cmdReport(args))
	case "scan":
		os.Exit(cmdScan(args))
	case "config":
		os.Exit(cmdConfig(args))
	case "init":
		os.Exit(cmdInit())
	case "version", "--version", "-V":
		fmt.Println(spottersh.Version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Shell Spotter %s\nusage: spotter-sh <exec|precheck|check|explain|test|install|uninstall|doctor|log|report|scan|config|init>\n", spottersh.Version)
}

func cmdPrecheck(args []string) int {
	adapter := ""
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--adapter" && i+1 < len(args) {
			adapter = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(args[i], "--adapter=") {
			adapter = strings.TrimPrefix(args[i], "--adapter=")
			continue
		}
		rest = append(rest, args[i])
	}
	cmd := hook.CommandFromArgs(rest)
	if strings.TrimSpace(cmd) == "" {
		s, err := hook.StdinCommand()
		if err != nil {
			return 122
		}
		cmd = s
	}
	if adapter != "" {
		return hook.WriteAdapter(os.Stdout, adapter, cmd)
	}
	r := precheck.Scan(cmd)
	if rollout.SilentNow("") {
		// Log the would-be verdict and let the caller continue.
		// Printing the block line would alert the shell.
		_ = writeSilentPrecheck(cmd, r)
		return 0
	}
	if r.Message != "" && r.Action != "allow" {
		fmt.Fprintln(os.Stderr, r.Message)
	}
	return r.Exit
}

func writeSilentPrecheck(cmd string, r precheck.Result) error {
	cwd, _ := os.Getwd()
	home, _ := os.UserHomeDir()
	cfg, _ := config.Load(config.DefaultLocations(cwd))
	path := cfg.Log.SilentPath
	if path == "" && home != "" {
		path = filepath.Join(home, ".local", "state", "spotter-sh", "silent.jsonl")
	}
	rec := silentlog.Record{
		Cwd:     cwd,
		Raw:     cmd,
		Layer:   "precheck",
		Verdict: "pass",
		Trust:   "none",
	}
	switch r.Action {
	case "hardblock":
		rec.Verdict = "hardblock"
		rec.Rule = r.Case
		rec.Reason = r.Message
	case "catch":
		rec.Verdict = "catch"
		rec.Rule = r.Case
		rec.Reason = r.Message
	}
	return silentlog.Write(rec, silentlog.Options{Path: path, MaxBytes: int64(cfg.Log.SilentMaxMB) << 20, MaxAge: cfg.Log.SilentMaxAge})
}

func spotterName(argv0 string) bool {
	base := filepath.Base(argv0)
	return base == "spotter-sh" || base == "spotter-sh.exe"
}

func cmdCheck(args []string) int {
	argv := args
	if len(argv) > 0 && argv[0] == "--" {
		argv = argv[1:]
	}
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: spotter-sh check -- <argv>")
		return 2
	}
	out := shim.Check(argv)
	if out.Report != "" {
		fmt.Fprint(os.Stderr, out.Report)
	} else if out.Message != "" {
		fmt.Fprintln(os.Stderr, out.Message)
	}
	if out.Exit != 0 {
		return out.Exit
	}
	return 0
}

func cmdExplain(args []string) int {
	which := "all"
	if len(args) > 0 {
		which = args[0]
	}
	text := map[string]string{
		"A": "Case A — parent of the working directory, or a sweep of a filesystem root. This is the '.*' accident.",
		"B": "Case B — empty variable. rm -rf $DIR/ when DIR is empty becomes rm -rf /.",
		"C": "Case C — bulk delete or overwrite over the threshold.",
		"D": "Case D — root or home sweep: rm -rf /, /*, ~, or ~/.",
		"E": "Case E — protected path or a permission that breaks a required mode.",
		"F": "Case F — database, git, infra, or power command with a wide effect.",
	}
	if which == "all" {
		for _, k := range []string{"A", "B", "C", "D", "E", "F"} {
			fmt.Println(text[k])
		}
		return 0
	}
	if t, ok := text[strings.ToUpper(which)]; ok {
		fmt.Println(t)
		return 0
	}
	fmt.Fprintln(os.Stderr, "unknown case")
	return 2
}

func cmdInstall(args []string) int {
	system := false
	refresh := false
	for _, a := range args {
		switch a {
		case "--system":
			system = true
		case "--user":
			system = false
		case "--refresh":
			refresh = true
		}
	}
	_ = refresh
	home, _ := os.UserHomeDir()
	shimDir := filepath.Join(home, ".local", "lib", "spotter-sh", "shims")
	state := filepath.Join(home, ".local", "state", "spotter-sh")
	if system {
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "install --system needs root")
			return 1
		}
		shimDir = "/usr/local/lib/spotter-sh/shims"
		state = "/var/lib/spotter-sh"
	}
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	exe, _ = filepath.EvalSymlinks(exe)
	linked := 0
	for _, name := range catalog() {
		if _, err := lookPathSkip(name, shimDir); err != nil {
			continue
		}
		dest := filepath.Join(shimDir, name)
		_ = os.Remove(dest)
		if err := os.Symlink(exe, dest); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		linked++
	}
	if err := codes.EnsureKey(state); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := codes.WriteStamp(exe, state); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if system {
		// The key stays unreadable to the agent. The shim is setgid
		// spotter-sh so it can read the key. The agent is not in that group,
		// so it cannot mint a code or a cover.
		if err := publishSystemKey(state, exe); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	} else if err := publishUserKey(state); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("installed %d shims in %s\n", linked, shimDir)
	fmt.Printf("state: %s\n", state)
	fmt.Printf("prepend PATH: export PATH=%s:$PATH\n", shimDir)
	fmt.Println("do not add this to a login shell; set it on the agent spawn only")
	if system {
		fmt.Println("key: root:spotter-sh mode 0640. The agent user must not be in group spotter-sh. One-time codes work because the agent cannot read the key.")
	} else {
		fmt.Println("key: mode 0600, owned by this user. The agent can read it, so one-time codes are disabled. Approve through the host, or reinstall with --system.")
	}
	return 0
}

// publishUserKey forces the user state directory to 0700 and the key to 0600.
// That still does not hide the key from the agent, who owns it. Codes stay off.
func publishUserKey(state string) error {
	if err := os.Chmod(state, 0o700); err != nil {
		return err
	}
	return os.Chmod(filepath.Join(state, "key"), 0o600)
}

// publishSystemKey makes the state directory setgid spotter-sh, mode 02770,
// and the key mode 0640. Other users cannot read the key or mint approvals.
// The spotter-sh binary is setgid spotter-sh, so a non-root shim still can.
// Symlinks to that binary keep the inode's setgid bit.
func publishSystemKey(state, exe string) error {
	gid := ensureSpotterGroup()
	if err := os.Chmod(state, os.ModeSetgid|0o770); err != nil {
		return err
	}
	key := filepath.Join(state, "key")
	if err := os.Chmod(key, 0o640); err != nil {
		return err
	}
	if gid >= 0 {
		_ = os.Chown(state, 0, gid)
		_ = os.Chown(key, 0, gid)
	}
	if exe == "" {
		return nil
	}
	if gid >= 0 {
		_ = os.Chown(exe, 0, gid)
		_ = os.Chown(exe+".state", 0, gid)
	}
	if err := os.Chmod(exe, os.ModeSetgid|0o755); err != nil {
		return err
	}
	info, err := os.Stat(key)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o640 {
		return fmt.Errorf("key mode is %o, want 0640", info.Mode().Perm())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return fmt.Errorf("key is not root-owned")
	}
	return nil
}

func ensureSpotterGroup() int {
	if g, err := user.LookupGroup("spotter-sh"); err == nil {
		if id, err := strconv.Atoi(g.Gid); err == nil {
			return id
		}
	}
	if err := exec.Command("groupadd", "--system", "spotter-sh").Run(); err != nil {
		return -1
	}
	g, err := user.LookupGroup("spotter-sh")
	if err != nil {
		return -1
	}
	id, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1
	}
	return id
}

func cmdUninstall(args []string) int {
	system := false
	for _, a := range args {
		if a == "--system" {
			system = true
		}
	}
	home, _ := os.UserHomeDir()
	shimDir := filepath.Join(home, ".local", "lib", "spotter-sh", "shims")
	if system {
		shimDir = "/usr/local/lib/spotter-sh/shims"
	}
	if err := os.RemoveAll(shimDir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("removed", shimDir)
	return 0
}

func cmdDoctor() int {
	home, _ := os.UserHomeDir()
	shimDir := envx.Get("SHIM_DIR")
	if shimDir == "" {
		user := filepath.Join(home, ".local", "lib", "spotter-sh", "shims")
		if st, err := os.Stat(user); err == nil && st.IsDir() {
			shimDir = user
		} else if st, err := os.Stat("/usr/local/lib/spotter-sh/shims"); err == nil && st.IsDir() {
			shimDir = "/usr/local/lib/spotter-sh/shims"
		}
	}
	bad := 0
	check := func(ok bool, name, detail string) {
		mark := "ok"
		if !ok {
			mark = "FAIL"
			bad++
		}
		fmt.Printf("%s  %s  %s\n", mark, name, detail)
	}
	check(shimDir != "", "shims", shimDir)
	state := codes.FixedDir()
	if envx.Get("HOME") != "" {
		fmt.Println("ok  state-override  SPOTTER_SH_HOME is set and ignored")
	}
	store := codes.Store{Dir: state}
	err := store.KeyReadable()
	check(err == nil, "key", state)
	if store.CallerControlsKey() {
		if state == "/var/lib/spotter-sh" {
			check(false, "key-perm", "system key is readable by this user")
		} else {
			fmt.Println("ok  key-perm  user key is readable by this user; one-time codes are disabled until install --system")
		}
	} else {
		fmt.Println("ok  key-perm  key is not readable by this user")
	}
	if shimDir != "" {
		first := firstOnPath("rm")
		check(strings.HasPrefix(first, shimDir+string(os.PathSeparator)), "rm-shim", first)
	}
	if hookPath := envx.Get("HOOK"); hookPath != "" {
		_, err := os.Stat(hookPath)
		check(err == nil, "hook", hookPath)
	} else {
		fmt.Println("ok  hook  not set (code fallback)")
	}
	cwd, _ := os.Getwd()
	cfg, err := config.Load(config.DefaultLocations(cwd))
	check(err == nil, "config", "")
	if err == nil {
		fmt.Printf("ok  packs  %s\n", strings.Join(cfg.Commands.Packs, ","))
		mode := rollout.Normalize(cfg.Mode)
		if m := rollout.HostMode(); m != "" {
			mode = m
		}
		if mode == "" {
			mode = "silent"
		}
		fmt.Printf("ok  mode  %s\n", mode)
	}
	fmt.Println("spawn snippet:")
	fmt.Printf("  export PATH=%s:$PATH\n", shimDir)
	if bad > 0 {
		return 1
	}
	return 0
}

func cmdReport(args []string) int {
	cwd, _ := os.Getwd()
	home, _ := os.UserHomeDir()
	cfg, _ := config.Load(config.DefaultLocations(cwd))
	path := cfg.Log.SilentPath
	if path == "" && home != "" {
		path = filepath.Join(home, ".local", "state", "spotter-sh", "silent.jsonl")
	}
	export := ""
	since := time.Time{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--log":
			if i+1 >= len(args) {
				return 2
			}
			i++
			path = args[i]
		case "--export":
			if i+1 >= len(args) {
				return 2
			}
			i++
			export = args[i]
		case "--since":
			if i+1 >= len(args) {
				return 2
			}
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil {
				fmt.Fprintln(os.Stderr, "since wants a duration such as 168h")
				return 2
			}
			since = time.Now().Add(-d)
		default:
			fmt.Fprintln(os.Stderr, "usage: spotter-sh report [--log path] [--since 168h] [--export held.jsonl]")
			return 2
		}
	}
	recs, err := silentlog.Read(path, since)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	rep := silentlog.Summarize(recs)
	fmt.Print(silentlog.Format(rep))
	if export != "" {
		if err := silentlog.ExportHeld(export, recs); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("export %s\n", export)
	}
	return 0
}

func cmdLog(args []string) int {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".local", "state", "spotter-sh", "spotter.log")
	if len(args) > 0 && args[0] == "--summary" {
		c, err := journal.Summary(path, time.Time{})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		for k, n := range c {
			fmt.Printf("%s %d\n", k, n)
		}
		return 0
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	os.Stdout.Write(buf)
	return 0
}

func cmdScan(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: spotter-sh scan <dir>")
		return 2
	}
	bad := 0
	_ = filepath.Walk(args[0], func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".sh") && !strings.HasSuffix(path, ".bash") {
			return nil
		}
		buf, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		r := precheck.Scan(string(buf))
		if r.Action != "allow" {
			fmt.Printf("%s: %s\n", path, r.Message)
			bad++
		}
		return nil
	})
	if bad > 0 {
		return 1
	}
	return 0
}

func cmdConfig(args []string) int {
	cwd, _ := os.Getwd()
	cfg, err := config.Load(config.DefaultLocations(cwd))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Shell Spotter failed; command not run; see log; a human can run it by hand or fix the spotter")
		return 122
	}
	fmt.Print(cfg.Explain())
	return 0
}

func cmdInit() int {
	fmt.Println("# agent spawn only — do not put this in a login shell")
	home, _ := os.UserHomeDir()
	fmt.Printf("export PATH=%s:$PATH\n", filepath.Join(home, ".local", "lib", "spotter-sh", "shims"))
	return 0
}

func catalog() []string {
	return []string{
		"bash", "sh", "dash", "zsh", "ksh",
		"rm", "rmdir", "unlink", "shred", "trash-put", "chmod", "chown", "chgrp", "setfacl",
		"cp", "mv", "ln", "install", "rsync", "dd", "find", "tar", "unzip", "sed", "perl", "truncate",
		"mkfs", "wipefs", "blkdiscard", "fdisk", "sgdisk", "parted", "sudo", "doas",
		"git",
		"mysql", "mariadb", "psql", "sqlite3", "mongosh", "mongo", "redis-cli", "clickhouse-client", "cockroach",
		"docker", "kubectl", "helm", "terraform", "aws", "gcloud", "gsutil", "crontab", "systemctl", "iptables", "userdel",
		"reboot", "shutdown", "halt", "poweroff",
	}
}

func lookPathSkip(name, skip string) (string, error) {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" || dir == skip {
			continue
		}
		cand := filepath.Join(dir, name)
		st, err := os.Stat(cand)
		if err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return cand, nil
		}
	}
	return "", os.ErrNotExist
}

func firstOnPath(name string) string {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		cand := filepath.Join(dir, name)
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand
		}
	}
	return ""
}
