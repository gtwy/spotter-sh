// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package rollout is the silent or enforce switch.
// The mode is sealed on the host process. A shell command cannot change it:
// the shim reads the outermost ancestor that was marked as the host, not its
// own environment and not a project config file.
package rollout

import (
	"github.com/gtwy/spotter-sh/internal/envx"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gtwy/spotter-sh/internal/config"
)

// Host is one ancestor process that owns the rollout mode.
type Host struct {
	Found bool
	Env   map[string]string
}

// Normalize accepts silent, enforce, and the old name standard (enforce).
func Normalize(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "silent":
		return "silent"
	case "enforce", "standard":
		return "enforce"
	default:
		return ""
	}
}

// Capture seals the mode on this process. The host calls it once it has
// started. A later shell command cannot reach this process's environment.
// An empty config mode becomes silent.
func Capture(configMode string) string {
	if envx.Get("HOST") == "1" {
		if m := Normalize(envx.Get("MODE")); m != "" {
			return m
		}
	}
	m := Normalize(envx.Get("MODE"))
	if m == "" {
		m = Normalize(configMode)
	}
	if m == "" {
		m = "silent"
	}
	_ = envx.Set("HOST", "1")
	_ = envx.Set("MODE", m)
	return m
}

// Scan walks ancestors and returns the outermost host.
// The current process is not a host: a command can set variables on itself.
func Scan() Host {
	pid := os.Getppid()
	seen := map[int]bool{}
	var outer map[string]string
	for pid > 1 && !seen[pid] && len(seen) < 64 {
		seen[pid] = true
		env := readEnviron(pid)
		if v, ok := envx.MapGet(env, "HOST"); ok && v == "1" {
			outer = env
		}
		next := ppid(pid)
		if next == pid {
			break
		}
		pid = next
	}
	if outer == nil {
		return Host{}
	}
	return Host{Found: true, Env: outer}
}

// HostMode is the sealed mode, or empty when no host is an ancestor.
func HostMode() string {
	h := Scan()
	if !h.Found {
		return ""
	}
	mode, _ := envx.MapGet(h.Env, "MODE")
	return Normalize(mode)
}

// Var reads one variable from the sealed host. A command's own environment
// is ignored while a host is present.
func Var(key string) string {
	h := Scan()
	if !h.Found {
		return ""
	}
	v, _ := envx.MapGet(h.Env, key)
	return v
}

// SilentNow reports whether the spotter-sh CLI must not block.
// The outermost host ancestor wins. Its mode is the environment it was
// started with: a later export in that process does not change it.
// With no host, this process's own SPOTTER_SH_MODE is the operator
// switch (a spotter-sh precheck invocation). Otherwise the root-owned
// config is used. A missing or invalid config stays silent. Only an
// explicit enforce (or the old name standard) enforces.
func SilentNow(cwd string) bool {
	return silent(cwd, true)
}

// ShimSilent is the PATH shim's switch. It does not read this process's
// environment. A prefix assignment such as SPOTTER_SH_MODE=silent rm,
// or the older SHELLSPOTTER_MODE=silent rm, changes only the shim, and
// that must not select the mode.
// A sealed host ancestor selects silent or enforce. With no host in the
// ancestor chain the shim judges and does not fall open. A disowned child
// reparented to init is that case: allowing it would skip the check.
func ShimSilent(cwd string) bool {
	if h := Scan(); h.Found {
		mode, _ := envx.MapGet(h.Env, "MODE")
		return Normalize(mode) != "enforce"
	}
	return false
}

func silent(cwd string, own bool) bool {
	if h := Scan(); h.Found {
		// A host with a missing or invalid mode stays silent. Only an
		// explicit enforce on that host pauses a command.
		mode, _ := envx.MapGet(h.Env, "MODE")
		return Normalize(mode) != "enforce"
	}
	if own {
		if m := Normalize(envx.Get("MODE")); m != "" {
			return m != "enforce"
		}
	}
	cfg, err := config.Load(config.DefaultLocations(cwd))
	if err != nil {
		return true
	}
	return Normalize(cfg.Mode) != "enforce"
}

// JudgeDelay is an optional pause inside the judge, sealed on the host.
// It is for tests that prove the command does not wait. A command cannot
// set it. The delay is capped so a bad value cannot wedge enforce mode.
func JudgeDelay() time.Duration {
	raw := strings.TrimSpace(Var("SPOTTER_SH_JUDGE_DELAY"))
	if raw == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0
	}
	if d > 5*time.Second {
		return 5 * time.Second
	}
	return d
}

func readEnviron(pid int) map[string]string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ")
	if err != nil {
		return nil
	}
	out := map[string]string{}
	start := 0
	for i := 0; i <= len(b); i++ {
		if i != len(b) && b[i] != 0 {
			continue
		}
		part := string(b[start:i])
		start = i + 1
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if ok {
			out[k] = v
		}
	}
	return out
}

func ppid(pid int) int {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	s := string(b)
	i := strings.LastIndex(s, ")")
	if i < 0 || i+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[i+2:])
	if len(fields) < 2 {
		return 0
	}
	n, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return n
}
