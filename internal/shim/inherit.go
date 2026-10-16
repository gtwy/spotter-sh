// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package shim

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/gtwy/spotter-sh/internal/envx"
	"github.com/gtwy/spotter-sh/internal/rollout"
)

// childEnv keeps a nested shell inside the spotter. The shim directory stays
// first on PATH, and SPOTTER_SH_* / SHELLSPOTTER_* values sealed on the host
// are put back when this process was started with a cleared environment.
// Other commands keep the environment they were given.
func childEnv(name string, env []string) []string {
	if !shellBin(name) {
		return env
	}
	return sealShellEnv(env, shimDirNow(), rollout.Scan().Env)
}

func shellBin(name string) bool {
	switch filepath.Base(name) {
	case "bash", "sh", "dash", "zsh", "ksh":
		return true
	default:
		return false
	}
}

func shimDirNow() string {
	if d := envx.Get("SHIM_DIR"); d != "" {
		return d
	}
	if len(os.Args) > 0 && strings.Contains(os.Args[0], string(os.PathSeparator)) {
		return filepath.Dir(os.Args[0])
	}
	return ""
}

func sealShellEnv(env []string, shimDir string, host map[string]string) []string {
	out := append([]string{}, env...)
	if shimDir != "" {
		out = prefixPath(out, shimDir)
	}
	have := map[string]bool{}
	for _, e := range out {
		k, _, ok := strings.Cut(e, "=")
		if ok {
			have[k] = true
		}
	}
	for k, v := range host {
		if !spotterKey(k) || have[k] {
			continue
		}
		out = append(out, k+"="+v)
		have[k] = true
	}
	return out
}

func spotterKey(k string) bool {
	return strings.HasPrefix(k, "SPOTTER_SH_") || strings.HasPrefix(k, "SHELLSPOTTER_")
}

func prefixPath(env []string, dir string) []string {
	sep := string(os.PathListSeparator)
	for i, e := range env {
		if !strings.HasPrefix(e, "PATH=") {
			continue
		}
		path := strings.TrimPrefix(e, "PATH=")
		first := path
		if j := strings.IndexByte(path, os.PathListSeparator); j >= 0 {
			first = path[:j]
		}
		if first == dir {
			return env
		}
		env[i] = "PATH=" + dir + sep + path
		return env
	}
	return append(env, "PATH="+dir)
}
