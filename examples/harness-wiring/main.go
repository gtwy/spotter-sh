// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command harness-wiring is a minimal example of how an agent harness
// puts Shell Spotter in front of one shell. It is not a product.
//
// Spawn the agent process with the shim directory first on PATH, and
// with the hook socket and the mode sealed by the harness:
//
//	SPOTTER_SH_HOST=1
//	SPOTTER_SH_MODE=silent
//	SPOTTER_SH_HOOK=/run/agent/spotter.sock
//	PATH=<shim-dir>:$PATH
//
// Silent is the default. spotter-sh precheck then exits 0 and only logs.
// After you switch the sealed mode to enforce, precheck exits 120 for an
// approvable catch and 121 for a hard block.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	shimDir := os.Getenv("SPOTTER_SHIM_DIR")
	if shimDir == "" {
		shimDir = os.ExpandEnv("$HOME/.local/lib/spotter-sh/shims")
	}
	fmt.Println(SpawnEnv(shimDir, "/run/agent/spotter.sock", "silent"))
}

// SpawnEnv is the environment for the agent shell only.
// Do not write it into a login profile.
func SpawnEnv(shimDir, hookSocket, mode string) string {
	if mode == "" {
		mode = "silent"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "SPOTTER_SH_HOST=1\n")
	fmt.Fprintf(&b, "SPOTTER_SH_MODE=%s\n", mode)
	fmt.Fprintf(&b, "SPOTTER_SH_HOOK=%s\n", hookSocket)
	fmt.Fprintf(&b, "PATH=%s:$PATH\n", shimDir)
	return b.String()
}

// Gate runs `spotter-sh precheck` on the command text.
// In silent mode the program exits 0. In enforce mode:
// 120 means ask a trusted admin, then rerun the identical command if
// they approve; 121 means do not run it at all.
func Gate(bin, command string, askAdmin func(command string) bool) (run bool, exit int, note string) {
	cmd := exec.Command(bin, "precheck", "--", command)
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	exit = 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			return false, 122, "spotter precheck failed"
		}
	}
	switch exit {
	case 0:
		return true, 0, "allowed, or silent mode logged it"
	case 120:
		if askAdmin == nil || !askAdmin(command) {
			return false, 120, "approvable catch; admin did not approve"
		}
		return true, 120, "admin approved; rerun the identical command"
	case 121:
		return false, 121, "hard block; never run"
	default:
		return false, exit, "spotter failure; command not run"
	}
}

// HookDecision is the one-line reply on SPOTTER_SH_HOOK.
// proceed is sent only after an admin approved that exact command.
// A hard block is cancelled here as well.
func HookDecision(level string, approve bool, adminOK bool) string {
	if level == "hardblock" && !approve {
		return `{"decision":"cancel","reason":"hard block"}`
	}
	if adminOK {
		return `{"decision":"proceed"}`
	}
	return `{"decision":"cancel"}`
}
