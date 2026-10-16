// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gtwy/spotter-sh/internal/precheck"
)

// AdapterResult is a pre-check mapped onto a host hook.
type AdapterResult struct {
	Decision string // allow, ask, deny
	Reason   string
	Exit     int
	Body     string
}

// Precheck runs Layer 1. The command text is not rewritten.
func Precheck(command string) (action string, exitCode int, message string) {
	r := precheck.Scan(command)
	return r.Action, r.Exit, r.Message
}

// PrecheckAt resolves ~, $PWD, and cd from the shell at cwd.
// approve is set when a hard block is a text heuristic an admin may override.
func PrecheckAt(command, cwd, home string) (action string, exitCode int, message string, approve bool) {
	r := precheck.ScanAt(command, cwd, home)
	return r.Action, r.Exit, r.Message, r.Approve
}

// Adapt runs Layer 1 and renders the host's hook shape.
// The command text is never rewritten.
func Adapt(kind, command string) AdapterResult {
	r := precheck.Scan(command)
	dec := "allow"
	exit := 0
	switch r.Action {
	case "hardblock":
		dec = "deny"
		exit = 121
	case "catch":
		dec = "ask"
		exit = 120
	}
	reason := r.Message
	switch kind {
	case "claude":
		// exit 2 blocks. allow stays 0.
		body := map[string]string{"permissionDecision": dec, "reason": reason}
		buf, _ := json.Marshal(body)
		ex := 0
		if dec == "deny" {
			ex = 2
		}
		return AdapterResult{Decision: dec, Reason: reason, Exit: ex, Body: string(buf)}
	case "cursor":
		body := map[string]string{"permission": dec, "agent_message": reason}
		buf, _ := json.Marshal(body)
		ex := 0
		if dec == "deny" {
			ex = 2
		}
		return AdapterResult{Decision: dec, Reason: reason, Exit: ex, Body: string(buf)}
	case "codex":
		body := map[string]string{"decision": dec, "reason": reason}
		buf, _ := json.Marshal(body)
		return AdapterResult{Decision: dec, Reason: reason, Exit: 0, Body: string(buf)}
	default:
		if dec == "ask" {
			exit = 123
		}
		return AdapterResult{Decision: dec, Reason: reason, Exit: exit, Body: reason}
	}
}

// WriteAdapter prints an adapter result. The command is not echoed back as a rewrite.
func WriteAdapter(w io.Writer, kind, command string) int {
	res := Adapt(kind, command)
	if kind == "generic" || kind == "" {
		if res.Body != "" && res.Decision != "allow" {
			fmt.Fprintln(w, res.Body)
		}
		return res.Exit
	}
	fmt.Fprintln(w, res.Body)
	return res.Exit
}

// CommandFromArgs takes the command after -- or joins args.
func CommandFromArgs(args []string) string {
	for i, a := range args {
		if a == "--" {
			return strings.Join(args[i+1:], " ")
		}
	}
	return strings.Join(args, " ")
}

// StdinCommand reads a command when argv is empty.
func StdinCommand() (string, error) {
	buf, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(buf))
	var wrap struct {
		Command string `json:"command"`
	}
	if json.Unmarshal([]byte(s), &wrap) == nil && wrap.Command != "" {
		return wrap.Command, nil
	}
	return s, nil
}
