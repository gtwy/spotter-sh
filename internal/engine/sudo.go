// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"strings"

	"github.com/gtwy/spotter-sh/internal/precheck"
)

func decideSudo(in Input, name string) Outcome {
	// sudo -u and doas with no command start a shell the shim does not wrap.
	if kind, _, _ := precheck.PeekLaunch(in.Argv, string(in.StdinPeek)); kind == precheck.LaunchOpaque {
		o := in.danger("F", "deferred", "a launcher runs a command this check cannot see", "the payload is not in the command", "pass the command where it can be read", nil, "deferred")
		o.Approve = true
		return in.render(o, in.Argv)
	}
	inner := sudoInner(name, in.Argv)
	if len(inner) == 0 {
		o := fallthroughAllow()
		o.LogNote = "parse_fallthrough"
		return in.render(o, in.Argv)
	}
	b := base(inner[0])
	// Documented limit: sudo bash -c is only scanned for hard blocks.
	if b == "bash" || b == "sh" || b == "dash" || b == "zsh" {
		if script, ok := inlineC(inner); ok {
			if o, hit := hardBlockText(script); hit {
				return in.render(o, in.Argv)
			}
		}
		o := fallthroughAllow()
		o.LogNote = "sudo_shell_limit"
		return in.render(o, in.Argv)
	}
	// xargs rm under sudo does not reach the rm shim when secure_path drops shims.
	if b == "xargs" {
		if xargsRM(inner) {
			return in.render(in.danger("A", "sudo xargs rm", "sudo would run rm without the shim", "secure_path drops the shim directory", "run rm directly so the spotter can see each target", nil, "xargs rm"), in.Argv)
		}
	}
	in.Argv = inner
	return Decide(in)
}

func sudoInner(name string, argv []string) []string {
	args := argv[1:]
	i := 0
	for i < len(args) {
		w := args[i]
		if w == "--" {
			return args[i+1:]
		}
		if isAssignWord(w) {
			i++
			continue
		}
		if !strings.HasPrefix(w, "-") {
			return args[i:]
		}
		if name == "sudo" && (w == "-i" || w == "-s" || w == "-e" || w == "--login" || w == "--shell" || w == "--edit") {
			// login/edit forms: no ordinary inner command
			if w == "-e" || w == "--edit" {
				return nil
			}
			return nil
		}
		if takes := sudoFlagTakes(w); takes && i+1 < len(args) && !strings.Contains(w, "=") {
			i += 2
			continue
		}
		i++
	}
	return nil
}

func sudoFlagTakes(w string) bool {
	switch strings.TrimLeft(w, "-") {
	case "u", "g", "p", "C", "D", "h", "U", "T", "r", "t", "R", "user", "group", "prompt", "role", "type", "chdir":
		return true
	default:
		return false
	}
}

func inlineC(argv []string) (string, bool) {
	for i := 1; i < len(argv); i++ {
		w := argv[i]
		if w == "-c" && i+1 < len(argv) {
			return argv[i+1], true
		}
		if strings.HasPrefix(w, "-") && strings.Contains(strings.TrimLeft(w, "-"), "c") && !strings.HasPrefix(w, "--") && i+1 < len(argv) {
			return argv[i+1], true
		}
	}
	return "", false
}

func xargsRM(argv []string) bool {
	for _, w := range argv[1:] {
		if base(w) == "rm" {
			return true
		}
	}
	return false
}

func isAssignWord(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	for _, r := range w[:eq] {
		if r != '_' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}
