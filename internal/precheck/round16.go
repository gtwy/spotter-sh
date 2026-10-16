// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package precheck

import (
	"path/filepath"
	"strings"
)

// ifPipeBomb is the self-pipe fork bomb inside an if/elif/else branch.
// A brace group and a called function already run; an if does too. An
// uncalled function is blanked before this sees the text.
func ifPipeBomb(s string) bool {
	for i := 0; i < len(s); {
		if !cmdWord(s, i, "if") {
			i++
			continue
		}
		bodies, next, ok := ifBranches(s, i)
		if !ok || next <= i {
			i++
			continue
		}
		for _, b := range bodies {
			if selfPipeBg(b) || ifPipeBomb(b) {
				return true
			}
		}
		i = next
	}
	return false
}

// ifBranches returns the then, elif, and else bodies. A nested if stays
// inside the outer body so its own fi does not close the outer compound.
func ifBranches(s string, ifAt int) (bodies []string, next int, ok bool) {
	i := ifAt + len("if")
	depth := 0
	inBody := false
	start := 0
	for i < len(s) {
		if cmdWord(s, i, "if") {
			depth++
			i += len("if")
			continue
		}
		if depth > 0 {
			if cmdWord(s, i, "fi") {
				depth--
				i += len("fi")
				continue
			}
			i++
			continue
		}
		switch {
		case cmdWord(s, i, "then"):
			inBody = true
			i += len("then")
			start = i
		case inBody && cmdWord(s, i, "elif"):
			bodies = append(bodies, s[start:i])
			inBody = false
			i += len("elif")
		case inBody && cmdWord(s, i, "else"):
			bodies = append(bodies, s[start:i])
			i += len("else")
			start = i
		case inBody && cmdWord(s, i, "fi"):
			bodies = append(bodies, s[start:i])
			return bodies, i + len("fi"), true
		case !inBody && cmdWord(s, i, "fi"):
			return bodies, i + len("fi"), len(bodies) > 0
		default:
			i++
		}
	}
	return nil, ifAt, false
}

// JudgeSystemd judges a systemd-run payload. The unit does not run under
// the shim. ok is false when argv is not systemd-run, or the payload is
// not a home or root delete.
func JudgeSystemd(argv, payload []string, cwd, home string) (Result, bool) {
	return judgeSystemd(argv, payload, cwd, home, 0)
}

func judgeSystemd(argv, payload []string, cwd, home string, depth int) (Result, bool) {
	name, _, ok := launchWord(argv)
	if !ok || name != "systemd-run" {
		return Result{}, false
	}
	if r, ok := judgeArgv(payload, cwd, home, depth); ok {
		return r, true
	}
	return homeBypassDelete(payload, home)
}

// homeBypassDelete is a recursive rm of the home directory or of a path
// under it. The home directory node stays a hard block. A path under it
// is an approvable catch, because the shim will not walk that tree.
func homeBypassDelete(words []string, home string) (Result, bool) {
	i := commandStart(words)
	if i >= len(words) || base(words[i]) != "rm" {
		return Result{}, false
	}
	rec, ops := rmRecOps(words[i+1:])
	if !rec {
		return Result{}, false
	}
	for _, op := range ops {
		if strings.HasPrefix(op, "\x00") {
			continue
		}
		if homeNodeOperand(op, home) {
			return block("rm-root", "rm -rf of a home directory"), true
		}
		if underHome(op, home) {
			return catchCase("home-delete", "recursive delete of a home path"), true
		}
	}
	return Result{}, false
}

func rmRecOps(rest []string) (bool, []string) {
	rec := false
	var ops []string
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		if w == "--" {
			ops = append(ops, rest[i+1:]...)
			break
		}
		if strings.HasPrefix(w, "--") {
			if w == "--recursive" {
				rec = true
			}
			continue
		}
		if strings.HasPrefix(w, "-") && len(w) > 1 && !strings.HasPrefix(w, "-/") && !strings.HasPrefix(w, "\x00") {
			for _, c := range strings.TrimPrefix(w, "\x00")[1:] {
				if c == 'r' || c == 'R' {
					rec = true
				}
			}
			continue
		}
		ops = append(ops, w)
	}
	return rec, ops
}

func homeNodeOperand(op, home string) bool {
	if strings.HasPrefix(op, "\x00") {
		return false
	}
	op = strings.TrimSpace(op)
	if op == "~/" || exactHomeDir(op) {
		return true
	}
	if home != "" && filepath.IsAbs(op) && filepath.Clean(op) == filepath.Clean(home) {
		return true
	}
	return false
}

func underHome(op, home string) bool {
	if strings.HasPrefix(op, "\x00") || homeNodeOperand(op, home) {
		return false
	}
	op = strings.TrimSpace(op)
	if op == "" {
		return false
	}
	if strings.HasPrefix(op, "~/") || strings.HasPrefix(op, "$HOME/") || strings.HasPrefix(op, "${HOME}/") {
		return true
	}
	if home == "" || !filepath.IsAbs(op) {
		return false
	}
	h := filepath.Clean(home)
	c := filepath.Clean(op)
	return c != h && strings.HasPrefix(c, h+string(filepath.Separator))
}
