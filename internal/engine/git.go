// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"context"
	"errors"
	"strings"
	"time"
)

func (in Input) decideGit(argv []string) Outcome {
	args, cwd := stripGitGlobals(argv, in.Cwd)
	if cwd != in.Cwd {
		in.Cwd = cwd
	}
	if len(args) < 2 {
		return allow()
	}
	sub := args[1]
	rest := args[2:]
	switch sub {
	case "reset":
		if hasWord(rest, "--hard") {
			return in.gitDirty("git reset --hard", "discards uncommitted work", "commit or stash first")
		}
	case "checkout":
		if hasCheckoutDiscard(rest) {
			return in.gitDirty("git checkout --", "discards local changes", "stash the files you want to keep")
		}
	case "restore":
		if len(operandWords(rest)) > 0 || hasWord(rest, ".") {
			return in.gitDirty("git restore", "discards local changes", "stash first")
		}
	case "clean":
		if cleanDestructive(rest) {
			return in.gitDirty("git clean", "removes untracked files", "run git clean -n first")
		}
	case "stash":
		if len(rest) > 0 && (rest[0] == "drop" || rest[0] == "clear") {
			n := in.stashCount()
			if n < 0 {
				return in.timeoutCatch("git stash", 0)
			}
			if n > 0 {
				o := in.danger("F", "git stash "+rest[0], "drops "+itoa(n)+" stash entries", "stash drop is easy to mistype", "keep the stash or pop it", nil, "git stash")
				o.Affected.Count = n
				return o
			}
		}
	case "push":
		return in.gitPush(rest)
	case "branch":
		if hasShortGit(rest, 'D') || hasWord(rest, "-D") {
			return in.danger("F", "git branch -D", "deletes a branch without merge checks", " -D does not check whether the branch is merged", "use -d, or name the exact branch after reading git branch", nil, "git branch -D")
		}
	case "filter-repo":
		return in.danger("F", "git filter-repo", "rewrites repository history", "filter-repo is hard to undo", "do it on a fresh clone", nil, "git filter-repo")
	}
	return allow()
}

func (in Input) gitPush(rest []string) Outcome {
	force := false
	lease := false
	mirror := false
	deleteRef := false
	for _, w := range rest {
		switch {
		case w == "--force" || w == "-f" || w == "--force-with-lease=false":
			force = true
		case w == "--force-with-lease" || strings.HasPrefix(w, "--force-with-lease="):
			lease = true
		case w == "--mirror":
			mirror = true
		case strings.HasPrefix(w, ":"):
			deleteRef = true
		}
	}
	if mirror || deleteRef {
		return in.danger("F", "git push", "deletes or mirrors refs on the remote", "a refspec starting with ':' deletes the remote branch", "push an ordinary branch name", nil, "git push")
	}
	if force && !lease {
		return in.danger("F", "git push --force", "overwrites remote history", "--force drops commits other people may have", "use --force-with-lease", nil, "git push")
	}
	return allow()
}

func (in Input) gitDirty(op, consequence, safer string) Outcome {
	out, err := in.gitStatus()
	if err != nil {
		if isTimeout(err) {
			return in.timeoutCatch(op, 0)
		}
		if errors.Is(err, errDrop) {
			return Outcome{Action: "fail", Exit: 122, Message: "Shell Spotter failed; command not run; see log; a human can run it by hand or fix the spotter"}
		}
		// not a repository, or git missing: unclassifiable
		o := allow()
		o.LogNote = "git_status_error"
		return o
	}
	lines := nonEmpty(strings.Split(out, "\n"))
	if len(lines) == 0 {
		return allow()
	}
	top := lines
	if len(top) > 20 {
		top = top[:20]
	}
	o := in.danger("F", op, consequence, "the work tree is not clean", safer, nil, op)
	o.Affected.Count = len(lines)
	o.Affected.Top = top
	o.Affected.Protected = false
	return o
}

func (in Input) gitStatus() (string, error) {
	if in.GitStatus != nil {
		return in.GitStatus(in.Cwd)
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout(in.Config.ProbeTimeout))
	defer cancel()
	return runProbe(ctx, in.Cwd, "git", "status", "--porcelain")
}

func (in Input) stashCount() int {
	if in.StashN != nil {
		n, err := in.StashN(in.Cwd)
		if err != nil {
			return -1
		}
		return n
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout(in.Config.ProbeTimeout))
	defer cancel()
	out, err := runProbe(ctx, in.Cwd, "git", "stash", "list")
	if err != nil {
		if isTimeout(err) || errors.Is(err, errDrop) {
			return -1
		}
		return 0
	}
	return len(nonEmpty(strings.Split(out, "\n")))
}

func (in Input) timeoutCatch(op string, partial int) Outcome {
	o := in.danger("F", op, "the check timed out", "a long scan likely means a very large target", "narrow the command or retry", nil, op)
	o.Level = "danger"
	o.Affected.TimedOut = true
	o.Affected.Partial = partial
	o.Affected.Protected = false
	return o
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "context deadline") || strings.Contains(s, "signal: killed")
}

func stripGitGlobals(argv []string, cwd string) ([]string, string) {
	if len(argv) < 2 {
		return argv, cwd
	}
	out := []string{argv[0]}
	args := argv[1:]
	for len(args) > 0 {
		w := args[0]
		switch {
		case w == "-C" && len(args) > 1:
			cwd = args[1]
			args = args[2:]
		case strings.HasPrefix(w, "-C"):
			cwd = strings.TrimPrefix(w, "-C")
			args = args[1:]
		case w == "--git-dir" || w == "--work-tree" || w == "-c" || w == "--namespace":
			if len(args) > 1 {
				args = args[2:]
			} else {
				args = args[1:]
			}
		case strings.HasPrefix(w, "--git-dir=") || strings.HasPrefix(w, "--work-tree=") || strings.HasPrefix(w, "-c"):
			args = args[1:]
		case w == "--bare" || w == "--no-pager" || w == "-p" || w == "--paginate":
			args = args[1:]
		default:
			out = append(out, args...)
			return out, cwd
		}
	}
	return out, cwd
}

func hasCheckoutDiscard(rest []string) bool {
	for i, w := range rest {
		if w == "--" {
			return i+1 < len(rest)
		}
	}
	// git checkout -- .  already handled. git checkout . is also a discard.
	for _, w := range rest {
		if w == "." || w == "./" {
			return true
		}
	}
	return false
}

func cleanDestructive(rest []string) bool {
	joined := ""
	force := false
	for _, w := range rest {
		if strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--") {
			joined += w[1:]
		}
		if w == "--force" {
			force = true
		}
	}
	if strings.Contains(joined, "f") {
		force = true
	}
	// git clean -f removes untracked files. -fd and -fx do too.
	// A clean tree is still allowed; gitDirty checks porcelain.
	return force
}

func hasShortGit(rest []string, c byte) bool {
	for _, w := range rest {
		if strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--") && strings.ContainsRune(w, rune(c)) {
			return true
		}
	}
	return false
}

func hasWord(rest []string, w string) bool {
	for _, x := range rest {
		if x == w {
			return true
		}
	}
	return false
}

func operandWords(rest []string) []string {
	var out []string
	for _, w := range rest {
		if strings.HasPrefix(w, "-") {
			continue
		}
		out = append(out, w)
	}
	return out
}

func nonEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// silence unused in case probe helper needs the time import via context only
var _ = time.Second
