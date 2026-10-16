// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package precheck

import (
	"strings"
)

// pipeSelfBomb is a backgrounded pipeline whose stages are the same
// shell builtin or no-op. `:|:&` and `true|true&` are that shape, including
// inside a subshell or an invoked function. A definition that is never
// called does not run, so it is not a bomb. A different command on each
// side, or a pipeline that is not backgrounded, is not this.
func pipeSelfBomb(s string) bool {
	plain := hideQuotes(dropHereBodies(stripComments(s)))
	visible := blankBodies(plain)
	// An if runs a branch immediately. A while whose condition is false does not,
	// so that body stays on the loop check and is not scanned here.
	if selfPipeBg(visible) || ifPipeBomb(visible) {
		return true
	}
	defined := map[string]string{}
	i := 0
	for i < len(plain) {
		name, body, next, ok := nextFunc(plain, i)
		if !ok {
			break
		}
		defined[name] = body
		if next <= i {
			break
		}
		i = next
	}
	for name, body := range defined {
		if invoked(name, visible) && (selfPipeBg(body) || ifPipeBomb(body)) {
			return true
		}
	}
	return false
}

func selfPipeBg(s string) bool {
	toks := opTokens(s)
	for i := 0; i < len(toks); {
		if sepToken(toks[i]) {
			i++
			continue
		}
		name, j, ok := stageCmd(toks, i)
		if !ok {
			i++
			continue
		}
		if !trivialBuiltin(name) || j >= len(toks) || (toks[j] != "|" && toks[j] != "|&") {
			i = j
			continue
		}
		same := true
		for j < len(toks) && (toks[j] == "|" || toks[j] == "|&") {
			n2, j2, ok2 := stageCmd(toks, j+1)
			if !ok2 || n2 != name || !trivialBuiltin(n2) {
				same = false
				if j2 > j {
					j = j2
				} else {
					j++
				}
				break
			}
			j = j2
		}
		if same && j < len(toks) && toks[j] == "&" {
			return true
		}
		if j <= i {
			i++
			continue
		}
		i = j
	}
	return false
}

func stageCmd(toks []string, i int) (string, int, bool) {
	if i < 0 || i >= len(toks) || sepToken(toks[i]) {
		return "", i, false
	}
	j := i
	for j < len(toks) && (toks[j] == "{" || toks[j] == "}") {
		j++
	}
	for j < len(toks) && (toks[j] == "command" || toks[j] == "builtin") {
		j++
		for j < len(toks) && strings.HasPrefix(toks[j], "-") && !sepToken(toks[j]) {
			j++
		}
	}
	if j >= len(toks) || sepToken(toks[j]) {
		return "", i, false
	}
	name := strings.Trim(toks[j], `"'`)
	j++
	for j < len(toks) && !sepToken(toks[j]) {
		j++
	}
	return name, j, name != ""
}

func sepToken(t string) bool {
	switch t {
	case "|", "&", "|&", "&&", "||", ";":
		return true
	default:
		return false
	}
}

func trivialBuiltin(name string) bool {
	switch name {
	case ":", "true", "false", "[", "test",
		"echo", "printf", "pwd", "times", "wait", "shift", "exit", "return",
		"builtin", "command", "eval", "exec", "umask", "ulimit", "hash",
		"type", "help", "alias", "unalias", "set", "unset", "export",
		"readonly", "local", "declare", "typeset", "let", "jobs", "fg", "bg",
		"disown", "enable", "shopt", "caller", "getopts", "read", "mapfile",
		"readarray", "pushd", "popd", "dirs", "fc", "history", "bind",
		"complete", "compgen", "compopt", "logout", "suspend":
		return true
	default:
		return false
	}
}

// Launch kinds. LaunchNone means this argv is not a deferred launcher.
const (
	LaunchNone = iota
	LaunchArgv
	LaunchScript
	LaunchOpaque
)

// PeekLaunch splits a launcher into the command it will run.
// stdin is a script already visible to the caller (a here-document, a
// here-string, a pipe, or a peeked file). An argv launcher returns the
// inner argv. A -c or stdin launcher returns the script text. A scheduler
// with nothing to read returns LaunchOpaque.
func PeekLaunch(words []string, stdin string) (kind int, rest []string, script string) {
	return peekLaunch(words, stdin, nil, "", "")
}

func peekLaunch(words []string, stdin string, bodies map[string]string, cwd, home string) (kind int, rest []string, script string) {
	name, i, ok := launchWord(words)
	if !ok {
		return LaunchNone, nil, ""
	}
	args := words[i+1:]
	switch name {
	case "timeout", "nice", "ionice", "stdbuf", "setsid", "nohup", "watch", "chrt", "taskset", "cpulimit", "nsenter", "unshare", "chroot", "ssh-agent", "dbus-launch", "tmux", "screen", "systemd-run", "flock":
		return argvLaunch(name, words, i)
	case "script":
		if s, ok := cString(name, args); ok {
			return LaunchScript, nil, s
		}
		return LaunchNone, nil, ""
	case "su", "runuser":
		return userLaunch(name, words, i)
	case "sudo":
		return sudoLaunch(words, i)
	case "doas":
		return doasLaunch(words, i)
	case "pkexec":
		return pkexecLaunch(words, i)
	case "machinectl":
		return machineLaunch(words, i)
	case "at", "batch":
		return schedScript(name, args, stdin, bodies, cwd, home)
	case "crontab":
		return cronLaunch(args, stdin, bodies, cwd, home)
	default:
		return LaunchNone, nil, ""
	}
}

func launchWord(words []string) (string, int, bool) {
	i := 0
	for i < len(words) && isAssign(trimWord(words[i])) {
		i++
	}
	if i >= len(words) {
		return "", i, false
	}
	return base(trimWord(words[i])), i, true
}

func argvLaunch(name string, words []string, at int) (int, []string, string) {
	i := at + 1
	switch name {
	case "timeout":
		i = skipTimeout(words, i)
	case "nice":
		i = skipOpts(words, i, map[string]bool{"-n": true, "--adjustment": true})
	case "ionice":
		i = skipOpts(words, i, map[string]bool{"-c": true, "-n": true, "-p": true, "-t": true})
	case "stdbuf":
		i = skipOpts(words, i, map[string]bool{"-i": true, "-o": true, "-e": true, "--input": true, "--output": true, "--error": true})
	case "setsid", "nohup":
		i = skipOpts(words, i, nil)
	case "watch":
		i = skipOpts(words, i, map[string]bool{"-n": true, "--interval": true, "-e": true, "--errexit": true})
	case "flock":
		if s, ok := flockScript(words[i:]); ok {
			return LaunchScript, nil, s
		}
		i = skipFlock(words, i)
	case "chrt":
		if optSeen(words[i:], "-p", "--pid") {
			return LaunchNone, nil, ""
		}
		i = skipOpts(words, i, nil)
		if i < len(words) && !isOpt(trimWord(words[i])) {
			i++ // priority
		}
	case "taskset":
		if optSeen(words[i:], "-p", "--pid") {
			return LaunchNone, nil, ""
		}
		i = skipOpts(words, i, map[string]bool{"-c": true, "--cpu-list": true})
		// Without -c the next word is the affinity mask.
		if !optSeen(words[at+1:i], "-c", "--cpu-list") && i < len(words) && !isOpt(trimWord(words[i])) {
			i++
		}
	case "cpulimit":
		if optSeen(words[i:], "-p", "--pid") && !hasCommandAfter(words, i, map[string]bool{"-l": true, "--limit": true, "-p": true, "--pid": true, "-P": true, "--path": true, "-z": true, "--lazy": true}) {
			return LaunchNone, nil, ""
		}
		i = skipOpts(words, i, map[string]bool{"-l": true, "--limit": true, "-p": true, "--pid": true, "-P": true, "--path": true, "-z": true, "--lazy": true})
	case "nsenter":
		i = skipOpts(words, i, map[string]bool{"-t": true, "--target": true, "-S": true, "--setuid": true, "-G": true, "--setgid": true, "-r": true, "--root": true, "-w": true, "--wd": true})
	case "unshare":
		i = skipOpts(words, i, map[string]bool{"--root": true, "--wd": true, "--setuid": true, "--setgid": true, "--map-user": true, "--map-group": true, "--map-users": true, "--map-groups": true, "--propagation": true, "-R": true})
	case "chroot":
		i = skipOpts(words, i, map[string]bool{"--userspec": true, "--groups": true})
		if i < len(words) && !isOpt(trimWord(words[i])) {
			i++ // new root
		}
	case "ssh-agent":
		i = skipOpts(words, i, map[string]bool{"-a": true, "-t": true})
	case "dbus-launch":
		i = skipOpts(words, i, map[string]bool{"--config-file": true})
	case "tmux":
		next, ok := tmuxCommand(words[i:])
		if !ok {
			return LaunchNone, nil, ""
		}
		i += next
	case "screen":
		next, ok := screenCommand(words[i:])
		if !ok {
			return LaunchNone, nil, ""
		}
		i += next
	case "systemd-run":
		i = skipOpts(words, i, systemdTakes())
	}
	if i >= len(words) {
		if sawInfo(words[at+1:]) {
			return LaunchNone, nil, ""
		}
		// These replace the process (user, namespace, root, or systemd).
		// With no command, the shell they start is not visible to the shim.
		if name == "nsenter" || name == "chroot" || name == "systemd-run" {
			return LaunchOpaque, nil, ""
		}
		return LaunchNone, nil, ""
	}
	return LaunchArgv, words[i:], ""
}

// userLaunch is su or runuser. -c is a script. runuser -u executes the
// remaining argv, including the words after --. Anything else starts a
// shell whose command this check cannot see.
func userLaunch(name string, words []string, at int) (int, []string, string) {
	args := words[at+1:]
	if s, ok := cString(name, args); ok {
		return LaunchScript, nil, s
	}
	takes := map[string]bool{
		"-u": true, "--user": true,
		"-g": true, "--group": true,
		"-G": true, "--supp-group": true,
		"-s": true, "--shell": true,
		"-w": true, "--whitelist-environment": true,
	}
	i := skipOpts(words, at+1, takes)
	if sawInfo(args) && i >= len(words) {
		return LaunchNone, nil, ""
	}
	if name == "runuser" && optSeen(args, "-u", "--user") {
		if i >= len(words) {
			return LaunchOpaque, nil, ""
		}
		return LaunchArgv, words[i:], ""
	}
	// su, and runuser without -u, pass extra words to a login shell.
	return LaunchOpaque, nil, ""
}

// sudoLaunch judges sudo -u. Plain sudo is unwrapped by the caller.
// -u with no command is a root shell the shim does not see.
func sudoLaunch(words []string, at int) (int, []string, string) {
	args := words[at+1:]
	i := skipOpts(words, at+1, map[string]bool{
		"-u": true, "--user": true,
		"-g": true, "--group": true,
		"-p": true, "--prompt": true,
		"-C": true, "-D": true, "-U": true, "-T": true,
		"-r": true, "-t": true, "-R": true,
	})
	if i < len(words) && trimWord(words[i]) == "-" {
		i++
	}
	userChange := optSeen(args, "-u", "--user")
	if i >= len(words) {
		if sawInfo(args) || !userChange {
			return LaunchNone, nil, ""
		}
		return LaunchOpaque, nil, ""
	}
	if !userChange {
		return LaunchNone, nil, ""
	}
	return LaunchArgv, words[i:], ""
}

func doasLaunch(words []string, at int) (int, []string, string) {
	args := words[at+1:]
	i := skipOpts(words, at+1, map[string]bool{"-u": true, "-a": true, "-C": true})
	if i >= len(words) {
		if sawInfo(args) {
			return LaunchNone, nil, ""
		}
		return LaunchOpaque, nil, ""
	}
	return LaunchArgv, words[i:], ""
}

func pkexecLaunch(words []string, at int) (int, []string, string) {
	args := words[at+1:]
	i := skipOpts(words, at+1, map[string]bool{"--user": true, "-u": true})
	if i >= len(words) {
		if sawInfo(args) {
			return LaunchNone, nil, ""
		}
		return LaunchOpaque, nil, ""
	}
	return LaunchArgv, words[i:], ""
}

// machineLaunch is `machinectl shell`. Other verbs are not a user handoff.
// One machine name and no command starts a shell. A following argv is the payload.
func machineLaunch(words []string, at int) (int, []string, string) {
	args := words[at+1:]
	i := skipOpts(words, at+1, map[string]bool{"-H": true, "--host": true, "-M": true, "--machine": true})
	if i >= len(words) || trimWord(words[i]) != "shell" {
		return LaunchNone, nil, ""
	}
	i++
	i = skipOpts(words, i, map[string]bool{"--uid": true, "-E": true, "--setenv": true})
	if i >= len(words) {
		if sawInfo(args) {
			return LaunchNone, nil, ""
		}
		return LaunchOpaque, nil, ""
	}
	w := trimWord(words[i])
	next := ""
	if i+1 < len(words) {
		next = trimWord(words[i+1])
	}
	if machineName(w, next, i+1 < len(words)) {
		i++
		if i >= len(words) {
			if sawInfo(args) {
				return LaunchNone, nil, ""
			}
			return LaunchOpaque, nil, ""
		}
	}
	return LaunchArgv, words[i:], ""
}

// machineName is the container in `machinectl shell`. A following flag means
// the word is the command (`rm -rf`), not a container. A path is a command.
func machineName(w, next string, hasNext bool) bool {
	if w == "" || strings.HasPrefix(w, "/") {
		return false
	}
	if strings.Contains(w, "@") || strings.HasPrefix(w, ".") {
		return true
	}
	if !hasNext {
		return true
	}
	if strings.HasPrefix(next, "-") {
		return false
	}
	return true
}

func sawInfo(args []string) bool {
	for _, w := range args {
		switch trimWord(w) {
		case "--help", "--version", "--usage", "-h", "-V", "--help-all":
			return true
		}
	}
	return false
}

func schedScript(name string, args []string, stdin string, bodies map[string]string, cwd, home string) (int, []string, string) {
	if name == "at" && atQuery(args) {
		return LaunchNone, nil, ""
	}
	if sawInfo(args) && !schedHasPayload(args, stdin) {
		return LaunchNone, nil, ""
	}
	if path, ok := optPath(args, "-f", "--file"); ok {
		if body, found := bodies[scriptKey(path, cwd, home)]; found && strings.TrimSpace(body) != "" {
			return LaunchScript, nil, body
		}
		return LaunchOpaque, nil, ""
	}
	if strings.TrimSpace(stdin) != "" {
		return LaunchScript, nil, stdin
	}
	return LaunchOpaque, nil, ""
}

func cronLaunch(args []string, stdin string, bodies map[string]string, cwd, home string) (int, []string, string) {
	path, stdinMode, query := cronMode(args)
	if query && !stdinMode && path == "" {
		return LaunchNone, nil, ""
	}
	if path != "" {
		if body, found := bodies[scriptKey(path, cwd, home)]; found {
			text := cronCommands(body)
			if strings.TrimSpace(text) == "" {
				return LaunchNone, nil, ""
			}
			return LaunchScript, nil, text
		}
		return LaunchOpaque, nil, ""
	}
	if !stdinMode {
		return LaunchNone, nil, ""
	}
	if strings.TrimSpace(stdin) == "" {
		return LaunchOpaque, nil, ""
	}
	text := cronCommands(stdin)
	if strings.TrimSpace(text) == "" {
		return LaunchNone, nil, ""
	}
	return LaunchScript, nil, text
}

func cronMode(args []string) (path string, stdin, query bool) {
	for i := 0; i < len(args); i++ {
		w := trimWord(args[i])
		switch w {
		case "-u", "-n":
			i++
			continue
		case "-l", "-r", "-e", "-i", "--list", "--remove", "--edit":
			query = true
			continue
		case "-":
			stdin = true
		default:
			if strings.HasPrefix(w, "-") {
				continue
			}
			if path == "" {
				path = w
			}
		}
	}
	return path, stdin, query
}

// schedHasPayload is a time word, a -f file, or stdin. Help and version
// flags are not a payload.
func schedHasPayload(args []string, stdin string) bool {
	if strings.TrimSpace(stdin) != "" {
		return true
	}
	takes := map[string]bool{"-f": true, "--file": true, "-q": true, "--queue": true, "-t": true}
	for i := 0; i < len(args); i++ {
		w := trimWord(args[i])
		if w == "--" {
			return i+1 < len(args)
		}
		if takes[w] {
			return true
		}
		if strings.HasPrefix(w, "--file=") || strings.HasPrefix(w, "--queue=") {
			return true
		}
		if isOpt(w) {
			continue
		}
		return true
	}
	return false
}

func atQuery(args []string) bool {
	for _, w := range args {
		switch trimWord(w) {
		case "-l", "-d", "-r", "-c", "--list", "--delete", "--cat":
			return true
		}
	}
	return false
}

func optPath(args []string, flag, long string) (string, bool) {
	for i := 0; i < len(args); i++ {
		w := trimWord(args[i])
		if w == flag || w == long {
			if i+1 < len(args) {
				return trimWord(args[i+1]), true
			}
			return "", true
		}
		if strings.HasPrefix(w, long+"=") {
			return strings.TrimPrefix(w, long+"="), true
		}
	}
	return "", false
}

// cronCommands turns a crontab into the shell commands it would run.
// A line that is not a crontab line is kept, so a raw payload is still judged.
func cronCommands(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if cmd, ok := cronCommand(line); ok {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(cmd)
		}
	}
	return b.String()
}

func cronCommand(line string) (string, bool) {
	if i := strings.IndexByte(line, '%'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", false
	}
	if strings.Contains(fields[0], "=") && !strings.HasPrefix(fields[0], "@") {
		return "", true
	}
	if strings.HasPrefix(fields[0], "@") {
		if len(fields) < 2 {
			return "", true
		}
		return strings.Join(fields[1:], " "), true
	}
	if len(fields) >= 6 && cronTime(fields[0]) && cronTime(fields[1]) && cronTime(fields[2]) && cronTime(fields[3]) && cronTime(fields[4]) {
		return strings.Join(fields[5:], " "), true
	}
	return line, true
}

func cronTime(f string) bool {
	if f == "" {
		return false
	}
	for _, c := range f {
		switch {
		case c == '*' || c == '-' || c == ',' || c == '/':
		case c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

func cString(name string, args []string) (string, bool) {
	flags := []string{"-c", "--command"}
	if name == "script" {
		flags = []string{"-c", "--command"}
	}
	for i := 0; i < len(args); i++ {
		w := trimWord(args[i])
		for _, f := range flags {
			if w == f && i+1 < len(args) {
				return trimWord(args[i+1]), true
			}
			if strings.HasPrefix(w, f+"=") {
				return strings.TrimPrefix(w, f+"="), true
			}
		}
	}
	return "", false
}

func flockScript(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		w := trimWord(args[i])
		if w == "-c" || w == "--command" {
			if i+1 < len(args) {
				return trimWord(args[i+1]), true
			}
		}
		if strings.HasPrefix(w, "--command=") {
			return strings.TrimPrefix(w, "--command="), true
		}
	}
	return "", false
}

func optSeen(args []string, names ...string) bool {
	for _, w := range args {
		w = trimWord(w)
		if w == "--" {
			return false
		}
		for _, n := range names {
			if w == n || strings.HasPrefix(w, n+"=") {
				return true
			}
		}
		if !isOpt(w) {
			return false
		}
	}
	return false
}

func hasCommandAfter(words []string, i int, takes map[string]bool) bool {
	j := skipOpts(words, i, takes)
	return j < len(words)
}

func systemdTakes() map[string]bool {
	return map[string]bool{
		"-p": true, "--property": true,
		"-E": true, "--setenv": true,
		"-H": true, "--host": true,
		"-M": true, "--machine": true,
		"--uid": true, "--gid": true,
		"--working-directory": true,
		"--unit":              true, "--description": true, "--slice": true,
		"--service-type": true,
		"--on-active":    true, "--on-boot": true, "--on-startup": true,
		"--on-unit-active": true, "--on-unit-inactive": true, "--on-calendar": true,
		"--timer-property": true, "--path-property": true, "--socket-property": true,
	}
}

func tmuxCommand(args []string) (int, bool) {
	// The returned index is relative to args, which starts after tmux.
	i := skipOpts(args, 0, map[string]bool{"-L": true, "-S": true, "-f": true})
	if i >= len(args) {
		return 0, false
	}
	sub := trimWord(args[i])
	switch sub {
	case "new", "new-session", "new-window", "neww", "split-window", "splitw":
	default:
		return 0, false
	}
	i++
	i = skipOpts(args, i, map[string]bool{
		"-s": true, "-n": true, "-c": true, "-t": true, "-e": true, "-F": true,
		"-x": true, "-y": true, "-h": true, "--target": true, "--session": true,
	})
	if i >= len(args) {
		return 0, false
	}
	return i, true
}

func screenCommand(args []string) (int, bool) {
	i := 0
	for i < len(args) {
		w := trimWord(args[i])
		if w == "--" {
			i++
			break
		}
		if w == "-ls" || w == "-list" || w == "--version" || w == "-v" {
			return 0, false
		}
		if !isOpt(w) {
			break
		}
		if strings.HasPrefix(w, "--") {
			if strings.Contains(w, "=") {
				i++
				continue
			}
			i++
			continue
		}
		cluster := w[1:]
		i++
		if cluster == "" {
			continue
		}
		last := cluster[len(cluster)-1]
		if last == 'S' || last == 'c' || last == 't' || last == 's' {
			if i < len(args) && !isOpt(trimWord(args[i])) {
				i++
			}
		}
	}
	if i >= len(args) {
		return 0, false
	}
	return i, true
}

func judgeLaunchers(command, cwd, home string, depth int) (Result, bool) {
	cmds := commandWords(command)
	bodies := map[string]string{}
	for _, c := range cmds {
		if c.openSub || c.closeSub {
			continue
		}
		if body, path, ok := knownScriptWrite(c, cwd, home); ok {
			bodies[path] = body
		}
	}
	for i, c := range cmds {
		if c.openSub || c.closeSub || len(c.words) == 0 {
			continue
		}
		stdin := launcherStdin(cmds, i)
		kind, rest, script := peekLaunch(c.words, stdin, bodies, cwd, home)
		switch kind {
		case LaunchOpaque:
			return catchCase("deferred", "a scheduler runs a command this check cannot see"), true
		case LaunchScript:
			if strings.TrimSpace(script) == "" {
				return catchCase("deferred", "a scheduler runs a command this check cannot see"), true
			}
			r := scanAt(script, cwd, home, depth+1)
			if r.Action == "hardblock" || r.Action == "catch" {
				return r, true
			}
		case LaunchArgv:
			// systemd-run starts a unit outside the shim, so the payload is
			// judged here. A home path cannot wait for a tree walk that will
			// not run. Other launchers keep the ordinary argv check.
			if r, ok := judgeSystemd(c.words, rest, cwd, home, depth); ok {
				return r, true
			}
			if r, ok := judgeArgv(rest, cwd, home, depth); ok {
				return r, true
			}
		}
	}
	return Result{}, false
}

func launcherStdin(cmds []scannedCmd, i int) string {
	c := cmds[i]
	if strings.TrimSpace(c.hereBody) != "" {
		return c.hereBody
	}
	if strings.TrimSpace(c.hereArg) != "" {
		return c.hereArg
	}
	if strings.TrimSpace(c.stdinCode) != "" {
		return c.stdinCode
	}
	if i == 0 || cmds[i-1].stop != "|" {
		return ""
	}
	prev := cmds[i-1]
	if strings.TrimSpace(prev.hereBody) != "" && (feedsStdin(prev.words) || pipeProducer(prev.words)) {
		return prev.hereBody
	}
	if s, ok := pipeScript(prev.words); ok {
		return s
	}
	return ""
}

func pipeProducer(words []string) bool {
	name, _, ok := launchWord(words)
	if !ok {
		return false
	}
	switch name {
	case "echo", "printf", "cat", "tee":
		return true
	default:
		return false
	}
}

func judgeArgv(rest []string, cwd, home string, depth int) (Result, bool) {
	if len(rest) == 0 {
		return Result{}, false
	}
	if len(rest) == 1 {
		w := trimWord(rest[0])
		if strings.ContainsAny(w, " \t\n;|&") {
			r := scanAt(w, cwd, home, depth+1)
			if r.Action == "hardblock" || r.Action == "catch" {
				return r, true
			}
			return Result{}, false
		}
	}
	if r, ok := match(rest); ok {
		return r, true
	}
	kind, inner, script := peekLaunch(rest, "", nil, cwd, home)
	switch kind {
	case LaunchOpaque:
		return catchCase("deferred", "a scheduler runs a command this check cannot see"), true
	case LaunchScript:
		if strings.TrimSpace(script) == "" {
			return catchCase("deferred", "a scheduler runs a command this check cannot see"), true
		}
		r := scanAt(script, cwd, home, depth+1)
		if r.Action == "hardblock" || r.Action == "catch" {
			return r, true
		}
	case LaunchArgv:
		if len(inner) == 0 || sameWords(inner, rest) {
			return Result{}, false
		}
		return judgeArgv(inner, cwd, home, depth+1)
	}
	return Result{}, false
}

func sameWords(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if trimWord(a[i]) != trimWord(b[i]) {
			return false
		}
	}
	return true
}

func joinWords(words []string) string {
	parts := make([]string, len(words))
	for i, w := range words {
		parts[i] = trimWord(w)
	}
	return strings.Join(parts, " ")
}

func trimWord(w string) string {
	return strings.TrimPrefix(w, "\x00")
}

func isOpt(w string) bool {
	return w != "-" && strings.HasPrefix(w, "-")
}

func skipOpts(words []string, i int, takes map[string]bool) int {
	for i < len(words) {
		w := trimWord(words[i])
		if w == "--" {
			return i + 1
		}
		if !isOpt(w) {
			return i
		}
		if strings.HasPrefix(w, "--") && strings.Contains(w, "=") {
			i++
			continue
		}
		if takes[w] {
			i += 2
			continue
		}
		i++
	}
	return i
}

func skipTimeout(words []string, i int) int {
	i = skipOpts(words, i, map[string]bool{
		"-k": true, "--kill-after": true,
		"-s": true, "--signal": true,
	})
	if i < len(words) && !isOpt(trimWord(words[i])) {
		i++ // duration
	}
	return i
}

func skipFlock(words []string, i int) int {
	takes := map[string]bool{
		"-w": true, "--timeout": true,
		"-E": true, "--conflict-exit-code": true,
		"-F": true,
	}
	for i < len(words) {
		w := trimWord(words[i])
		if w == "--" {
			return i + 1
		}
		if w == "-c" || w == "--command" || strings.HasPrefix(w, "--command=") {
			return i
		}
		if takes[w] {
			i += 2
			continue
		}
		if isOpt(w) {
			i++
			continue
		}
		break
	}
	if i < len(words) {
		i++ // lock path
	}
	return i
}
