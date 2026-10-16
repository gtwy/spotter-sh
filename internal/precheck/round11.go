// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package precheck

import (
	"os"
	"path/filepath"
	"strings"
)

// embeddedSubst judges every command substitution the shell would run
// before the outer command, including one buried in an argument.
// A single-quoted substitution is text. The bytes of a nested script are
// judged by the same rules, not by a pattern for one spelling.
func embeddedSubst(command, cwd, home string, depth int) (Result, bool) {
	if depth > 8 {
		return catchCase("fed-shell", "nested generated shell"), true
	}
	for _, inner := range commandSubsts(command) {
		inner = strings.TrimSpace(inner)
		if inner == "" {
			continue
		}
		r := scanAt(inner, cwd, home, depth+1)
		if r.Action == "hardblock" || r.Action == "catch" {
			return r, true
		}
	}
	return Result{}, false
}

// commandSubsts returns $(...) and backtick bodies the shell would execute.
// Single quotes, comments, and a quoted heredoc are text. An unquoted
// heredoc and a herestring still expand substitutions.
func commandSubsts(s string) []string {
	var out []string
	inS, inD, inHere := false, false, false
	hereDelim, hereStrip := "", false
	take := func(i int) int {
		if strings.HasPrefix(s[i:], "$(") {
			end := skipSubst(s, i)
			if end > i+2 {
				out = append(out, s[i+2:end-1])
			}
			if end > i {
				return end - 1
			}
			return i
		}
		if s[i] != '`' {
			return i
		}
		j := i + 1
		for j < len(s) {
			if s[j] == '\\' && j+1 < len(s) {
				j += 2
				continue
			}
			if s[j] == '`' {
				out = append(out, s[i+1:j])
				return j
			}
			j++
		}
		return i
	}
	for i := 0; i < len(s); i++ {
		if inHere {
			if i == 0 || s[i-1] == '\n' {
				line, next := hereLine(s, i)
				cmp := line
				if hereStrip {
					cmp = strings.TrimLeft(cmp, " \t")
				}
				if cmp == hereDelim {
					inHere = false
					if next > i {
						i = next
					}
					continue
				}
			}
			if strings.HasPrefix(s[i:], "$(") || s[i] == '`' {
				i = take(i)
			}
			continue
		}
		c := s[i]
		switch {
		case inS:
			if c == '\'' {
				inS = false
			}
		case c == '\\' && !inD:
			i++
		case inD && c == '\\' && i+1 < len(s):
			// "\$", "\`", "\\", and "\"" are not the start of a substitution.
			i++
		case c == '\'' && !inD:
			inS = true
		case c == '"':
			inD = !inD
		case c == '#' && !inD && wordStart(s, i):
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case !inD && strings.HasPrefix(s[i:], "<<<"):
			// Consume the operator. The operand is an ordinary word, so a
			// substitution inside it is still judged. The loop adds one.
			i += 2
		case !inD && strings.HasPrefix(s[i:], "<<"):
			body, delim, strip, quoted, ok := openHeredoc(s, i)
			if !ok {
				break
			}
			if quoted {
				i = body
				continue
			}
			inHere = true
			hereDelim = delim
			hereStrip = strip
			if body > i {
				i = body - 1
			}
		case strings.HasPrefix(s[i:], "$(") || c == '`':
			i = take(i)
		}
	}
	return out
}

func hereLine(s string, i int) (line string, next int) {
	end := strings.IndexByte(s[i:], '\n')
	if end < 0 {
		return s[i:], len(s) - 1
	}
	return s[i : i+end], i + end
}

// openHeredoc parses a heredoc that starts at i. body is the index of the
// last byte of a quoted body, or the first byte of an unquoted body.
func openHeredoc(s string, i int) (body int, delim string, strip, quoted, ok bool) {
	if !strings.HasPrefix(s[i:], "<<") || strings.HasPrefix(s[i:], "<<<") {
		return 0, "", false, false, false
	}
	j := i + 2
	if j < len(s) && s[j] == '-' {
		strip = true
		j++
	}
	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	if j >= len(s) {
		return 0, "", false, false, false
	}
	q := byte(0)
	if s[j] == '\'' || s[j] == '"' || s[j] == '\\' {
		quoted = true
		if s[j] != '\\' {
			q = s[j]
		}
		j++
	}
	var d strings.Builder
	for j < len(s) && s[j] != '\n' && (q != 0 || (s[j] != ' ' && s[j] != '\t')) {
		if q != 0 && s[j] == q {
			j++
			break
		}
		if q == 0 && quoted && (s[j] == ' ' || s[j] == '\t') {
			break
		}
		d.WriteByte(s[j])
		j++
	}
	delim = d.String()
	if delim == "" {
		return 0, "", false, false, false
	}
	for j < len(s) && s[j] != '\n' {
		j++
	}
	if j < len(s) && s[j] == '\n' {
		j++
	}
	if !quoted {
		return j, delim, strip, false, true
	}
	for j < len(s) {
		line, next := hereLine(s, j)
		cmp := line
		if strip {
			cmp = strings.TrimLeft(cmp, " \t")
		}
		if cmp == delim {
			return next, delim, strip, true, true
		}
		if next < len(s) && s[next] == '\n' {
			j = next + 1
			continue
		}
		break
	}
	return len(s) - 1, delim, strip, true, true
}

func wordStart(s string, i int) bool {
	if i == 0 {
		return true
	}
	switch s[i-1] {
	case ' ', '\t', '\n', ';', '&', '|', '(':
		return true
	default:
		return false
	}
}

// selfExec is a shell that re-executes itself ($0, $BASH_SOURCE), including
// exec without a background operator, and a script file that does the same.
// The file is read. It is not executed.
func selfExec(command, cwd string) (Result, bool) {
	if relaunchBomb(command) {
		return block("fork bomb", "a shell re-executes itself"), true
	}
	for _, c := range commandWords(command) {
		i := commandStart(c.words)
		if i >= len(c.words) {
			continue
		}
		name := base(c.words[i])
		rest := c.words[i+1:]
		script, ok := inlineScript(name, rest)
		if !ok {
			script, ok = codePayload(name, rest)
		}
		if ok && relaunchBomb(script) {
			return block("fork bomb", "a shell re-executes itself"), true
		}
		if body, ok := launchedScript(cwd, c.words); ok && relaunchBomb(body) {
			return block("fork bomb", "a shell re-executes itself"), true
		}
	}
	return Result{}, false
}

func relaunchBomb(s string) bool {
	toks := shellToks(s)
	n, backed := 0, false
	for i := 0; i < len(toks); i++ {
		if !cmdAt(toks, i) {
			continue
		}
		name := strings.Trim(toks[i], `"'`)
		if selfName(name) {
			n++
			if followedByBg(toks, i) {
				backed = true
			}
			continue
		}
		if !shellWord(name) && name != "exec" {
			continue
		}
		selfArg, bg := false, false
		sawCmd := false
		for j := i + 1; j < len(toks); j++ {
			switch toks[j] {
			case "&":
				bg = true
				j = len(toks)
			case "|", ";", "&&", "||":
				j = len(toks)
			default:
				arg := strings.Trim(toks[j], `"'`)
				if !sawCmd && strings.HasPrefix(arg, "-") && arg != "-" {
					continue
				}
				if !sawCmd {
					sawCmd = true
					if selfName(arg) {
						selfArg = true
					}
				}
			}
		}
		// exec of the script itself replaces the process and runs again.
		// A shell needs the background operator, or two self commands.
		if selfArg && (bg || name == "exec") {
			return true
		}
	}
	return backed || n >= 2
}

// shellToks splits on operators outside quotes. A quoted word stays one token,
// so echo "$0" is not a command named $0.
func shellToks(s string) []string {
	var out []string
	var w strings.Builder
	inS, inD := false, false
	flush := func() {
		if w.Len() == 0 {
			return
		}
		out = append(out, w.String())
		w.Reset()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inS {
			w.WriteByte(c)
			if c == '\'' {
				inS = false
			}
			continue
		}
		if inD {
			w.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				w.WriteByte(s[i])
				continue
			}
			if c == '"' {
				inD = false
			}
			continue
		}
		switch c {
		case '\'':
			inS = true
			w.WriteByte(c)
		case '"':
			inD = true
			w.WriteByte(c)
		case ' ', '\t', '(', ')':
			flush()
		case '\n':
			flush()
			out = append(out, ";")
		case ';':
			flush()
			out = append(out, ";")
		case '|':
			flush()
			if i+1 < len(s) && s[i+1] == '|' {
				out = append(out, "||")
				i++
			} else {
				out = append(out, "|")
			}
		case '&':
			flush()
			if i+1 < len(s) && s[i+1] == '&' {
				out = append(out, "&&")
				i++
			} else {
				out = append(out, "&")
			}
		default:
			w.WriteByte(c)
		}
	}
	flush()
	return out
}

// launchedScript reads a literal script a shell was asked to run, or a
// .sh / shebang command word. The cap keeps a huge file from being a delay.
func launchedScript(cwd string, words []string) (string, bool) {
	i := commandStart(words)
	if i >= len(words) {
		return "", false
	}
	word := strings.TrimPrefix(words[i], "\x00")
	name := base(word)
	if shellWord(name) {
		p := scriptOperand(words[i+1:])
		if p == "" {
			return "", false
		}
		return readScript(cwd, p)
	}
	if !strings.Contains(word, "/") && !strings.HasPrefix(word, ".") && !strings.HasSuffix(name, ".sh") {
		return "", false
	}
	body, ok := readScript(cwd, word)
	if !ok {
		return "", false
	}
	if strings.HasSuffix(name, ".sh") || strings.HasPrefix(body, "#!") {
		return body, true
	}
	return "", false
}

func scriptOperand(rest []string) string {
	for i := 0; i < len(rest); i++ {
		w := strings.TrimPrefix(rest[i], "\x00")
		if w == "--" {
			if i+1 >= len(rest) || stdinOperand(rest[i+1]) {
				return ""
			}
			return strings.TrimPrefix(rest[i+1], "\x00")
		}
		if w == "-c" || w == "-e" || w == "--eval" || w == "-r" || w == "--command" {
			if i+1 < len(rest) {
				i++
			}
			continue
		}
		if stdinOperand(w) || (strings.HasPrefix(w, "-") && w != "-") {
			continue
		}
		return w
	}
	return ""
}

func readScript(cwd, path string) (string, bool) {
	path = strings.TrimPrefix(path, "\x00")
	if path == "" || strings.ContainsAny(path, "*?[$`<>|;&") || strings.Contains(path, "$") || strings.HasPrefix(path, "~") {
		return "", false
	}
	if !filepath.IsAbs(path) {
		if cwd == "" {
			return "", false
		}
		path = filepath.Join(cwd, path)
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 64*1024 {
		return "", false
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 64*1024 {
		return "", false
	}
	return string(b), true
}

func followedByBg(toks []string, i int) bool {
	for j := i + 1; j < len(toks); j++ {
		switch toks[j] {
		case "&":
			return true
		case "|", ";", "&&", "||":
			return false
		}
	}
	return false
}

func selfName(tok string) bool {
	switch tok {
	case "$0", "${0}", "$BASH_SOURCE", "${BASH_SOURCE}", "${BASH_SOURCE[0]}":
		return true
	default:
		return strings.HasPrefix(tok, "${BASH_SOURCE")
	}
}

func shellWord(name string) bool {
	switch name {
	case "bash", "sh", "dash", "zsh", "ksh":
		return true
	default:
		return false
	}
}

// plainRecurse is an invoked function whose every path calls itself and
// that has no conditional. A base case (if, &&, ||, a loop) stays allowed.
func plainRecurse(s string) (Result, bool) {
	plain := hideQuotes(dropHereBodies(stripComments(s)))
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
	visible := blankBodies(plain)
	for name, body := range defined {
		if !invoked(name, visible) {
			continue
		}
		if !callsSelf(name, body) || hasGuard(body) {
			continue
		}
		return catchCase("recurse", "a function calls itself with no base case"), true
	}
	return Result{}, false
}

func callsSelf(name, body string) bool {
	for _, t := range callTargets(body) {
		if t == name {
			return true
		}
	}
	return false
}

func hasGuard(body string) bool {
	for _, t := range opTokens(stripQuotes(body)) {
		switch t {
		case "if", "case", "while", "until", "for", "&&", "||":
			return true
		}
	}
	return false
}

// sensitiveGlob is a glob whose matches are the top-level children of home
// or of a sensitive directory. ~/ws/scratch/*.png is a project glob and
// follows the ordinary rules. The home node, /, and a raw disk are not this.
func sensitiveGlob(op string) bool {
	op = strings.TrimPrefix(op, "\x00")
	op = strings.TrimRight(op, "/")
	if !hasMeta(op) {
		return false
	}
	switch strings.TrimSpace(op) {
	case "/", "/*", "~", "~/", "$HOME", "${HOME}", "$HOME/", "${HOME}/":
		return false
	}
	dir, base := op, op
	if slash := strings.LastIndex(op, "/"); slash >= 0 {
		dir, base = op[:slash], op[slash+1:]
	}
	dir = strings.TrimRight(dir, "/")
	if !hasMeta(base) || hasMeta(dir) {
		return false
	}
	if dir == "" {
		return false
	}
	if exactHomeDir(dir) || systemDirNode(dir) {
		return true
	}
	// A data directory and a dot directory are not project globs.
	// ~/ws/scratch/*.png and ~/ws/var/www/* stay on the ordinary rules.
	return hasDataComponent(dir) || hasDotComponent(dir)
}

// dirGlobCatch is a recursive delete of a directory glob, such as ~/ws/*/.
// The trailing slash follows every match, so this is an approvable catch.
// It is not a hard block: the star is not the home node and not /.
func dirGlobCatch(op string) bool {
	raw := strings.TrimPrefix(op, "\x00")
	if !operandFollowsSlash(raw) || !hasMeta(raw) {
		return false
	}
	trimmed := strings.TrimRight(raw, "/")
	switch trimmed {
	case "", "/", "*", "/*", "~", "~/*", "$HOME", "${HOME}":
		return false
	}
	if exactHomeDir(trimmed) || systemDirNode(trimmed) {
		return false
	}
	return homeTreeOperand(trimmed) || strings.HasPrefix(trimmed, "~/") || strings.HasPrefix(trimmed, "$HOME/") || strings.HasPrefix(trimmed, "${HOME}/")
}

func hasDataComponent(dir string) bool {
	for _, part := range strings.Split(dir, "/") {
		if part == "data" {
			return true
		}
	}
	return false
}

func hasDotComponent(dir string) bool {
	for _, part := range strings.Split(dir, "/") {
		if len(part) > 1 && part[0] == '.' && part != ".." {
			return true
		}
	}
	return false
}

func exactHomeDir(dir string) bool {
	switch dir {
	case "~", "$HOME", "${HOME}", "/root":
		return true
	}
	if strings.HasPrefix(dir, "/home/") {
		rest := strings.TrimPrefix(dir, "/home/")
		return rest != "" && !strings.Contains(rest, "/")
	}
	return false
}

func hasMeta(s string) bool {
	return shellGlob(s)
}

// shellGlob reports a glob metacharacter outside ${...}. The ? in ${name:?}
// aborts on an unset variable. It does not glob.
func shellGlob(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '$' && i+1 < len(s) && s[i+1] == '{' {
			end := strings.IndexByte(s[i+2:], '}')
			if end >= 0 {
				i += 2 + end
				continue
			}
		}
		if s[i] == '*' || s[i] == '?' || s[i] == '[' {
			return true
		}
	}
	return false
}

// judgeXargsList judges rm targets that xargs would receive.
// A statically known list is judged as those items. Bulk applies to a
// large known recursive list, or to a recursive list whose items are not
// visible. A short non-recursive list is not a bulk delete.
func judgeXargsList(prev []scannedCmd, xargsWords []string, rec bool) (Result, bool) {
	items, known := xargsItems(prev, xargsNul(xargsWords))
	if !known {
		if rec {
			return catchCase("xargs-rm", "recursive rm of a list that is not visible here"), true
		}
		if vcsListInto(prev) {
			return catchCase("xargs-rm", "rm of a repository file list"), true
		}
		return Result{}, false
	}
	return judgeKnownRM(items, rec)
}

// vcsListInto is a version-control path listing (git ls-files, and the same
// shape) feeding xargs, possibly through cat or tee. A later head or sed
// has already limited the list, so that is not this case.
func vcsListInto(prev []scannedCmd) bool {
	for i := len(prev) - 1; i >= 0; i-- {
		if passthroughStage(prev[i].words) {
			continue
		}
		return vcsPathList(prev[i].words)
	}
	return false
}

func vcsPathList(words []string) bool {
	i := commandStart(words)
	if i >= len(words) {
		return false
	}
	name := base(words[i])
	sub := ""
	for _, w := range words[i+1:] {
		w = strings.TrimPrefix(w, "\x00")
		if w == "--" || strings.HasPrefix(w, "-") {
			continue
		}
		sub = w
		break
	}
	switch name {
	case "git":
		switch sub {
		case "ls-files", "diff", "grep", "status":
			return true
		}
	case "hg":
		switch sub {
		case "status", "files", "locate", "grep", "diff":
			return true
		}
	case "svn":
		switch sub {
		case "status", "list", "ls", "diff":
			return true
		}
	}
	return false
}

func xargsNul(words []string) bool {
	for _, w := range words {
		if w == "-0" || w == "--null" {
			return true
		}
	}
	return false
}

func xargsItems(prev []scannedCmd, nul bool) ([]string, bool) {
	for i := len(prev) - 1; i >= 0; i-- {
		if passthroughStage(prev[i].words) {
			body := prev[i].hereBody
			if body == "" {
				continue
			}
			if hasMeta(body) || hasOpaqueEscape(body) {
				return nil, false
			}
			return splitList(body, nul), true
		}
		return producerItems(prev[i], nul)
	}
	return nil, false
}

func producerItems(c scannedCmd, nul bool) ([]string, bool) {
	if streamOpaque(c) {
		return nil, false
	}
	i := commandStart(c.words)
	if i >= len(c.words) {
		return nil, false
	}
	name := base(c.words[i])
	switch name {
	case "echo":
		text, ok := echoScript(c.words)
		if !ok || hasMeta(text) || hasOpaqueEscape(text) {
			return nil, false
		}
		return splitList(text, nul), true
	case "printf":
		return printfItems(c.words, nul)
	default:
		return nil, false
	}
}

func printfItems(words []string, nul bool) ([]string, bool) {
	i := commandStart(words)
	var parts []string
	for _, w := range words[i+1:] {
		w = strings.TrimPrefix(w, "\x00")
		if w == "--" || (strings.HasPrefix(w, "-") && w != "-" && !strings.HasPrefix(w, "%")) {
			continue
		}
		parts = append(parts, w)
	}
	if len(parts) == 0 {
		return nil, false
	}
	format := parts[0]
	args := parts[1:]
	for _, a := range args {
		if hasMeta(a) || hasOpaqueEscape(a) {
			return nil, false
		}
	}
	// %s arguments are the items. A \0 or \n in the format is a separator,
	// not an encoded path. A format with no arguments and a \x or octal
	// escape is an opaque list.
	if strings.Contains(format, "%") && len(args) > 0 {
		return args, true
	}
	if hasOpaqueEscape(format) {
		return nil, false
	}
	text := decodePrintf(format)
	if hasMeta(text) || hasOpaqueEscape(text) {
		return nil, false
	}
	return splitList(text, nul), true
}

func splitList(s string, nul bool) []string {
	if nul {
		return strings.Split(strings.Trim(s, "\x00"), "\x00")
	}
	return strings.Fields(s)
}

func judgeKnownRM(items []string, rec bool) (Result, bool) {
	var ops []string
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		ops = append(ops, it)
	}
	if len(ops) == 0 {
		return Result{}, false
	}
	if rec && wholeRoot(ops) {
		return block("rm-root", "rm of the top-level directories"), true
	}
	for _, op := range ops {
		switch strings.TrimSpace(op) {
		case "/", "/*", "~", "~/", "$HOME", "${HOME}":
			return block("rm-root", "rm of / or a home directory"), true
		}
		if rec && systemDirNode(op) {
			return catchCase("system-dir", "recursive delete of a system directory"), true
		}
		if rec && sensitiveGlob(op) {
			return catchCase("glob-delete", "recursive delete of a glob under a home or sensitive tree"), true
		}
	}
	if rec && weightedHomeOperands(ops) {
		return catchCase("bulk", "recursive delete of several directories in a home or sensitive tree"), true
	}
	if !rec && len(ops) > bulkTargets {
		return catchCase("bulk", "rm of more files than the bulk threshold"), true
	}
	// A known list is judged per item. Two or more filesystem paths are a
	// delete of that list. One path is the same as one rm. Plain names are not.
	if pathCount(ops) >= 2 {
		return catchCase("xargs-rm", "rm of a list of paths"), true
	}
	return Result{}, false
}

// wholeRoot is a recursive delete of every top-level directory that exists,
// the same set engine.coversSystemTop uses for bash's /*. One system
// directory is not this. A directory that is not on this host does not count.
func wholeRoot(ops []string) bool {
	set := map[string]struct{}{}
	for _, t := range ops {
		t = strings.TrimSpace(strings.TrimPrefix(t, "\x00"))
		if t == "" {
			continue
		}
		set[filepath.Clean(t)] = struct{}{}
	}
	canonical := []string{"/bin", "/etc", "/usr", "/home", "/var", "/lib", "/sbin", "/opt", "/root", "/boot"}
	need, hit := 0, 0
	for _, c := range canonical {
		if _, err := os.Lstat(c); err != nil {
			continue
		}
		need++
		if _, ok := set[c]; ok {
			hit++
		}
	}
	return need >= 3 && hit == need
}

func pathCount(ops []string) int {
	n := 0
	for _, op := range ops {
		if pathLike(op) {
			n++
		}
	}
	return n
}

func pathLike(s string) bool {
	s = strings.TrimSpace(strings.TrimPrefix(s, "\x00"))
	if s == "" || s == "-" {
		return false
	}
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || strings.Contains(s, "/")
}

// stdinOperand is a shell argument that means "read the script from stdin".
func stdinOperand(w string) bool {
	w = strings.TrimPrefix(w, "\x00")
	switch w {
	case "-", "/dev/stdin", "/dev/fd/0":
		return true
	default:
		return false
	}
}

// encodedStream is printf/echo output whose bytes are hidden by \x, octal,
// or $'...' . The text is not decoded to decide whether it is safe.
func encodedStream(prev []scannedCmd, payload string) bool {
	if hasOpaqueEscape(payload) {
		return true
	}
	for _, c := range prev {
		if streamOpaque(c) {
			return true
		}
	}
	return false
}

func streamOpaque(c scannedCmd) bool {
	for _, r := range c.raws {
		if strings.Contains(r, "$'") {
			return true
		}
	}
	for _, w := range c.words {
		if strings.Contains(w, "$'") || hasOpaqueEscape(w) {
			return true
		}
	}
	if hasOpaqueEscape(c.hereBody) || hasOpaqueEscape(c.hereArg) || strings.Contains(c.hereArg, "$'") {
		return true
	}
	return false
}

func hasOpaqueEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			continue
		}
		n := s[i+1]
		switch n {
		case 'x', 'X', 'u', 'U':
			return true
		}
		if n >= '0' && n <= '7' {
			return true
		}
	}
	return false
}

// encodedIntoExec is an interpreter payload that decodes bytes and passes
// them to a process or eval. The decoded text is not inspected.
func encodedIntoExec(code string) bool {
	execs := []string{"system", "popen", "exec", "eval", "execl", "execv", "check_output", "check_call"}
	decoders := []string{"b64decode", "urlsafe_b64decode", "decodebytes", "a2b_base64", "unhexlify", "atob", "b64decode"}
	for _, name := range execs {
		for _, arg := range callArgs(code, name) {
			low := strings.ToLower(arg)
			for _, d := range decoders {
				if strings.Contains(low, d) {
					return true
				}
			}
		}
	}
	return false
}

// opaqueCode is an ANSI-C quoted -c or -e payload. The escapes are not
// decoded to decide whether the script is safe. \n, \t, and \r are spacing.
func opaqueCode(command string) (Result, bool) {
	for _, c := range commandWords(command) {
		raw := rawCodeArg(c)
		if raw != "" && ansiCOpaque(raw) {
			return catchCase("encoded-exec", "an encoded script is passed to an interpreter"), true
		}
	}
	return Result{}, false
}

func rawCodeArg(c scannedCmd) string {
	words := c.words
	raws := c.raws
	if len(raws) != len(words) {
		raws = words
	}
	i := commandStart(words)
	if i >= len(words) {
		return ""
	}
	name := base(words[i])
	var flags []string
	switch name {
	case "bash", "sh", "dash", "zsh", "ksh", "python", "python2", "python3":
		flags = []string{"-c"}
	case "perl", "node", "nodejs", "ruby":
		flags = []string{"-e"}
	case "php":
		flags = []string{"-r"}
	default:
		return ""
	}
	for j := i + 1; j < len(words); j++ {
		w := words[j]
		for _, f := range flags {
			if w == f && j+1 < len(words) {
				return raws[j+1]
			}
			if strings.HasPrefix(w, f+"=") {
				return raws[j]
			}
		}
		if (name == "bash" || name == "sh" || name == "dash" || name == "zsh" || name == "ksh") &&
			strings.HasPrefix(w, "-") && strings.Contains(w, "c") && !strings.HasPrefix(w, "--") && j+1 < len(words) {
			return raws[j+1]
		}
	}
	return ""
}

func ansiCOpaque(raw string) bool {
	for i := 0; i+1 < len(raw); i++ {
		if raw[i] != '$' || raw[i+1] != '\'' {
			continue
		}
		j := i + 2
		for j < len(raw) && raw[j] != '\'' {
			if raw[j] == '\\' && j+1 < len(raw) {
				n := raw[j+1]
				switch n {
				case 'x', 'X', 'u', 'U':
					return true
				case 'n', 't', 'r', '\\', '\'', '"':
				default:
					if n >= '0' && n <= '7' {
						return true
					}
				}
				j += 2
				continue
			}
			j++
		}
	}
	return false
}

// stateOverride is a command that sets the spotter state directory.
// The shim ignores that variable. Setting it is still a catch, because
// the caller is trying to choose the key. An argument of echo is not a set.
func stateOverride(command string) (Result, bool) {
	for _, c := range commandWords(command) {
		if assignsState(c.words) {
			return catchCase("state-override", "a command sets the spotter state directory or a cover id"), true
		}
	}
	return Result{}, false
}

func assignsState(words []string) bool {
	i := 0
	for i < len(words) {
		w := strings.TrimPrefix(words[i], "\x00")
		if isAssign(w) {
			name, _, _ := strings.Cut(w, "=")
			if stateDirName(name) {
				return true
			}
			i++
			continue
		}
		b := base(w)
		switch b {
		case "command", "builtin", "nice", "nohup", "time", "setsid":
			i++
			continue
		case "sudo", "doas":
			i++
			i = skipSudoFlags(words, i)
			continue
		case "env", "export", "declare", "typeset", "local", "readonly":
			i++
			for i < len(words) {
				rest := strings.TrimPrefix(words[i], "\x00")
				if isAssign(rest) {
					name, _, _ := strings.Cut(rest, "=")
					if stateDirName(name) {
						return true
					}
					i++
					continue
				}
				if strings.HasPrefix(rest, "-") && rest != "-" {
					i++
					continue
				}
				// declare -x SPOTTER_SH_HOME   exports the name with no value.
				if b != "env" && stateDirName(rest) {
					return true
				}
				break
			}
			if b == "env" {
				continue
			}
			return false
		default:
			return false
		}
	}
	return false
}

func stateDirName(name string) bool {
	switch name {
	case "SPOTTER_SH_HOME", "SHELLSPOTTER_HOME", "SPOTTER_SH_COVERED", "SHELLSPOTTER_COVERED":
		return true
	default:
		return false
	}
}

// writtenThenRun judges a script this command writes and then executes,
// when the bytes are visible in the command. The file is not run.
func writtenThenRun(command, cwd, home string, depth int) (Result, bool) {
	if depth > 8 {
		return catchCase("fed-shell", "nested generated shell"), true
	}
	bodies := map[string]string{}
	for _, c := range commandWords(command) {
		if c.openSub || c.closeSub {
			continue
		}
		if body, path, ok := knownScriptWrite(c, cwd, home); ok {
			bodies[path] = body
		}
		path, ok := executedScriptPath(c, cwd, home)
		if !ok {
			continue
		}
		body, found := bodies[path]
		if !found {
			continue
		}
		r := scanAt(body, cwd, home, depth+1)
		if r.Action == "hardblock" || r.Action == "catch" {
			return r, true
		}
	}
	return Result{}, false
}

func knownScriptWrite(c scannedCmd, cwd, home string) (body, path string, ok bool) {
	path = scriptKey(truncatingTarget(c.redirs), cwd, home)
	if path == "" {
		return "", "", false
	}
	name := ""
	if i := commandStart(c.words); i < len(c.words) {
		name = base(c.words[i])
	}
	if c.hereBody != "" && (name == "cat" || name == "tee") {
		return c.hereBody, path, true
	}
	if text, ok := pipeScript(c.words); ok && strings.TrimSpace(text) != "" {
		return text, path, true
	}
	return "", "", false
}

func truncatingTarget(rs []redir) string {
	for _, rd := range rs {
		if rd.append || rd.path == "" {
			continue
		}
		return rd.path
	}
	return ""
}

func executedScriptPath(c scannedCmd, cwd, home string) (string, bool) {
	i := commandStart(c.words)
	if i >= len(c.words) {
		return "", false
	}
	name := base(c.words[i])
	switch name {
	case "bash", "sh", "dash", "zsh", "ksh", "source", ".":
	default:
		return "", false
	}
	for _, w := range c.words[i+1:] {
		w = strings.TrimPrefix(w, "\x00")
		if w == "" || w == "--" {
			continue
		}
		if name != "source" && name != "." && strings.HasPrefix(w, "-") {
			if w == "-c" || w == "-e" || (strings.Contains(w, "c") && !strings.HasPrefix(w, "--")) {
				return "", false
			}
			continue
		}
		key := scriptKey(w, cwd, home)
		if key == "" {
			return "", false
		}
		return key, true
	}
	return "", false
}

func scriptKey(p, cwd, home string) string {
	p = strings.TrimSpace(strings.TrimPrefix(p, "\x00"))
	if p == "" {
		return ""
	}
	p = expandBashWord(p, shellState{cwd: cwd, home: home})
	if p == "" || strings.HasPrefix(p, "\x00") {
		return ""
	}
	if !filepath.IsAbs(p) {
		base := cwd
		if base == "" {
			base = "."
		}
		p = filepath.Join(base, p)
	}
	return filepath.Clean(p)
}
