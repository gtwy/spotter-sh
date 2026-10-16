// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package precheck is the tiny Layer-1 text check.
// It only hard-blocks commands that are never legitimate, plus the bare .* warning.
// Bash remains the parser. Quoted text and heredoc bodies are not commands.
package precheck

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Result is a pre-check decision. Exit follows the public contract.
// Approve is set when a hard block is a text heuristic that can be wrong.
// An admin can then proceed through a catch id. A disk or an exact /
// stays blocked with no approval.
type Result struct {
	Action  string // allow, catch, hardblock
	Exit    int
	Message string
	Case    string
	Approve bool
}

type shellState struct {
	cwd  string
	home string
	old  string
}

// Scan inspects a command string. It does not rewrite it.
func Scan(command string) Result {
	cwd, _ := os.Getwd()
	return ScanAt(command, cwd, loginHome())
}

// ScanAt resolves ~, $PWD, and cd the way the shell at cwd would.
func ScanAt(command, cwd, home string) Result {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	if home == "" {
		home = loginHome()
	}
	return scanAt(command, cwd, home, 0)
}

func scanAt(command, cwd, home string, depth int) Result {
	if depth > 8 {
		return catchCase("fed-shell", "nested generated shell")
	}
	st := shellState{cwd: cwd, home: home, old: os.Getenv("OLDPWD")}
	if r, ok := embeddedSubst(command, cwd, home, depth); ok {
		return r
	}
	if r, ok := opaqueCode(command); ok {
		return r
	}
	if r, ok := selfExec(command, cwd); ok {
		return r
	}
	text := normalize(command)
	if r, ok := fedCode(command); ok {
		return r
	}
	if bomb(text) {
		return block("fork bomb", "a function that pipes or backgrounds a call to itself")
	}
	if loopBomb(text) {
		return block("fork bomb", "an unbounded loop that backgrounds a new process")
	}
	if pipeSelfBomb(text) {
		return block("fork bomb", "a builtin piped to itself in the background")
	}
	if r, ok := plainRecurse(text); ok {
		return r
	}
	if r, ok := pipelineRisk(command, st); ok {
		return r
	}
	// Redirects are read from the original text so quotes and $'...' keep
	// bash's expansion rules. cd updates the directory for later redirects.
	// A subshell and every pipeline stage get their own directory: (cd ~)
	// and `echo | cd` do not change the next command. Command words use the
	// normalized text so a disguised rm is still visible.
	skip := false
	var stack []shellState
	inPipe := false
	pipeBase := st
	for _, c := range commandWords(command) {
		if c.openSub {
			stack = append(stack, st)
			skip = false
			inPipe = false
			continue
		}
		if c.closeSub {
			if len(stack) > 0 {
				st = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			}
			skip = false
			inPipe = false
			continue
		}
		use := st
		if inPipe {
			use = pipeBase
		}
		if !skip {
			if r, ok := rmFollowsRoot(c.words, use); ok {
				return r
			}
			for _, rd := range c.redirs {
				path := resolveRedirect(rd.path, use)
				rd.path = path
				if isSystemDisk(path) {
					return block("raw-disk", "redirect onto a system disk")
				}
				if got, ok := protectedRedirect(rd, use.home); ok {
					return catchRedirect(got)
				}
			}
			ran, ok := use.cd(c.words)
			if c.stop == "|" {
				if !inPipe {
					pipeBase = st
					inPipe = true
				}
				continue
			}
			if !inPipe {
				st = use
			}
			inPipe = false
			switch c.stop {
			case "&&":
				if ran && !ok {
					skip = true
				}
			case "||":
				if ran && ok {
					skip = true
				}
			default:
				skip = false
			}
			continue
		}
		if c.stop == "|" {
			if !inPipe {
				pipeBase = st
				inPipe = true
			}
			continue
		}
		inPipe = false
		switch c.stop {
		case "&&", "||":
		default:
			skip = false
		}
	}
	for _, c := range commandWords(text) {
		if r, ok := match(c.words); ok {
			return r
		}
	}
	if r, ok := judgeLaunchers(text, cwd, home, depth); ok {
		return r
	}
	if r, ok := writtenThenRun(command, cwd, home, depth); ok {
		return r
	}
	if r, ok := stateOverride(command); ok {
		return r
	}
	return Result{Action: "allow", Exit: 0}
}

func resolveRedirect(raw string, st shellState) string {
	p := expandBashWord(raw, st)
	if p == "" || strings.HasPrefix(p, "~") {
		return p
	}
	if !filepath.IsAbs(p) {
		base := st.cwd
		if base == "" {
			base, _ = os.Getwd()
		}
		p = filepath.Join(base, p)
	}
	return filepath.Clean(p)
}

func (st *shellState) cd(words []string) (ran, ok bool) {
	i := 0
	for i < len(words) && (isAssign(words[i]) || words[i] == "{") {
		i++
	}
	kind := ""
	if i < len(words) {
		kind = base(words[i])
	}
	if kind != "cd" && kind != "pushd" && kind != "popd" {
		return false, false
	}
	if kind == "popd" || (kind == "pushd" && (i+1 >= len(words) || strings.HasPrefix(words[i+1], "-"))) {
		if st.old == "" {
			return true, false
		}
		st.cwd, st.old = st.old, st.cwd
		return true, true
	}
	arg := ""
	if i+1 < len(words) && !strings.HasPrefix(words[i+1], "-") {
		arg = words[i+1]
	}
	dest := st.home
	switch {
	case arg == "-":
		dest = st.old
	case arg != "":
		dest = expandBashWord(arg, *st)
	}
	if dest == "" {
		return true, false
	}
	if !filepath.IsAbs(dest) {
		dest = filepath.Join(st.cwd, dest)
	}
	dest = evalPath(filepath.Clean(dest))
	info, err := os.Stat(dest)
	if err != nil || !info.IsDir() {
		return true, false
	}
	st.old = st.cwd
	st.cwd = dest
	return true, true
}

func block(caseName, why string) Result {
	return Result{
		Action:  "hardblock",
		Exit:    121,
		Case:    caseName,
		Message: "Shell Spotter: BLOCKED — " + why + ". This command is never allowed. If you truly mean it, a human must run it by hand (/bin/<cmd>).",
	}
}

// blockHeuristic is a hard block that pattern-matches text. It can be a
// false positive, so an admin may approve it through a catch id.
func blockHeuristic(caseName, why string) Result {
	r := block(caseName, why)
	r.Approve = true
	return r
}

func catchRedirect(path string) Result {
	return Result{
		Action:  "catch",
		Exit:    120,
		Case:    "redirect",
		Approve: true,
		Message: "Shell Spotter: redirect onto a protected file (" + path + "). The file would be replaced.",
	}
}

func protectedRedirect(rd redir, home string) (string, bool) {
	p := strings.TrimSpace(rd.path)
	if p == "" || p == "." || strings.HasPrefix(p, "~") {
		return "", false
	}
	p = filepath.Clean(p)
	resolved := evalPath(p)
	for _, f := range protectedRedirects(home) {
		if samePath(resolved, f) || samePath(p, f) {
			return resolved, true
		}
	}
	if home == "" {
		home = loginHome()
	}
	if home == "" {
		return "", false
	}
	// ~/.config is broad. Catch a truncate of a file that is already there.
	// Creating a new file, appending, or writing a stderr log is ordinary.
	cfg := filepath.Join(home, ".config")
	if underPath(resolved, cfg) || underPath(p, cfg) {
		if rd.append || rd.fd == 2 {
			return "", false
		}
		st, err := os.Lstat(p)
		if err != nil {
			st, err = os.Lstat(resolved)
		}
		if err != nil || st.IsDir() {
			return "", false
		}
		return resolved, true
	}
	// /usr/lib and /lib, including the /lib -> usr/lib symlink, are file by
	// file like /usr/bin. A truncating overwrite catches. Append and stderr do not.
	if !rd.append && rd.fd != 2 && (systemTreePath(resolved) || systemTreePath(p)) {
		return resolved, true
	}
	return "", false
}

func systemTreePath(p string) bool {
	roots := []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/lib64", "/usr/lib", "/usr/lib64"}
	p = filepath.Clean(p)
	for _, root := range roots {
		if p == root || strings.HasPrefix(p, root+string(filepath.Separator)) {
			return true
		}
		if real, err := filepath.EvalSymlinks(p); err == nil {
			real = filepath.Clean(real)
			if real == root || strings.HasPrefix(real, root+string(filepath.Separator)) {
				return true
			}
		}
	}
	return false
}

func underPath(p, root string) bool {
	p = filepath.Clean(p)
	root = filepath.Clean(root)
	if p == root {
		return true
	}
	realP := evalPath(p)
	realRoot := evalPath(root)
	return realP == realRoot || strings.HasPrefix(realP, realRoot+string(os.PathSeparator)) || strings.HasPrefix(p, root+string(os.PathSeparator))
}

func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	return evalPath(a) == evalPath(b)
}

func evalPath(p string) string {
	if p == "" {
		return ""
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return filepath.Clean(real)
	}
	var tail []string
	parent := p
	for {
		if real, err := filepath.EvalSymlinks(parent); err == nil {
			parts := append([]string{real}, tail...)
			return filepath.Clean(filepath.Join(parts...))
		}
		base := filepath.Base(parent)
		next := filepath.Dir(parent)
		if next == parent {
			break
		}
		tail = append([]string{base}, tail...)
		parent = next
	}
	return filepath.Clean(p)
}

func loginHome() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		return ""
	}
	return u.HomeDir
}

func protectedRedirects(home string) []string {
	if home == "" {
		home = loginHome()
	}
	files := []string{
		"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers",
		"/etc/fstab", "/etc/hosts", "/etc/resolv.conf", "/etc/crontab",
	}
	if home != "" {
		files = append(files,
			filepath.Join(home, ".bashrc"),
			filepath.Join(home, ".bash_profile"),
			filepath.Join(home, ".profile"),
			filepath.Join(home, ".zshrc"),
			filepath.Join(home, ".ssh", "authorized_keys"),
			filepath.Join(home, ".ssh", "config"),
		)
	}
	return files
}

func catchStar() Result {
	return Result{
		Action:  "catch",
		Exit:    120,
		Case:    "B",
		Message: "Shell Spotter: bare .* matches .. and can recurse into the parent. Prefer .[!.]*",
	}
}

func normalize(s string) string {
	s = strings.ReplaceAll(s, "\u200b", "")
	s = strings.ReplaceAll(s, "\u200c", "")
	s = strings.ReplaceAll(s, "\u200d", "")
	s = strings.ReplaceAll(s, "\ufeff", "")
	s = strings.ReplaceAll(s, "\u2060", "")
	s = decodeANSI(s)
	return s
}

// decodeANSI rewrites $'\xNN' and $'\nnn' so a disguised command word is visible.
func decodeANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], "$'") {
			j := i + 2
			var body strings.Builder
			closed := false
			for j < len(s) {
				if s[j] == '\\' && j+1 < len(s) {
					j++
					switch s[j] {
					case 'x', 'X':
						if j+2 < len(s) && isHex(s[j+1]) && isHex(s[j+2]) {
							body.WriteByte(unhex(s[j+1])<<4 | unhex(s[j+2]))
							j += 3
							continue
						}
					case 'n':
						body.WriteByte('\n')
						j++
						continue
					case 't':
						body.WriteByte('\t')
						j++
						continue
					default:
						if s[j] >= '0' && s[j] <= '7' {
							n := 0
							k := 0
							for k < 3 && j < len(s) && s[j] >= '0' && s[j] <= '7' {
								n = n*8 + int(s[j]-'0')
								j++
								k++
							}
							body.WriteByte(byte(n))
							continue
						}
						body.WriteByte(s[j])
						j++
						continue
					}
				}
				if s[j] == '\'' {
					closed = true
					j++
					break
				}
				body.WriteByte(s[j])
				j++
			}
			if closed {
				// $'...' is quoting. A tilde inside it is a literal name,
				// the same as '~'. Slashes are still slashes.
				b.WriteByte('\'')
				for _, r := range body.String() {
					if r == '\'' {
						b.WriteString("'\\''")
						continue
					}
					b.WriteRune(r)
				}
				b.WriteByte('\'')
				i = j
				continue
			}
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

type redir struct {
	path   string
	append bool
	fd     int
}

type scannedCmd struct {
	words     []string
	raws      []string
	redirs    []redir
	stop      string
	openSub   bool
	closeSub  bool
	stdinCode string
	hereBody  string
	hereArg   string
}

// commandWords returns argv-like words for each command position.
// Words inside quotes, heredocs, and comments are not commands.
// A '>' is a redirect only outside quotes.
func commandWords(s string) []scannedCmd {
	var cmds []scannedCmd
	var cur []string
	var raws []string
	var redirs []redir
	var word strings.Builder
	inS, inD := false, false
	atCmd := true
	skipNextArg := false
	qkind := byte(0)
	bare := false
	stopper := ""
	stdinCode := ""
	hereBody := ""
	hereArg := ""
	rawStart := -1
	var i int
	markRaw := func(at int) {
		if rawStart < 0 {
			rawStart = at
		}
	}
	// A heredoc body starts on the next line. The rest of the delimiter
	// line, including `| bash`, is still a command.
	pendDelim := ""
	pendStrip := false
	pendCmd := -1
	flushWord := func() {
		if word.Len() == 0 {
			qkind = 0
			bare = false
			rawStart = -1
			return
		}
		w := word.String()
		raw := ""
		if rawStart >= 0 {
			raw = s[rawStart:i]
			rawStart = -1
		}
		word.Reset()
		if !bare && qkind != 0 {
			w = literalOperand(w, qkind)
		}
		qkind = 0
		bare = false
		if skipNextArg {
			skipNextArg = false
			cur = append(cur, w)
			raws = append(raws, raw)
			return
		}
		cur = append(cur, w)
		raws = append(raws, raw)
		if atCmd {
			atCmd = false
		}
		if isMessageFlag(w) {
			skipNextArg = true
		}
	}
	endCmd := func() {
		flushWord()
		if pendDelim != "" && pendCmd < 0 && (len(cur) > 0 || len(redirs) > 0 || stdinCode != "" || hereBody != "") {
			pendCmd = len(cmds)
		}
		if len(cur) > 0 || len(redirs) > 0 || stdinCode != "" || hereBody != "" || hereArg != "" {
			cmds = append(cmds, scannedCmd{words: cur, raws: raws, redirs: redirs, stop: stopper, stdinCode: stdinCode, hereBody: hereBody, hereArg: hereArg})
		}
		cur = nil
		raws = nil
		redirs = nil
		stopper = ""
		stdinCode = ""
		hereBody = ""
		hereArg = ""
		atCmd = true
		skipNextArg = false
	}
	for i < len(s) {
		c := s[i]
		if !inS && !inD && (c == '\n') {
			if pendDelim != "" {
				i++
				body, next := readHereBody(s, i, pendDelim, pendStrip)
				i = next
				if pendCmd >= 0 && pendCmd < len(cmds) {
					cmds[pendCmd].hereBody = body
				} else {
					hereBody = body
					if shellReadsStdin(cur) {
						stdinCode = body
					}
				}
				pendDelim = ""
				pendStrip = false
				pendCmd = -1
			} else {
				i++
			}
			stopper = ";"
			endCmd()
			continue
		}
		switch {
		case inS:
			if c == '\'' {
				inS = false
			} else {
				word.WriteByte(c)
			}
			i++
		case inD:
			// Bash only drops the backslash for $, `, ", \, and newline.
			// \n stays two characters so printf can still see the escape.
			if c == '\\' && i+1 < len(s) {
				n := s[i+1]
				if n == '$' || n == '`' || n == '"' || n == '\\' || n == '\n' {
					if n != '\n' {
						word.WriteByte(n)
					}
					i += 2
					continue
				}
				word.WriteByte('\\')
				word.WriteByte(n)
				i += 2
				continue
			}
			if c == '"' {
				inD = false
			} else {
				word.WriteByte(c)
			}
			i++
		case c == '\'':
			markRaw(i)
			if word.Len() == 0 && !bare {
				qkind = '\''
			}
			inS = true
			i++
		case c == '"':
			markRaw(i)
			if word.Len() == 0 && !bare {
				qkind = '"'
			}
			inD = true
			i++
		case c == ' ' || c == '\t':
			flushWord()
			i++
		case c == ';' || c == '\n':
			stopper = ";"
			endCmd()
			i++
		case (c == '<' || c == '>') && i+1 < len(s) && s[i+1] == '(':
			// Process substitution is one word. A decoder inside it is judged
			// with the command that receives the substitution.
			markRaw(i)
			end := skipParen(s, i+1)
			word.WriteString(s[i:end])
			i = end
			bare = true
			qkind = 0
			continue
		case c == '&' || c == '|':
			// && || | &
			if i+1 < len(s) && s[i+1] == c {
				if c == '&' {
					stopper = "&&"
				} else {
					stopper = "||"
				}
				endCmd()
				i += 2
				continue
			}
			if c == '&' {
				stopper = "&"
			} else {
				stopper = "|"
			}
			endCmd()
			i++
		case c == '<' && i+2 < len(s) && s[i+1] == '<' && s[i+2] == '<':
			// herestring: the word is stdin. A shell reads it as code.
			flushWord()
			i += 3
			for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
				i++
			}
			raw, next := readRedirectOperand(s, i)
			i = next
			hereArg = unquoteWord(strings.TrimPrefix(raw, "\x00"))
			if shellReadsStdin(cur) {
				stdinCode = hereArg
			}
		case c == '<' && i+1 < len(s) && s[i+1] == '<':
			// heredoc: skip body until delimiter. A shell reads that body as code.
			flushWord()
			i += 2
			strip := false
			if i < len(s) && s[i] == '-' {
				strip = true
				i++
			}
			for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
				i++
			}
			var delim strings.Builder
			q := byte(0)
			if i < len(s) && (s[i] == '\'' || s[i] == '"') {
				q = s[i]
				i++
			}
			for i < len(s) && s[i] != '\n' && (q != 0 || (s[i] != ' ' && s[i] != '\t')) {
				if q != 0 && s[i] == q {
					i++
					break
				}
				delim.WriteByte(s[i])
				i++
			}
			// The body begins on the next line. Leave `| bash` on this line.
			pendDelim = delim.String()
			pendStrip = strip
			pendCmd = -1
		case c == '#' && word.Len() == 0:
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '>':
			fdNum := 1
			if word.Len() > 0 {
				fdText := word.String()
				digits := fdText != ""
				n := 0
				for _, r := range fdText {
					if r < '0' || r > '9' {
						digits = false
						break
					}
					n = n*10 + int(r-'0')
				}
				if digits {
					fdNum = n
					word.Reset()
				} else {
					flushWord()
				}
			}
			i++
			appending := false
			if i < len(s) && s[i] == '>' {
				appending = true
				i++
			} else if i < len(s) && s[i] == '|' {
				i++
			}
			if i < len(s) && s[i] == '&' {
				i++
				for i < len(s) && s[i] >= '0' && s[i] <= '9' {
					i++
				}
				continue
			}
			for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
				i++
			}
			raw, next := readRedirectOperand(s, i)
			i = next
			if raw != "" && raw != "." {
				redirs = append(redirs, redir{path: raw, append: appending, fd: fdNum})
			}
		case c == '(' || c == ')':
			// A subshell does not keep cd. Function parentheses are the same
			// boundary: the body is not the next command's directory.
			endCmd()
			if c == '(' {
				cmds = append(cmds, scannedCmd{openSub: true, stop: ";"})
			} else {
				cmds = append(cmds, scannedCmd{closeSub: true, stop: ";"})
			}
			i++
		default:
			if c == '$' && i+1 < len(s) && s[i+1] == '(' {
				// $(...) is one word. It does not change the parent directory.
				markRaw(i)
				end := skipSubst(s, i)
				word.WriteString(s[i:end])
				i = end
				bare = true
				qkind = 0
				continue
			}
			if c == '`' {
				markRaw(i)
				j := i + 1
				for j < len(s) {
					if s[j] == '\\' && j+1 < len(s) {
						j += 2
						continue
					}
					if s[j] == '`' {
						j++
						break
					}
					j++
				}
				word.WriteString(s[i:j])
				i = j
				bare = true
				qkind = 0
				continue
			}
			markRaw(i)
			bare = true
			qkind = 0
			word.WriteByte(c)
			i++
		}
	}
	endCmd()
	return cmds
}

// skipSubst returns the index just after a $(...) that starts at i.
func skipSubst(s string, i int) int {
	if i >= len(s) || s[i] != '$' {
		return i
	}
	i++
	if i >= len(s) || s[i] != '(' {
		return i
	}
	depth := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if s[i] == '\'' || s[i] == '"' || (s[i] == '$' && i+1 < len(s) && s[i+1] == '\'') {
			i = skipBashQuote(s, i)
			continue
		}
		if s[i] == '(' {
			depth++
			i++
			continue
		}
		if s[i] == ')' {
			depth--
			i++
			if depth == 0 {
				return i
			}
			continue
		}
		i++
	}
	return i
}

// readHereBody reads a heredoc body starting at i, up to but not including
// the closing delimiter line. next is the index after that line.
func readHereBody(s string, i int, delim string, strip bool) (body string, next int) {
	var b strings.Builder
	for i < len(s) {
		lineEnd := strings.IndexByte(s[i:], '\n')
		var line string
		if lineEnd < 0 {
			line = s[i:]
			next = len(s)
		} else {
			line = s[i : i+lineEnd]
			next = i + lineEnd + 1
		}
		cmp := line
		if strip {
			cmp = strings.TrimLeft(cmp, " \t")
		}
		if cmp == delim {
			return b.String(), next
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(line)
		if lineEnd < 0 {
			return b.String(), next
		}
		i = next
	}
	return b.String(), i
}

func isMessageFlag(w string) bool {
	if w == "-m" || w == "-e" || w == "--eval" || w == "-c" || w == "-q" || w == "--message" {
		return false // handled as command args, not skipped for hard-block of the command itself
	}
	// git commit -m "...." — the next word is data, never a command.
	switch w {
	case "-m", "--message":
		return true
	default:
		return false
	}
}

func match(words []string) (Result, bool) {
	if len(words) == 0 {
		return Result{}, false
	}
	// Assignments and wrappers (env, sudo, command, nice, timeout, exec)
	// are not the command. env -i PATH=... rm is still rm.
	i := commandStart(words)
	if i >= len(words) {
		return Result{}, false
	}
	name := base(words[i])
	rest := words[i+1:]
	switch name {
	case "rm":
		return matchRM(rest)
	case "find":
		if r, ok := matchFind(rest); ok {
			return r, true
		}
	case "chmod", "chown", "chgrp":
		return matchPerm(name, rest)
	case "mkfs", "wipefs", "blkdiscard", "shred":
		if aimsAtDisk(rest) {
			return block("raw-disk", name+" aimed at a disk"), true
		}
	default:
		if strings.HasPrefix(name, "mkfs.") && aimsAtDisk(rest) {
			return block("raw-disk", name+" aimed at a disk"), true
		}
	}
	if name == "dd" {
		for _, w := range rest {
			if strings.HasPrefix(w, "of=") && isSystemDisk(strings.TrimPrefix(w, "of=")) {
				return block("raw-disk", "dd writing a system disk"), true
			}
		}
	}
	if name == "tee" {
		if r, ok := matchTee(rest); ok {
			return r, true
		}
	}
	// recursive inline scripts, including a catch from the inner script
	if script, ok := inlineScript(name, rest); ok {
		script = strings.TrimPrefix(script, "\x00")
		if r, ok := fedPayload(script); ok {
			return r, true
		}
		inner := Scan(script)
		if inner.Action == "hardblock" || inner.Action == "catch" {
			return inner, true
		}
		if r, ok := interpreterPayload(script); ok {
			return r, true
		}
	}
	if code, ok := codePayload(name, rest); ok {
		if r, ok := interpreterPayload(code); ok {
			return r, true
		}
	}
	if name == "python" || name == "python3" || name == "python2" {
		if s, ok := flagArg(rest, "-c"); ok {
			s = strings.TrimPrefix(s, "\x00")
			// rmtree("/") is the same non-approvable block as rm -rf /.
			// A home or /root guess stays approvable; it can be a false positive.
			if slashRmtree(s) {
				return block("rmtree", "python rmtree of /"), true
			}
			if obviousRmtree(s) {
				return blockHeuristic("rmtree", "python rmtree of a filesystem root or home"), true
			}
		}
	}
	return Result{}, false
}

func matchRM(rest []string) (Result, bool) {
	rec, force := false, false
	var ops []string
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		if w == "--" {
			ops = append(ops, rest[i+1:]...)
			break
		}
		if strings.HasPrefix(w, "--") {
			switch w {
			case "--recursive", "--force", "--no-preserve-root":
				if w == "--recursive" {
					rec = true
				}
				if w == "--force" || w == "--no-preserve-root" {
					force = true
				}
			}
			continue
		}
		if strings.HasPrefix(w, "-") && len(w) > 1 && !strings.HasPrefix(w, "-/") {
			for _, c := range w[1:] {
				if c == 'r' || c == 'R' {
					rec = true
				}
				if c == 'f' {
					force = true
				}
			}
			continue
		}
		ops = append(ops, w)
	}
	if !(rec && force) && !force {
		// rm -rf is the hard-block form. Recursive without force is still catastrophic
		// for these exact targets; require recursive.
	}
	if !rec {
		return Result{}, false
	}
	// -rf or -r -f or --recursive --force, or recursive alone on these targets.
	_ = force
	// A sweep of every top-level directory is /, not one system directory.
	// One directory, or a shorter list, stays an approvable catch below.
	if wholeRoot(ops) {
		return block("rm-root", "rm -rf of the top-level directories"), true
	}
	for _, op := range ops {
		// A quoted "~" or '$HOME' is a literal name. Bash does not expand it.
		if strings.HasPrefix(op, "\x00") {
			continue
		}
		if root, ok := rootishDelete(op); ok {
			return block("rm-root", "rm -rf of "+root), true
		}
		switch strings.TrimSpace(op) {
		case "/", "/*", "~", "~/", "$HOME", "${HOME}":
			return block("rm-root", "rm -rf of / or a home directory"), true
		case ".*", "./.*":
			return block("rm-dot-star", "rm -rf of .*"), true
		}
		if op == `"$HOME"` {
			return block("rm-root", "rm -rf of a home directory"), true
		}
		if systemDirNode(strings.TrimPrefix(op, "\x00")) {
			return catchCase("system-dir", "recursive delete of a system directory"), true
		}
		if rec && sensitiveGlob(op) {
			return catchCase("glob-delete", "recursive delete of a glob under a home or sensitive tree"), true
		}
		if rec && dirGlobCatch(op) {
			return catchCase("glob-delete", "recursive delete of a directory glob"), true
		}
	}
	if rec && weightedHomeOperands(ops) {
		return catchCase("bulk", "recursive delete of several directories in a home or sensitive tree"), true
	}
	return Result{}, false
}

// matchFind hard-blocks an unfiltered find -delete of / or a home directory.
// A depth limit together with a name, path, or type test deletes matches,
// not the directory node, so that search is an approvable catch.
func matchFind(rest []string) (Result, bool) {
	depth := false
	gated := false
	scoped := false
	unguarded := false
	var roots []string
	for i := 0; i < len(rest); i++ {
		w := strings.TrimPrefix(rest[i], "\x00")
		switch w {
		case "-delete":
			if depth && gated {
				scoped = true
			} else {
				unguarded = true
			}
		case "-exec", "-execdir", "-ok", "-okdir":
			if i+1 < len(rest) && base(strings.TrimPrefix(rest[i+1], "\x00")) == "rm" {
				if depth && gated {
					scoped = true
				} else {
					unguarded = true
				}
			}
		case "-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-wholename", "-iwholename", "-type", "-xtype":
			gated = true
			if i+1 < len(rest) {
				i++
			}
		case "-maxdepth", "-mindepth":
			if w == "-maxdepth" {
				depth = true
			}
			if i+1 < len(rest) {
				i++
			}
		default:
			if w == "" || strings.HasPrefix(w, "-") || w == "(" || w == ")" || w == ";" || w == "+" || w == "!" || w == "-o" || w == "-a" {
				continue
			}
			roots = append(roots, w)
		}
	}
	if !scoped && !unguarded {
		return Result{}, false
	}
	home, slash := false, false
	for _, r := range roots {
		if strings.HasPrefix(r, "\x00") {
			continue
		}
		switch strings.TrimSpace(r) {
		case "/", "/*":
			slash = true
		case "~", "~/", "$HOME", "${HOME}":
			home = true
		default:
			if expanded, ok := rootishDelete(r); ok {
				if expanded == "/" || expanded == "/*" {
					slash = true
				} else {
					home = true
				}
			}
		}
	}
	if !home && !slash {
		return Result{}, false
	}
	// -maxdepth is global, but a delete that runs before any filter still
	// removes every entry it reaches. That is the directory, not the matches.
	if unguarded || !scoped {
		return block("rm-root", "find -delete of / or a home directory"), true
	}
	return catchCase("find-scoped", "find -delete limited by depth and a name or type test"), true
}

// rootishDelete is what a command substitution would expand to when that
// text is /, /*, or a home directory. Quoted literal tildes are not.
func rootishDelete(w string) (string, bool) {
	expanded, ok := replaceSubsts(strings.TrimPrefix(w, "\x00"))
	if !ok {
		return "", false
	}
	expanded = strings.TrimSpace(expanded)
	switch expanded {
	case "/", "/*", "~", "~/", "$HOME", "${HOME}":
		return expanded, true
	}
	// $(echo /)/* is concatenated as //* . That is still every top-level name.
	if strings.HasPrefix(expanded, "/") {
		rest := strings.TrimLeft(expanded, "/")
		if rest == "" || rest == "*" || strings.HasPrefix(rest, "*") {
			if rest == "" {
				return "/", true
			}
			return "/*", true
		}
	}
	return "", false
}

// replaceSubsts rewrites one echo or printf substitution. The bool is false
// when the word has no substitution.
func replaceSubsts(w string) (string, bool) {
	inner, rest, ok := takeSubst(w)
	if !ok {
		return w, false
	}
	cmds := commandWords(inner)
	if len(cmds) == 0 {
		return w, false
	}
	produced, ok := pipeScript(cmds[0].words)
	if !ok {
		return w, false
	}
	return produced + rest, true
}

// takeSubst splits a leading $(...) or `...` from the rest of the word.
func takeSubst(w string) (inner, rest string, ok bool) {
	if strings.HasPrefix(w, "$(") {
		end := skipSubst(w, 0)
		if end <= 2 || end > len(w) {
			return "", "", false
		}
		return w[2 : end-1], w[end:], true
	}
	if len(w) >= 2 && w[0] == '`' {
		j := 1
		for j < len(w) {
			if w[j] == '\\' && j+1 < len(w) {
				j += 2
				continue
			}
			if w[j] == '`' {
				return w[1:j], w[j+1:], true
			}
			j++
		}
	}
	return "", "", false
}

// rmFollowsRoot hard-blocks rm -rf of a symlink that follows to /.
// A trailing slash or a final . or .. follows the link. The bare link does not.
// The literal operand / stays on the matchRM path. This one has no catch id.
func rmFollowsRoot(words []string, st shellState) (Result, bool) {
	i := commandStart(words)
	if i >= len(words) || base(words[i]) != "rm" {
		return Result{}, false
	}
	rec := false
	var ops []string
	for _, w := range words[i+1:] {
		if w == "--" {
			continue
		}
		if strings.HasPrefix(w, "--") {
			if w == "--recursive" {
				rec = true
			}
			continue
		}
		if strings.HasPrefix(w, "-") && len(w) > 1 && !strings.HasPrefix(w, "-/") {
			for _, c := range w[1:] {
				if c == 'r' || c == 'R' {
					rec = true
				}
			}
			continue
		}
		ops = append(ops, w)
	}
	if !rec {
		return Result{}, false
	}
	for _, op := range ops {
		if strings.HasPrefix(op, "\x00") {
			continue
		}
		// A glob is not one symlink. Collapsing "*" onto a parent that
		// points at / would hard-block a project directory glob.
		// ${name:?} is not a glob; the ? is bash's unset check.
		if shellGlob(op) {
			continue
		}
		if strings.Contains(op, "$") || strings.Contains(op, "~") {
			if expandedRoot(op, st) {
				return block("rm-root", "rm -rf of / or a home directory"), true
			}
		}
		if !operandFollowsSlash(op) {
			continue
		}
		if followedRoot(op, st) {
			return block("rm-root", "rm -rf of / or a home directory"), true
		}
	}
	return Result{}, false
}

func operandFollowsSlash(op string) bool {
	if op == "" || op == "/" || op == "/*" {
		return false
	}
	if strings.HasSuffix(op, "/") {
		return true
	}
	if i := strings.LastIndex(op, "/"); i >= 0 {
		last := op[i+1:]
		return last == "." || last == ".."
	}
	return false
}

func expandedRoot(op string, st shellState) bool {
	p := expandBashWord(op, st)
	if p == "" || strings.HasPrefix(p, "\x00") {
		return false
	}
	if !filepath.IsAbs(p) {
		base := st.cwd
		if base == "" {
			base, _ = os.Getwd()
		}
		p = filepath.Join(base, p)
	}
	real := evalPath(filepath.Clean(p))
	if real == "/" {
		return true
	}
	home := st.home
	if home == "" {
		home = loginHome()
	}
	return home != "" && real == filepath.Clean(home)
}

func followedRoot(op string, st shellState) bool {
	p := expandBashWord(op, st)
	if p == "" || strings.HasPrefix(p, "\x00") {
		return false
	}
	if !filepath.IsAbs(p) {
		base := st.cwd
		if base == "" {
			base, _ = os.Getwd()
		}
		p = filepath.Join(base, p)
	}
	// Clean drops the trailing slash. EvalSymlinks then follows, which is
	// what rm does for a directory operand and not for a bare link.
	real := evalPath(filepath.Clean(p))
	return real == "/"
}

func matchPerm(name string, rest []string) (Result, bool) {
	rec := false
	mode := ""
	var ops []string
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		if w == "--" {
			ops = append(ops, rest[i+1:]...)
			break
		}
		if w == "-R" || w == "-r" || w == "--recursive" {
			rec = true
			continue
		}
		if strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--") && len(w) > 1 {
			for _, c := range w[1:] {
				if c == 'R' || c == 'r' {
					rec = true
				}
			}
			// chmod -R755 is uncommon; a numeric mode is an operand
			if name == "chmod" && isMode(w) {
				mode = w
			}
			continue
		}
		if name == "chmod" && mode == "" && isMode(w) {
			mode = w
			continue
		}
		ops = append(ops, w)
	}
	if !rec {
		return Result{}, false
	}
	for _, op := range ops {
		if strings.HasPrefix(op, "\x00") {
			continue
		}
		if _, ok := rootishDelete(op); ok {
			return block("perm-root", name+" -R of /"), true
		}
		switch op {
		case "/", "/*", "~", "~/", "$HOME", "${HOME}", ".*", "./.*":
			if mode == "777" || mode == "000" || mode == "0777" || mode == "0000" {
				return block("chmod-root", name+" -R "+mode+" of /"), true
			}
			return block("perm-root", name+" -R of "+op), true
		}
	}
	if (mode == "777" || mode == "000" || mode == "0777" || mode == "0000") && len(ops) > 0 {
		for _, op := range ops {
			if op == "/" || op == "/*" {
				return block("chmod-root", name+" -R "+mode+" of /"), true
			}
		}
	}
	return Result{}, false
}

func isMode(w string) bool {
	if w == "" {
		return false
	}
	for _, c := range w {
		if c < '0' || c > '7' {
			if c == '+' || c == '-' || c == '=' || c == 'u' || c == 'g' || c == 'o' || c == 'a' || c == 'r' || c == 'w' || c == 'x' || c == 'X' || c == 's' || c == 't' {
				continue
			}
			return false
		}
	}
	return true
}

func aimsAtDisk(rest []string) bool {
	for _, w := range rest {
		if w == "--" {
			continue
		}
		if strings.HasPrefix(w, "-") && w != "-" {
			continue
		}
		if isSystemDisk(w) {
			return true
		}
	}
	return false
}

// readRedirectOperand reads one redirect word, including mixed quotes
// such as ~/".bashrc" and "$HOME/.bashrc".
func readRedirectOperand(s string, i int) (string, int) {
	if i >= len(s) {
		return "", i
	}
	start := i
	for i < len(s) {
		c := s[i]
		if c == '\'' || c == '"' || (c == '$' && i+1 < len(s) && s[i+1] == '\'') {
			i = skipBashQuote(s, i)
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' || c == ';' || c == '&' || c == '|' || c == '<' || c == '>' || c == '(' || c == ')' {
			break
		}
		i++
	}
	return s[start:i], i
}

func skipBashQuote(s string, i int) int {
	if i >= len(s) {
		return i
	}
	if s[i] == '$' && i+1 < len(s) && s[i+1] == '\'' {
		i += 2
		for i < len(s) && s[i] != '\'' {
			if s[i] == '\\' && i+1 < len(s) {
				i += 2
				continue
			}
			i++
		}
		if i < len(s) {
			i++
		}
		return i
	}
	q := s[i]
	i++
	for i < len(s) && s[i] != q {
		if q == '"' && s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		i++
	}
	if i < len(s) {
		i++
	}
	return i
}

// expandBashWord applies the expansions bash would before open().
// A tilde expands only when it is unquoted at the start of the word.
// $'...' is decoded and then left literal, so $'\x7e' stays a relative name.
// ${HOME:-word} and ${HOME%/} follow bash parameter rules. HOME inside
// ${} is the environment variable, not the passwd directory.
func expandBashWord(s string, st shellState) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	tilde := true
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '\'':
			i++
			for i < len(s) && s[i] != '\'' {
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				i++
			}
			tilde = false
		case c == '"':
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					n := s[i+1]
					if n == '$' || n == '`' || n == '"' || n == '\\' {
						i++
						b.WriteByte(s[i])
						i++
						continue
					}
				}
				if s[i] == '$' {
					v, n, ok := expandDollar(s, i, st)
					if !ok {
						return "\x00"
					}
					b.WriteString(v)
					i = n
					continue
				}
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				i++
			}
			tilde = false
		case c == '$' && i+1 < len(s) && s[i+1] == '\'':
			v, n := ansiCWord(s, i)
			b.WriteString(v)
			i = n
			tilde = false
		case c == '$':
			v, n, ok := expandDollar(s, i, st)
			if !ok {
				// ${name:?} aborts the shell. It does not become an empty path.
				return "\x00"
			}
			b.WriteString(v)
			i = n
			tilde = false
		case tilde && c == '~' && b.Len() == 0:
			if i+1 < len(s) && (s[i+1] == '+' || s[i+1] == '-') {
				next := i + 2
				if next >= len(s) || s[next] == '/' || s[next] == '\'' || s[next] == '"' {
					if s[i+1] == '+' {
						b.WriteString(st.cwd)
					} else if st.old != "" {
						b.WriteString(st.old)
					}
					i += 2
					continue
				}
			}
			nextOK := i+1 >= len(s) || s[i+1] == '/' || s[i+1] == '\'' || s[i+1] == '"'
			if nextOK {
				home := st.home
				if home == "" {
					home = loginHome()
				}
				b.WriteString(home)
				i++
				continue
			}
			b.WriteByte(c)
			i++
			tilde = false
		default:
			b.WriteByte(c)
			i++
			tilde = false
		}
	}
	out := b.String()
	if out == "" {
		return ""
	}
	return filepath.Clean(out)
}

func expandDollar(s string, i int, st shellState) (string, int, bool) {
	if i+1 >= len(s) {
		return "$", i + 1, true
	}
	if s[i+1] == '{' {
		end := strings.IndexByte(s[i+2:], '}')
		if end < 0 {
			return "$", i + 1, true
		}
		body := s[i+2 : i+2+end]
		v, ok := applyParam(body, st)
		if !ok {
			return "", i, false
		}
		return v, i + 2 + end + 1, true
	}
	j := i + 1
	if !isNameStart(s[j]) {
		return "$", i + 1, true
	}
	j++
	for j < len(s) && isNameCont(s[j]) {
		j++
	}
	val, _ := lookupShellVar(s[i+1:j], st)
	return val, j, true
}

func applyParam(body string, st shellState) (string, bool) {
	name, op, pat, ok := splitParam(body)
	if !ok {
		return "", true
	}
	val, set := lookupShellVar(name, st)
	switch op {
	case "":
		return val, true
	case "-":
		if !set {
			got := expandBashWord(pat, st)
			if strings.HasPrefix(got, "\x00") {
				return "", false
			}
			return got, true
		}
		return val, true
	case ":-":
		if !set || val == "" {
			got := expandBashWord(pat, st)
			if strings.HasPrefix(got, "\x00") {
				return "", false
			}
			return got, true
		}
		return val, true
	case "?", ":?":
		// Bash prints an error and does not run the command.
		if !set || (op == ":?" && val == "") {
			return "", false
		}
		return val, true
	case "%":
		return trimAffix(val, pat, false, false), true
	case "%%":
		return trimAffix(val, pat, false, true), true
	case "#":
		return trimAffix(val, pat, true, false), true
	case "##":
		return trimAffix(val, pat, true, true), true
	default:
		return val, true
	}
}

func splitParam(body string) (name, op, pat string, ok bool) {
	if body == "" {
		return "", "", "", false
	}
	i := 0
	if !isNameStart(body[0]) {
		return "", "", "", false
	}
	i++
	for i < len(body) && isNameCont(body[i]) {
		i++
	}
	name = body[:i]
	rest := body[i:]
	switch {
	case rest == "":
		return name, "", "", true
	case strings.HasPrefix(rest, ":?"):
		return name, ":?", rest[2:], true
	case strings.HasPrefix(rest, "?"):
		return name, "?", rest[1:], true
	case strings.HasPrefix(rest, ":-"):
		return name, ":-", rest[2:], true
	case strings.HasPrefix(rest, "-"):
		return name, "-", rest[1:], true
	case strings.HasPrefix(rest, "%%"):
		return name, "%%", rest[2:], true
	case strings.HasPrefix(rest, "%"):
		return name, "%", rest[1:], true
	case strings.HasPrefix(rest, "##"):
		return name, "##", rest[2:], true
	case strings.HasPrefix(rest, "#"):
		return name, "#", rest[1:], true
	default:
		return name, "", "", true
	}
}

func trimAffix(val, pat string, prefix, longest bool) string {
	if pat == "" || val == "" {
		return val
	}
	if prefix {
		if strings.HasPrefix(val, pat) {
			return strings.TrimPrefix(val, pat)
		}
		return val
	}
	if strings.HasSuffix(val, pat) {
		return strings.TrimSuffix(val, pat)
	}
	_ = longest
	return val
}

func lookupShellVar(name string, st shellState) (string, bool) {
	switch name {
	case "HOME":
		if v, ok := os.LookupEnv("HOME"); ok {
			return v, true
		}
		return "", false
	case "PWD":
		if st.cwd != "" {
			return st.cwd, true
		}
	case "OLDPWD":
		if st.old != "" {
			return st.old, true
		}
	}
	v, ok := os.LookupEnv(name)
	return v, ok
}

// hideQuotes blanks quoted spans so a bomb written as data is not a command.
func hideQuotes(s string) string {
	var b strings.Builder
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inS:
			if c == '\'' {
				inS = false
			}
			b.WriteByte(' ')
		case inD:
			if c == '\\' && i+1 < len(s) {
				b.WriteByte(' ')
				i++
				b.WriteByte(' ')
				continue
			}
			if c == '"' {
				inD = false
			}
			b.WriteByte(' ')
		case c == '\'':
			inS = true
			b.WriteByte(' ')
		case c == '"':
			inD = true
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isNameCont(c byte) bool {
	return isNameStart(c) || (c >= '0' && c <= '9')
}

func ansiCWord(s string, i int) (string, int) {
	// s[i] is $ and s[i+1] is '
	j := i + 2
	var body strings.Builder
	for j < len(s) {
		if s[j] == '\\' && j+1 < len(s) {
			j++
			switch s[j] {
			case 'x', 'X':
				if j+2 < len(s) && isHex(s[j+1]) && isHex(s[j+2]) {
					body.WriteByte(unhex(s[j+1])<<4 | unhex(s[j+2]))
					j += 3
					continue
				}
			case 'n':
				body.WriteByte('\n')
				j++
				continue
			case 't':
				body.WriteByte('\t')
				j++
				continue
			default:
				if s[j] >= '0' && s[j] <= '7' {
					n := 0
					k := 0
					for k < 3 && j < len(s) && s[j] >= '0' && s[j] <= '7' {
						n = n*8 + int(s[j]-'0')
						j++
						k++
					}
					body.WriteByte(byte(n))
					continue
				}
				body.WriteByte(s[j])
				j++
				continue
			}
		}
		if s[j] == '\'' {
			j++
			break
		}
		body.WriteByte(s[j])
		j++
	}
	return body.String(), j
}

func isSystemDisk(p string) bool {
	p = strings.TrimSpace(p)
	switch {
	case strings.HasPrefix(p, "/dev/sd"), strings.HasPrefix(p, "/dev/hd"),
		strings.HasPrefix(p, "/dev/nvme"),
		strings.HasPrefix(p, "/dev/mmcblk"), strings.HasPrefix(p, "/dev/vd"),
		strings.HasPrefix(p, "/dev/xvd"), strings.HasPrefix(p, "/dev/mapper/"),
		strings.HasPrefix(p, "/dev/disk/"):
		return true
	default:
		return false
	}
}

// obviousRmtree is true only when rmtree or unlink is aimed at a filesystem
// root or a home directory. A non-root path that merely contains '/' is not.
func obviousRmtree(s string) bool {
	l := strings.ToLower(s)
	if !strings.Contains(l, "rmtree") && !strings.Contains(l, "unlink") {
		return false
	}
	for _, arg := range callArgs(s, "rmtree", "unlink") {
		if rootishPath(arg) {
			return true
		}
	}
	return false
}

func callArgs(s string, names ...string) []string {
	var out []string
	low := strings.ToLower(s)
	for _, name := range names {
		from := 0
		needle := strings.ToLower(name) + "("
		for {
			j := strings.Index(low[from:], needle)
			if j < 0 {
				break
			}
			j += from + len(needle)
			arg, next := firstCallArg(s, j)
			if arg != "" {
				out = append(out, arg)
			}
			if next <= from {
				break
			}
			from = next
		}
	}
	return out
}

func firstCallArg(s string, i int) (string, int) {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n') {
		i++
	}
	if i >= len(s) {
		return "", i
	}
	if s[i] == '\'' || s[i] == '"' {
		q := s[i]
		i++
		start := i
		for i < len(s) && s[i] != q {
			if s[i] == '\\' && i+1 < len(s) {
				i += 2
				continue
			}
			i++
		}
		arg := s[start:i]
		if i < len(s) {
			i++
		}
		return arg, i
	}
	start := i
	depth := 0
	for i < len(s) {
		switch s[i] {
		case '\'', '"':
			q := s[i]
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				i++
			}
		case '(':
			depth++
		case ')':
			if depth == 0 {
				return strings.TrimSpace(s[start:i]), i
			}
			depth--
		case ',':
			if depth == 0 {
				return strings.TrimSpace(s[start:i]), i
			}
		}
		if i < len(s) {
			i++
		}
	}
	return strings.TrimSpace(s[start:i]), i
}

func slashRmtree(s string) bool {
	if !strings.Contains(strings.ToLower(s), "rmtree") {
		return false
	}
	for _, arg := range callArgs(s, "rmtree") {
		a := strings.TrimSpace(arg)
		a = strings.Trim(a, `"'`)
		if strings.TrimSpace(a) == "/" {
			return true
		}
	}
	return false
}

func rootishPath(arg string) bool {
	a := strings.TrimSpace(arg)
	a = strings.Trim(a, `"'`)
	switch strings.TrimSpace(a) {
	case "/", "/root", "/root/", "/home", "/home/", "~", "~/":
		return true
	}
	low := strings.ToLower(strings.ReplaceAll(arg, " ", ""))
	if strings.Contains(low, `expanduser("~")`) || strings.Contains(low, `expanduser('~')`) {
		return true
	}
	return false
}

func inlineScript(name string, rest []string) (string, bool) {
	var script string
	ok := false
	switch name {
	case "bash", "sh", "dash", "zsh", "ksh":
		script, ok = flagArg(rest, "-c")
	case "perl":
		script, ok = flagArg(rest, "-e")
	case "node", "nodejs":
		script, ok = flagArg(rest, "-e")
	case "mongosh", "mongo":
		script, ok = flagArg(rest, "--eval")
	case "ssh":
		// last non-flag argument is the remote command when there are two operands
		var ops []string
		for _, w := range rest {
			if strings.HasPrefix(w, "-") {
				continue
			}
			ops = append(ops, w)
		}
		if len(ops) >= 2 {
			script, ok = ops[len(ops)-1], true
		}
	}
	if !ok {
		return "", false
	}
	// A quoted script that contains ~ or $ is marked so rm treats "~" as a
	// literal name. The mark is not part of the script the inner shell runs.
	return strings.TrimPrefix(script, "\x00"), true
}

func flagArg(rest []string, flag string) (string, bool) {
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		if w == flag && i+1 < len(rest) {
			return rest[i+1], true
		}
		if strings.HasPrefix(w, flag+"=") {
			return strings.TrimPrefix(w, flag+"="), true
		}
		if flag == "-c" && strings.HasPrefix(w, "-") && strings.Contains(w, "c") && !strings.HasPrefix(w, "--") && i+1 < len(rest) {
			return rest[i+1], true
		}
	}
	return "", false
}

func skipSudoFlags(words []string, i int) int {
	for i < len(words) {
		w := words[i]
		if w == "--" {
			return i + 1
		}
		if !strings.HasPrefix(w, "-") {
			return i
		}
		if takes, ok := sudoTakes(w); ok && takes && !strings.Contains(w, "=") && i+1 < len(words) {
			i += 2
			continue
		}
		i++
	}
	return i
}

func sudoTakes(w string) (bool, bool) {
	switch w {
	case "-u", "-g", "-p", "-C", "-D", "-h", "-U", "-T", "-r", "-t", "-R", "--user", "--group", "--prompt":
		return true, true
	default:
		if strings.HasPrefix(w, "--") {
			return false, true
		}
		return false, true
	}
}

func skipWrapperFlags(name string, words []string, i int) int {
	switch name {
	case "timeout":
		return skipTimeout(words, i)
	case "nice":
		return skipOpts(words, i, map[string]bool{"-n": true, "--adjustment": true})
	case "ionice":
		return skipOpts(words, i, map[string]bool{"-c": true, "-n": true, "-p": true, "-t": true})
	case "stdbuf":
		return skipOpts(words, i, map[string]bool{"-i": true, "-o": true, "-e": true, "--input": true, "--output": true, "--error": true})
	case "flock":
		return skipFlock(words, i)
	case "watch":
		// -n takes the interval. -d does not take the command that follows.
		return skipOpts(words, i, map[string]bool{"-n": true, "--interval": true, "-e": true, "--errexit": true})
	default:
		// setsid, nohup: flags only, then the command.
		return skipOpts(words, i, nil)
	}
}

func isAssign(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	for _, r := range w[:eq] {
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func base(w string) string {
	w = strings.TrimSpace(w)
	if i := strings.LastIndex(w, "/"); i >= 0 {
		w = w[i+1:]
	}
	return w
}

// bomb detects a function that forks by calling itself, and that is actually
// invoked afterward. A definition alone is not a bomb. "function name" is a
// definition. A pipe of the function to itself forks even without &.
// Bash allows a space before () and a function named ".".
func literalOperand(w string, quote byte) string {
	// Quoting does not change /. It does stop ~, and single quotes also stop $.
	switch quote {
	case '\'':
		if strings.Contains(w, "~") || strings.Contains(w, "$") {
			return "\x00" + w
		}
	case '"':
		if strings.Contains(w, "~") && !strings.Contains(w, "$") {
			return "\x00" + w
		}
	}
	return w
}

func bomb(s string) bool {
	// Heredoc and herestring bodies are data unless a shell is reading them.
	// Those shell bodies are judged separately, so they are not bombs twice.
	plain := hideQuotes(dropHereBodies(stripComments(s)))
	type fn struct {
		name string
		body string
	}
	var fns []fn
	defined := map[string]bool{}
	i := 0
	for i < len(plain) {
		name, body, next, ok := nextFunc(plain, i)
		if !ok {
			break
		}
		fns = append(fns, fn{name, body})
		defined[name] = true
		if next <= i {
			break
		}
		i = next
	}
	if len(fns) == 0 {
		return false
	}
	visible := blankBodies(plain)
	invokedFn := map[string]bool{}
	graph := map[string][]string{}
	for _, f := range fns {
		if invoked(f.name, visible) {
			invokedFn[f.name] = true
		}
		seenEdge := map[string]bool{}
		var edges []string
		add := func(t string) {
			if t == "" || !defined[t] || seenEdge[t] {
				return
			}
			seenEdge[t] = true
			edges = append(edges, t)
		}
		for _, t := range forkTargets(f.body) {
			add(t)
			if t == f.name && invokedFn[f.name] {
				return true
			}
		}
		// A plain call to another function is an edge. An invoked x/y
		// cycle is a bomb even when neither side pipes to itself.
		// A function that only calls itself, without a fork, is not.
		for _, t := range callTargets(f.body) {
			if t == f.name {
				continue
			}
			add(t)
		}
		graph[f.name] = edges
	}
	return cycleInvoked(graph, defined, invokedFn)
}

// fedCode judges eval strings and code a shell reads from a pipe, a
// heredoc, or a herestring. Quoted bomb text that is only printed stays data.
func fedCode(command string) (Result, bool) {
	if r, ok := dynamicFeed(command); ok {
		return r, true
	}
	cmds := commandWords(command)
	for i, c := range cmds {
		if script, ok := evalScript(c.words, c.raws); ok {
			if r, hit := asCode(script); hit {
				return r, true
			}
		}
		if c.stdinCode != "" && shellReadsStdin(c.words) {
			if r, hit := asCode(c.stdinCode); hit {
				return r, true
			}
		}
		if c.stop == "|" && i+1 < len(cmds) && bareShell(cmds[i+1].words) {
			if c.hereBody != "" && feedsStdin(c.words) {
				if r, hit := asCode(c.hereBody); hit {
					return r, true
				}
			}
			if script, ok := pipeScript(c.words); ok {
				if r, hit := asCode(script); hit {
					return r, true
				}
			}
		}
	}
	return Result{}, false
}

func asCode(script string) (Result, bool) {
	script = strings.TrimSpace(strings.TrimPrefix(script, "\x00"))
	if script == "" {
		return Result{}, false
	}
	if bomb(script) {
		return block("fork bomb", "a function that pipes or backgrounds a call to itself"), true
	}
	inner := Scan(script)
	if inner.Action == "hardblock" || inner.Action == "catch" {
		return inner, true
	}
	return Result{}, false
}

func evalScript(words, raws []string) (string, bool) {
	i := commandStart(words)
	if i >= len(words) || base(words[i]) != "eval" {
		return "", false
	}
	script, ok := joinCode(words[i+1:])
	if !ok {
		return "", false
	}
	// The raw spelling still has the quotes around an echoed bomb.
	// The parsed words do not, so a pipe inside those quotes would split.
	rawScript := script
	if len(raws) == len(words) {
		if joined, ok := joinCode(raws[i+1:]); ok {
			rawScript = joined
		}
	}
	trySubst := func(s string) (string, bool) {
		inner, ok := commandSubst(s)
		if !ok {
			return "", false
		}
		cmds := commandWords(inner)
		if len(cmds) == 1 {
			if produced, ok := pipeScript(cmds[0].words); ok && strings.TrimSpace(produced) != "" {
				return produced, true
			}
		}
		return inner, true
	}
	if s, ok := trySubst(rawScript); ok {
		return s, true
	}
	if s, ok := trySubst(script); ok {
		return s, true
	}
	return script, true
}

// commandStart skips assignments and wrappers so `command eval` and
// `env FOO=1 eval` are still eval.
func commandStart(words []string) int {
	i := 0
	for i < len(words) {
		w := words[i]
		if isAssign(w) {
			i++
			continue
		}
		switch base(strings.Trim(w, "\"'`")) {
		case "command", "builtin", "nocorrect":
			// command -p does not take the next word. sudo -p does.
			i++
			for i < len(words) {
				f := words[i]
				if f == "--" {
					i++
					break
				}
				if strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "-/") {
					i++
					continue
				}
				break
			}
			continue
		case "sudo", "doas":
			i++
			i = skipSudoFlags(words, i)
			continue
		case "exec":
			i++
			for i < len(words) {
				f := words[i]
				if f == "-a" && i+1 < len(words) {
					i += 2
					continue
				}
				if strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "-/") {
					i++
					continue
				}
				break
			}
			continue
		case "{", "}":
			// A brace group runs its body. The brace is not the command.
			i++
			continue
		case "coproc":
			i++
			if i < len(words) && words[i] != "{" && !strings.HasPrefix(words[i], "-") {
				if i+1 < len(words) && words[i+1] == "{" {
					i++
				}
			}
			if i < len(words) && words[i] == "{" {
				i++
			}
			continue
		case "timeout", "nice", "ionice", "setsid", "nohup", "flock", "watch", "stdbuf":
			name := base(strings.Trim(w, "\"'`"))
			i++
			i = skipWrapperFlags(name, words, i)
			continue
		case "env":
			i++
			for i < len(words) {
				e := words[i]
				if isAssign(e) {
					i++
					continue
				}
				if e == "--" {
					i++
					break
				}
				if strings.HasPrefix(e, "-") {
					if (e == "-u" || e == "-C" || e == "--unset" || e == "--chdir") && i+1 < len(words) {
						i += 2
						continue
					}
					i++
					continue
				}
				break
			}
			continue
		default:
			return i
		}
	}
	return i
}

func commandSubst(s string) (string, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "\x00"))
	if len(s) >= 3 && s[0] == '$' && s[1] == '(' && s[len(s)-1] == ')' {
		return s[2 : len(s)-1], true
	}
	if len(s) >= 2 && s[0] == '`' && s[len(s)-1] == '`' {
		return s[1 : len(s)-1], true
	}
	return "", false
}

// pipeScript is the text echo or printf would write into a shell.
func pipeScript(words []string) (string, bool) {
	if s, ok := echoScript(words); ok {
		return s, true
	}
	i := commandStart(words)
	if i >= len(words) || base(words[i]) != "printf" {
		return "", false
	}
	var parts []string
	for _, w := range words[i+1:] {
		w = strings.TrimPrefix(w, "\x00")
		if w == "--" || (strings.HasPrefix(w, "-") && w != "-") {
			continue
		}
		parts = append(parts, w)
	}
	if len(parts) == 0 {
		return "", false
	}
	format := decodePrintf(parts[0])
	args := parts[1:]
	if strings.Contains(parts[0], "%") && len(args) > 0 {
		return decodePrintf(printfApply(parts[0], args)), true
	}
	return format, true
}

// decodePrintf turns printf's \n and \t into the characters bash's printf writes.
func decodePrintf(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '\\', '\'', '"':
			b.WriteByte(s[i])
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// printfApply substitutes %s and %% and keeps other format text.
func printfApply(format string, args []string) string {
	var b strings.Builder
	ai := 0
	for i := 0; i < len(format); i++ {
		if format[i] != '%' || i+1 >= len(format) {
			b.WriteByte(format[i])
			continue
		}
		i++
		switch format[i] {
		case '%':
			b.WriteByte('%')
		case 's':
			if ai < len(args) {
				b.WriteString(args[ai])
				ai++
			}
		default:
			if ai < len(args) {
				ai++
			}
		}
	}
	return b.String()
}

// feedsStdin reports a command that copies its heredoc to the next stage.
func feedsStdin(words []string) bool {
	i := commandStart(words)
	if i >= len(words) {
		return false
	}
	switch base(words[i]) {
	case "cat", "tee":
		return true
	default:
		return false
	}
}

func echoScript(words []string) (string, bool) {
	i := 0
	for i < len(words) && isAssign(words[i]) {
		i++
	}
	if i >= len(words) || base(words[i]) != "echo" {
		return "", false
	}
	i++
	for i < len(words) && words[i] != "--" && strings.HasPrefix(words[i], "-") {
		i++
	}
	if i < len(words) && words[i] == "--" {
		i++
	}
	return joinCode(words[i:])
}

func joinCode(words []string) (string, bool) {
	if len(words) == 0 {
		return "", false
	}
	parts := make([]string, len(words))
	for i, w := range words {
		parts[i] = strings.TrimPrefix(w, "\x00")
	}
	return strings.Join(parts, " "), true
}

func bareShell(words []string) bool {
	i := 0
	for i < len(words) && isAssign(words[i]) {
		i++
	}
	if i >= len(words) {
		return false
	}
	switch base(words[i]) {
	case "bash", "sh", "dash", "zsh", "ksh":
	default:
		return false
	}
	for _, w := range words[i+1:] {
		w = strings.TrimPrefix(w, "\x00")
		if w == "-c" || w == "--command" {
			return false
		}
		if strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--") && strings.Contains(w, "c") {
			return false
		}
	}
	return true
}

func shellReadsStdin(words []string) bool {
	return bareShell(words)
}

func unquoteWord(s string) string {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func forkTargets(body string) []string {
	toks := opTokens(body)
	var out []string
	seen := map[string]bool{}
	add := func(n string) {
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for i := 0; i < len(toks); i++ {
		if !cmdAt(toks, i) {
			continue
		}
		name := toks[i]
		if i+1 < len(toks) && toks[i+1] == "&" {
			add(name)
		}
		if i+2 < len(toks) && (toks[i+1] == "|" || toks[i+1] == "|&") && toks[i+2] == name && cmdAt(toks, i+2) {
			add(name)
		}
	}
	return out
}

// callTargets are command-position names. Arguments are not calls.
func callTargets(body string) []string {
	toks := opTokens(body)
	var out []string
	seen := map[string]bool{}
	for i := 0; i < len(toks); i++ {
		if !cmdAt(toks, i) {
			continue
		}
		name := toks[i]
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

func cycleInvoked(graph map[string][]string, defined, invokedFn map[string]bool) bool {
	color := map[string]int{}
	var stack []string
	var dfs func(string) bool
	dfs = func(n string) bool {
		if !defined[n] {
			return false
		}
		if color[n] == 1 {
			if invokedFn[n] {
				return true
			}
			for i := len(stack) - 1; i >= 0; i-- {
				if invokedFn[stack[i]] {
					return true
				}
				if stack[i] == n {
					break
				}
			}
			return false
		}
		if color[n] == 2 {
			return false
		}
		color[n] = 1
		stack = append(stack, n)
		for _, t := range graph[n] {
			if dfs(t) {
				return true
			}
		}
		stack = stack[:len(stack)-1]
		color[n] = 2
		return false
	}
	for n := range defined {
		if dfs(n) {
			return true
		}
	}
	return false
}

func blankBodies(s string) string {
	b := []byte(s)
	i := 0
	for i < len(s) {
		name, _, next, ok := nextFunc(s, i)
		if !ok {
			break
		}
		rel := strings.Index(s[i:next], name)
		if rel >= 0 {
			start := i + rel
			for j := start; j < next && j < len(b); j++ {
				if b[j] != '\n' {
					b[j] = ' '
				}
			}
		}
		if next <= i {
			break
		}
		i = next
	}
	return string(b)
}

// dropHereBodies blanks heredoc and herestring bodies. A shell that reads
// them is judged from the saved body, so the text is not also a top-level bomb.
func dropHereBodies(s string) string {
	var b strings.Builder
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inS:
			b.WriteByte(c)
			if c == '\'' {
				inS = false
			}
		case inD:
			b.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
				continue
			}
			if c == '"' {
				inD = false
			}
		case c == '\'':
			inS = true
			b.WriteByte(c)
		case c == '"':
			inD = true
			b.WriteByte(c)
		case c == '<' && i+2 < len(s) && s[i+1] == '<' && s[i+2] == '<':
			b.WriteString("<<<")
			i += 3
			for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
				b.WriteByte(s[i])
				i++
			}
			_, next := readRedirectOperand(s, i)
			for j := i; j < next; j++ {
				b.WriteByte(' ')
			}
			if next > i {
				i = next - 1
			}
		case c == '<' && i+1 < len(s) && s[i+1] == '<':
			b.WriteString("<<")
			i += 2
			strip := false
			if i < len(s) && s[i] == '-' {
				strip = true
				b.WriteByte('-')
				i++
			}
			for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
				b.WriteByte(s[i])
				i++
			}
			var delim strings.Builder
			q := byte(0)
			if i < len(s) && (s[i] == '\'' || s[i] == '"') {
				q = s[i]
				b.WriteByte(s[i])
				i++
			}
			for i < len(s) && s[i] != '\n' && (q != 0 || (s[i] != ' ' && s[i] != '\t')) {
				if q != 0 && s[i] == q {
					b.WriteByte(s[i])
					i++
					break
				}
				delim.WriteByte(s[i])
				b.WriteByte(s[i])
				i++
			}
			for i < len(s) && s[i] != '\n' {
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) && s[i] == '\n' {
				b.WriteByte('\n')
				i++
			}
			d := delim.String()
			for i < len(s) {
				lineEnd := strings.IndexByte(s[i:], '\n')
				var line string
				if lineEnd < 0 {
					line = s[i:]
				} else {
					line = s[i : i+lineEnd]
				}
				cmp := line
				if strip {
					cmp = strings.TrimLeft(cmp, " \t")
				}
				if cmp == d {
					b.WriteString(line)
					if lineEnd >= 0 {
						b.WriteByte('\n')
						i += lineEnd + 1
					} else {
						i = len(s)
					}
					break
				}
				for k := 0; k < len(line); k++ {
					b.WriteByte(' ')
				}
				if lineEnd < 0 {
					i = len(s)
					break
				}
				b.WriteByte('\n')
				i += lineEnd + 1
			}
			if i < len(s) && i > 0 {
				i--
			} else if i > 0 {
				i = len(s)
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func nextFunc(s string, from int) (name, body string, next int, ok bool) {
	for i := from; i < len(s); i++ {
		if wordAt(s, i, "function") {
			j := skipSpace(s, i+len("function"))
			nm, j := readFuncName(s, j)
			j = skipSpace(s, j)
			if strings.HasPrefix(s[j:], "()") {
				j = skipSpace(s, j+2)
			}
			if nm != "" && j < len(s) && s[j] == '(' {
				b, end, good := parenBody(s, j)
				if good {
					return nm, b, end, true
				}
			}
			if nm != "" && j < len(s) && s[j] == '{' {
				b, end, good := funcBody(s, j)
				if good {
					return nm, b, end, true
				}
			}
		}
		if i > from && i > 0 && isNameCont(s[i-1]) {
			continue
		}
		nm, j := readFuncName(s, i)
		if nm == "" || nm == "function" {
			continue
		}
		j = skipSpace(s, j)
		if j+1 >= len(s) || s[j] != '(' || s[j+1] != ')' {
			continue
		}
		after := skipSpace(s, j+2)
		if after < len(s) && s[after] == '(' {
			b, end, good := parenBody(s, after)
			if good {
				return nm, b, end, true
			}
		}
		braceAt := strings.Index(s[after:], "{")
		if braceAt < 0 || braceAt > 8 {
			continue
		}
		b, end, good := funcBody(s, after+braceAt)
		if !good {
			return "", "", 0, false
		}
		return nm, b, end, true
	}
	return "", "", 0, false
}

// parenBody is the subshell form f()( body ).
func parenBody(s string, open int) (body string, next int, ok bool) {
	if open >= len(s) || s[open] != '(' {
		return "", open, false
	}
	depth := 0
	inS, inD := false, false
	for i := open; i < len(s); i++ {
		c := s[i]
		switch {
		case inS:
			if c == '\'' {
				inS = false
			}
		case inD:
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '"' {
				inD = false
			}
		case c == '\'':
			inS = true
		case c == '"':
			inD = true
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return s[open+1 : i], i + 1, true
			}
		}
	}
	return "", open, false
}

func funcBody(s string, brace int) (body string, next int, ok bool) {
	if brace >= len(s) || s[brace] != '{' {
		return "", brace, false
	}
	inner := s[brace+1:]
	end := strings.Index(inner, "}")
	if end < 0 {
		return "", brace, false
	}
	return inner[:end], brace + 1 + end + 1, true
}

func wordAt(s string, i int, word string) bool {
	if i < 0 || i+len(word) > len(s) || s[i:i+len(word)] != word {
		return false
	}
	if i > 0 && isNameCont(s[i-1]) {
		return false
	}
	end := i + len(word)
	if end < len(s) && isNameCont(s[end]) {
		return false
	}
	return true
}

func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n') {
		i++
	}
	return i
}

func readFuncName(s string, i int) (string, int) {
	if i >= len(s) {
		return "", i
	}
	j := i
	for j < len(s) {
		r := rune(s[j])
		if r == '_' || r == ':' || r == '.' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			j++
			continue
		}
		break
	}
	return s[i:j], j
}

// invoked reports a later command-position call. ": f" and "echo f" are not calls.
func invoked(name, after string) bool {
	if name == "" {
		return false
	}
	toks := opTokens(stripQuotes(after))
	for i := 0; i < len(toks); i++ {
		if toks[i] != name || !cmdAt(toks, i) {
			continue
		}
		if i > 0 && toks[i-1] == "function" {
			continue
		}
		return true
	}
	return false
}

// forksSelf is true when the function is the command on both sides of a
// pipe, or when it backgrounds itself. An argument that happens to equal
// the name is not a call. The pipe forks even without a trailing &.
func forksSelf(name, body string) bool {
	if name == "" {
		return false
	}
	toks := opTokens(body)
	for i := 0; i < len(toks); i++ {
		if toks[i] != name || !cmdAt(toks, i) {
			continue
		}
		if i+1 < len(toks) && toks[i+1] == "&" {
			return true
		}
		if i+2 < len(toks) && toks[i+1] == "|" && toks[i+2] == name && cmdAt(toks, i+2) {
			return true
		}
		if i+2 < len(toks) && toks[i+1] == "|&" && toks[i+2] == name && cmdAt(toks, i+2) {
			return true
		}
	}
	return false
}

func cmdAt(toks []string, i int) bool {
	if i == 0 {
		return true
	}
	switch toks[i-1] {
	case "|", "&", "|&", "&&", "||", ";":
		return true
	default:
		return false
	}
}

func opTokens(s string) []string {
	var out []string
	var w strings.Builder
	flush := func() {
		if w.Len() == 0 {
			return
		}
		out = append(out, w.String())
		w.Reset()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case ' ', '\t', '\n', '(', ')':
			flush()
		case '{':
			// ${...} is a parameter, not a brace group. A brace group runs now.
			if i > 0 && s[i-1] == '$' {
				w.WriteByte(c)
				continue
			}
			flush()
		case '}':
			flush()
		case ';':
			flush()
			out = append(out, ";")
		case '|':
			flush()
			if i+1 < len(s) && s[i+1] == '|' {
				out = append(out, "||")
				i++
			} else if i+1 < len(s) && s[i+1] == '&' {
				out = append(out, "|&")
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

// stripComments drops # comments that start a word. $# and ${#} stay.
func stripComments(s string) string {
	var b strings.Builder
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inS:
			b.WriteByte(c)
			if c == '\'' {
				inS = false
			}
		case inD:
			b.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
				continue
			}
			if c == '"' {
				inD = false
			}
		case c == '\'':
			inS = true
			b.WriteByte(c)
		case c == '"':
			inD = true
			b.WriteByte(c)
		case c == '#' && commentStart(s, i):
			for i < len(s) && s[i] != '\n' {
				i++
			}
			if i < len(s) {
				b.WriteByte('\n')
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func commentStart(s string, i int) bool {
	if i == 0 {
		return true
	}
	p := s[i-1]
	return p == ' ' || p == '\t' || p == '\n' || p == ';' || p == '&' || p == '|' || p == '(' || p == '{'
}

func stripQuotes(s string) string {
	var b strings.Builder
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inS:
			if c == '\'' {
				inS = false
			}
		case inD:
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '"' {
				inD = false
			}
		case c == '\'':
			inS = true
		case c == '"':
			inD = true
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

const bulkTargets = 100

// pipelineRisk counts find | xargs rm and treats ls / piped into
// xargs rm -rf as a root wipe, whether the middle stage is sed or awk.
func pipelineRisk(command string, st shellState) (Result, bool) {
	cmds := commandWords(command)
	var group []scannedCmd
	flush := func() (Result, bool) {
		if len(group) < 2 {
			group = nil
			return Result{}, false
		}
		r, ok := judgePipe(group, st)
		group = nil
		return r, ok
	}
	for _, c := range cmds {
		if c.openSub || c.closeSub || len(c.words) == 0 {
			if r, ok := flush(); ok {
				return r, true
			}
			continue
		}
		group = append(group, c)
		if c.stop != "|" {
			if r, ok := flush(); ok {
				return r, true
			}
		}
	}
	return flush()
}

func judgePipe(group []scannedCmd, st shellState) (Result, bool) {
	for i, c := range group {
		rec, ok := xargsRM(c.words)
		if !ok {
			continue
		}
		sawFind := false
		for _, prev := range group[:i] {
			if base(commandWord(prev.words)) == "find" {
				sawFind = true
				if r, hit := findIntoRM(prev.words, st); hit {
					return r, true
				}
			}
			if rec && lsRoot(prev.words) {
				return block("rm-root", "ls of / piped into xargs rm -rf"), true
			}
		}
		// find already counted its matches. Any other producer, including a
		// literal echo of paths, hands rm a list the command line does not show.
		if sawFind {
			continue
		}
		if r, hit := judgeXargsList(group[:i], c.words, rec); hit {
			return r, true
		}
	}
	return Result{}, false
}

// xargsRM reports an xargs invocation whose utility is rm.
// rec is true when that rm is recursive.
func xargsRM(words []string) (rec bool, ok bool) {
	i := commandStart(words)
	if i >= len(words) || base(words[i]) != "xargs" {
		return false, false
	}
	i++
	for i < len(words) {
		w := words[i]
		if w == "--" {
			i++
			break
		}
		if strings.HasPrefix(w, "-") && w != "-" && !strings.HasPrefix(w, "-/") {
			switch w {
			case "-n", "-I", "-i", "-P", "-s", "-L", "-a", "-E", "-J":
				if i+1 < len(words) {
					i += 2
					continue
				}
			}
			i++
			continue
		}
		break
	}
	if i >= len(words) || base(words[i]) != "rm" {
		return false, false
	}
	for _, w := range words[i+1:] {
		if w == "--recursive" || w == "-r" || w == "-R" {
			rec = true
		}
		if strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--") {
			if strings.Contains(w, "r") || strings.Contains(w, "R") {
				rec = true
			}
		}
	}
	return rec, true
}

func lsRoot(words []string) bool {
	i := commandStart(words)
	if i >= len(words) || base(words[i]) != "ls" {
		return false
	}
	for _, w := range words[i+1:] {
		w = strings.TrimPrefix(w, "\x00")
		if w == "/" || w == "/*" {
			return true
		}
	}
	return false
}

func findIntoRM(words []string, st shellState) (Result, bool) {
	i := commandStart(words)
	if i >= len(words) || base(words[i]) != "find" {
		return Result{}, false
	}
	var roots, names []string
	args := words[i+1:]
	for n := 0; n < len(args); n++ {
		w := strings.TrimPrefix(args[n], "\x00")
		if w == "-name" || w == "-iname" {
			if n+1 < len(args) {
				names = append(names, strings.TrimPrefix(args[n+1], "\x00"))
				n++
			}
			continue
		}
		if w == "" || strings.HasPrefix(w, "-") || w == "(" || w == ")" || w == "!" || w == ";" || w == "+" {
			continue
		}
		roots = append(roots, w)
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	total := 0
	for _, root := range roots {
		if len(names) == 0 && wipeRoot(root, st) {
			return block("rm-root", "find of / or a home directory piped into xargs rm"), true
		}
		p := resolveFindRoot(root, st)
		if p == "" {
			continue
		}
		n, over := countFind(p, names, bulkTargets-total)
		total += n
		if over || total > bulkTargets {
			return catchCase("xargs-rm", "find piped into xargs rm matches more than the bulk threshold"), true
		}
	}
	return Result{}, false
}

func wipeRoot(w string, st shellState) bool {
	w = strings.TrimPrefix(w, "\x00")
	switch strings.TrimSpace(w) {
	case "/", "/*", "~", "~/", "$HOME", "${HOME}":
		return true
	}
	if _, ok := rootishDelete(w); ok {
		return true
	}
	p := expandBashWord(w, st)
	if p == "" || strings.HasPrefix(p, "\x00") {
		return false
	}
	if !filepath.IsAbs(p) {
		base := st.cwd
		if base == "" {
			base, _ = os.Getwd()
		}
		p = filepath.Join(base, p)
	}
	p = filepath.Clean(p)
	if p == "/" {
		return true
	}
	home := st.home
	if home == "" {
		home = loginHome()
	}
	return home != "" && p == filepath.Clean(home)
}

func resolveFindRoot(w string, st shellState) string {
	w = strings.TrimPrefix(w, "\x00")
	p := expandBashWord(w, st)
	if p == "" || strings.HasPrefix(p, "\x00") {
		return ""
	}
	if !filepath.IsAbs(p) {
		base := st.cwd
		if base == "" {
			base, _ = os.Getwd()
		}
		p = filepath.Join(base, p)
	}
	return filepath.Clean(p)
}

func countFind(root string, names []string, room int) (int, bool) {
	if room < 0 {
		room = 0
	}
	n := 0
	var walk func(string) bool
	walk = func(p string) bool {
		baseName := filepath.Base(p)
		if len(names) == 0 || nameMatch(baseName, names) {
			n++
			if n > room {
				return true
			}
		}
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		ents, err := os.ReadDir(p)
		if err != nil {
			return false
		}
		for _, e := range ents {
			if walk(filepath.Join(p, e.Name())) {
				return true
			}
		}
		return false
	}
	if len(names) > 0 {
		info, err := os.Lstat(root)
		if err != nil {
			return 0, false
		}
		if !info.IsDir() {
			if nameMatch(filepath.Base(root), names) {
				return 1, false
			}
			return 0, false
		}
		ents, err := os.ReadDir(root)
		if err != nil {
			return 0, false
		}
		for _, e := range ents {
			if walk(filepath.Join(root, e.Name())) {
				return n, true
			}
		}
		return n, false
	}
	if walk(root) {
		return n, true
	}
	return n, false
}

func nameMatch(baseName string, names []string) bool {
	for _, n := range names {
		ok, err := filepath.Match(n, baseName)
		if err == nil && ok {
			return true
		}
	}
	return false
}
