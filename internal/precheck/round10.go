// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package precheck

import (
	"path/filepath"
	"strings"
)

// catchCase is an approvable pause. An admin can proceed; a non-admin cannot.
func catchCase(caseName, why string) Result {
	return Result{
		Action:  "catch",
		Exit:    120,
		Case:    caseName,
		Approve: true,
		Message: "Shell Spotter: " + why + ".",
	}
}

// dynamicFeed judges scripts a shell or interpreter would run: pipes, eval,
// here-strings, xargs, and command substitutions. A decoder (base64 -d,
// xxd -r, openssl enc -d, rev) that feeds a shell or interpreter is always
// a catch. The bytes are not decoded, so a harmless payload is still caught.
// Decoding into a file, with no shell or interpreter reading it, is allowed.
func dynamicFeed(command string) (Result, bool) {
	return dynamicFeedDepth(command, 0)
}

func dynamicFeedDepth(command string, depth int) (Result, bool) {
	if depth > 6 {
		return catchCase("fed-shell", "nested generated shell"), true
	}
	cmds := commandWords(command)
	bind := map[string]string{}
	var group []scannedCmd
	finish := func() (Result, bool) {
		if len(group) == 0 {
			return Result{}, false
		}
		r, ok := judgeFeedGroup(group, bind, depth)
		for _, c := range group {
			noteBind(bind, c)
		}
		group = nil
		return r, ok
	}
	for _, c := range cmds {
		if c.openSub || c.closeSub {
			if r, ok := finish(); ok {
				return r, true
			}
			continue
		}
		group = append(group, c)
		if c.stop != "|" {
			if r, ok := finish(); ok {
				return r, true
			}
		}
	}
	return finish()
}

func judgeFeedGroup(group []scannedCmd, bind map[string]string, depth int) (Result, bool) {
	if len(group) == 0 {
		return Result{}, false
	}
	for i, c := range group {
		if stageDecodes(c) {
			for _, later := range group[i+1:] {
				if consumesCode(later.words) {
					return catchCase("encoded-exec", "decoded text fed to a shell or interpreter"), true
				}
			}
		}
		if r, ok := argumentDecodes(c.words); ok {
			return r, true
		}
	}
	for i, c := range group {
		if !consumesStdin(c.words) && !xargsRunsCode(c.words) {
			continue
		}
		if i == 0 && consumesStdin(c.words) {
			script := firstNonEmpty(c.stdinCode, c.hereBody, c.hereArg)
			if script == "" {
				continue
			}
			if s, opaque, matched := resolveWhole(script, bind); matched {
				if opaque {
					return catchCase("fed-shell", "a shell would run a script that is not visible here"), true
				}
				script = s
			}
			return verdictScript(script, depth, true)
		}
		payload, known, opaque := "", false, false
		for _, prev := range group[:i] {
			if stageDecodes(prev) {
				return catchCase("encoded-exec", "decoded text fed to a shell or interpreter"), true
			}
			if s, ok := pipeScript(prev.words); ok && strings.TrimSpace(s) != "" {
				payload, known, opaque = s, true, false
				continue
			}
			if prev.hereBody != "" && feedsStdin(prev.words) {
				payload, known, opaque = prev.hereBody, true, false
				continue
			}
			if passthroughStage(prev.words) {
				continue
			}
			opaque = true
			known = false
		}
		if known && !opaque {
			if encodedStream(group[:i], payload) {
				return catchCase("encoded-exec", "encoded text fed to a shell or interpreter"), true
			}
			if s, op, matched := resolveWhole(strings.TrimSpace(payload), bind); matched {
				if op {
					return catchCase("fed-shell", "a shell would run a script that is not visible here"), true
				}
				payload = s
			}
			return verdictScript(payload, depth, true)
		}
		if opaque || i > 0 {
			return catchCase("fed-shell", "a shell or interpreter would run a script that is not visible here"), true
		}
	}
	if len(group) == 1 {
		return judgeOne(group[0], bind, depth)
	}
	return Result{}, false
}

func judgeOne(c scannedCmd, bind map[string]string, depth int) (Result, bool) {
	if script, opaque, ok := resolveEval(c.words, bind); ok {
		if opaque {
			return catchCase("fed-shell", "eval of a script that is not visible here"), true
		}
		return verdictScript(script, depth, false)
	}
	if script, opaque, ok := resolveInline(c.words, bind); ok {
		if opaque {
			return catchCase("fed-shell", "a shell would run a script that is not visible here"), true
		}
		return verdictScript(script, depth, true)
	}
	if script, opaque, ok := xargsInline(c); ok {
		if opaque {
			return catchCase("fed-shell", "a shell would run a script supplied to xargs"), true
		}
		return verdictScript(script, depth, true)
	}
	return Result{}, false
}

func verdictScript(script string, depth int, elevate bool) (Result, bool) {
	if depth > 6 {
		return catchCase("fed-shell", "nested generated shell"), true
	}
	script = strings.TrimSpace(strings.TrimPrefix(script, "\x00"))
	if script == "" {
		return Result{}, false
	}
	if bomb(script) || loopBomb(script) {
		return block("fork bomb", "a function that pipes or backgrounds a call to itself"), true
	}
	if r, ok := dynamicFeedDepth(script, depth+1); ok {
		return r, true
	}
	if r, ok := interpreterPayload(script); ok {
		return r, true
	}
	inner := Scan(script)
	if inner.Action == "hardblock" || inner.Action == "catch" {
		return inner, true
	}
	if elevate && destructivePlain(script) {
		return catchCase("fed-shell", "a generated script would run a destructive command"), true
	}
	return Result{}, false
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func stageDecodes(c scannedCmd) bool {
	if decoding(c.words) {
		return true
	}
	return false
}

func decoding(words []string) bool {
	i := commandStart(words)
	if i >= len(words) {
		return false
	}
	name := base(words[i])
	rest := words[i+1:]
	switch name {
	case "base64":
		return flagPresent(rest, "-d", "--decode", "-D")
	case "xxd":
		return flagPresent(rest, "-r", "--revert") || shortCluster(rest, 'r')
	case "openssl":
		return opensslDecodes(rest)
	case "rev":
		return true
	default:
		return false
	}
}

func flagPresent(rest []string, flags ...string) bool {
	for _, w := range rest {
		w = strings.TrimPrefix(w, "\x00")
		for _, f := range flags {
			if w == f {
				return true
			}
		}
	}
	return false
}

func shortCluster(rest []string, flag byte) bool {
	for _, w := range rest {
		w = strings.TrimPrefix(w, "\x00")
		if len(w) < 2 || !strings.HasPrefix(w, "-") || strings.HasPrefix(w, "--") {
			continue
		}
		if strings.ContainsRune(w, rune(flag)) {
			return true
		}
	}
	return false
}

func opensslDecodes(rest []string) bool {
	cmd := ""
	decode := false
	for _, w := range rest {
		w = strings.TrimPrefix(w, "\x00")
		switch w {
		case "-d", "-decrypt", "--decrypt":
			decode = true
			continue
		}
		if strings.HasPrefix(w, "-") {
			continue
		}
		if cmd == "" {
			cmd = w
		}
	}
	switch cmd {
	case "enc", "base64":
		return decode
	default:
		return decode && (strings.HasPrefix(cmd, "aes-") || strings.HasPrefix(cmd, "des"))
	}
}

func consumesCode(words []string) bool {
	return consumesStdin(words) || codeArgCommand(words) || xargsRunsCode(words)
}

func consumesStdin(words []string) bool {
	i := commandStart(words)
	if i >= len(words) {
		return false
	}
	name := base(words[i])
	rest := words[i+1:]
	switch name {
	case "bash", "sh", "dash", "zsh", "ksh":
		if _, ok := flagArg(rest, "-c"); ok {
			return false
		}
		if scriptFile(rest) && !flagPresent(rest, "-s", "--stdin") {
			return false
		}
		return true
	case "python", "python2", "python3", "perl", "node", "nodejs", "ruby", "php":
		if _, ok := codePayload(name, rest); ok {
			return false
		}
		if scriptFile(rest) {
			return false
		}
		return true
	default:
		return false
	}
}

func scriptFile(rest []string) bool {
	for i := 0; i < len(rest); i++ {
		w := strings.TrimPrefix(rest[i], "\x00")
		if w == "--" {
			if i+1 >= len(rest) || stdinOperand(rest[i+1]) {
				return false
			}
			return true
		}
		if stdinOperand(w) {
			return false
		}
		if w == "-c" || w == "-e" || w == "--eval" || w == "-r" || w == "--command" {
			if i+1 < len(rest) {
				i++
			}
			continue
		}
		if strings.HasPrefix(w, "-") && w != "-" {
			continue
		}
		return true
	}
	return false
}

func launchesCode(words []string) bool {
	if codeArgCommand(words) || consumesStdin(words) {
		return true
	}
	i := commandStart(words)
	if i >= len(words) {
		return false
	}
	switch base(words[i]) {
	case "bash", "sh", "dash", "zsh", "ksh", "source", ".", "eval":
		return true
	default:
		return false
	}
}

func codeArgCommand(words []string) bool {
	i := commandStart(words)
	if i >= len(words) {
		return false
	}
	name := base(words[i])
	rest := words[i+1:]
	switch name {
	case "eval", "source", ".":
		return true
	case "bash", "sh", "dash", "zsh", "ksh":
		_, ok := flagArg(rest, "-c")
		return ok
	case "python", "python2", "python3", "perl", "node", "nodejs", "ruby", "php":
		_, ok := codePayload(name, rest)
		return ok
	default:
		return xargsRunsCode(words)
	}
}

func xargsRunsCode(words []string) bool {
	_, _, ok := xargsUtility(words)
	return ok
}

func xargsUtility(words []string) (name, script string, ok bool) {
	i := commandStart(words)
	if i >= len(words) || base(words[i]) != "xargs" {
		return "", "", false
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
			case "-n", "-I", "-i", "-P", "-s", "-L", "-a", "-E", "-J", "-d":
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
	if i >= len(words) {
		return "", "", false
	}
	name = base(words[i])
	rest := words[i+1:]
	switch name {
	case "bash", "sh", "dash", "zsh", "ksh":
		if s, ok := flagArg(rest, "-c"); ok {
			return name, strings.TrimPrefix(s, "\x00"), true
		}
	case "eval":
		if s, ok := joinCode(rest); ok {
			return name, s, true
		}
	case "python", "python2", "python3", "perl", "node", "nodejs", "ruby", "php":
		if s, ok := codePayload(name, rest); ok {
			return name, s, true
		}
	}
	return "", "", false
}

func resolveInline(words []string, bind map[string]string) (string, bool, bool) {
	i := commandStart(words)
	if i >= len(words) {
		return "", false, false
	}
	name := base(words[i])
	rest := words[i+1:]
	var script string
	ok := false
	switch name {
	case "source", ".":
		if len(rest) > 0 {
			script, ok = rest[0], true
		}
	case "bash", "sh", "dash", "zsh", "ksh":
		script, ok = flagArg(rest, "-c")
	default:
		if name != "eval" && name != "xargs" {
			script, ok = codePayload(name, rest)
		}
	}
	if !ok {
		return "", false, false
	}
	script = strings.TrimSpace(strings.TrimPrefix(script, "\x00"))
	if s, opaque, matched := resolveWhole(script, bind); matched {
		return s, opaque, true
	}
	return "", false, false
}

func xargsInline(c scannedCmd) (string, bool, bool) {
	_, script, ok := xargsUtility(c.words)
	if !ok {
		return "", false, false
	}
	if placeholder(script) {
		if body := firstNonEmpty(c.hereArg, c.stdinCode, c.hereBody); body != "" {
			return body, false, true
		}
		return "", true, true
	}
	return script, false, true
}

func placeholder(s string) bool {
	s = strings.TrimSpace(strings.TrimPrefix(s, "\x00"))
	switch s {
	case "", "{}", "{1}", "$1", "$0":
		return true
	default:
		return false
	}
}

func passthroughStage(words []string) bool {
	i := commandStart(words)
	if i >= len(words) {
		return false
	}
	switch base(words[i]) {
	case "tee", "cat":
		return true
	default:
		return false
	}
}

func argumentDecodes(words []string) (Result, bool) {
	if !launchesCode(words) {
		return Result{}, false
	}
	blob := strings.Join(words, " ")
	if substDecodes(blob) {
		return catchCase("encoded-exec", "decoded text fed to a shell or interpreter"), true
	}
	return Result{}, false
}

func substDecodes(s string) bool {
	for _, inner := range substInners(s) {
		cmds := commandWords(inner)
		for _, c := range cmds {
			if decoding(c.words) || stageDecodes(c) {
				return true
			}
		}
	}
	return false
}

func substInners(s string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		if strings.HasPrefix(s[i:], "$(") {
			end := skipSubst(s, i)
			if end > i+2 {
				out = append(out, s[i+2:end-1])
				i = end - 1
			}
			continue
		}
		if strings.HasPrefix(s[i:], "<(") || strings.HasPrefix(s[i:], ">(") {
			end := skipParen(s, i+1)
			if end > i+2 {
				out = append(out, s[i+2:end-1])
				i = end - 1
			}
			continue
		}
		if s[i] == '`' {
			j := i + 1
			for j < len(s) {
				if s[j] == '\\' && j+1 < len(s) {
					j += 2
					continue
				}
				if s[j] == '`' {
					out = append(out, s[i+1:j])
					i = j
					break
				}
				j++
			}
		}
	}
	return out
}

func skipParen(s string, i int) int {
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

func resolveEval(words []string, bind map[string]string) (string, bool, bool) {
	i := commandStart(words)
	if i >= len(words) || base(words[i]) != "eval" {
		return "", false, false
	}
	raw, ok := joinCode(words[i+1:])
	if !ok {
		return "", false, false
	}
	raw = strings.TrimSpace(raw)
	if s, opaque, matched := resolveWhole(raw, bind); matched {
		return s, opaque, true
	}
	return raw, false, true
}

func resolveWhole(raw string, bind map[string]string) (string, bool, bool) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "\x00"))
	if inner, ok := commandSubst(raw); ok {
		return resolveCommandText(inner)
	}
	if strings.HasPrefix(raw, "<(") && strings.HasSuffix(raw, ")") && len(raw) > 3 {
		return resolveCommandText(raw[2 : len(raw)-1])
	}
	if name, idx, def, hasDef, ok := parseParam(raw); ok {
		key := name
		if idx != "" {
			key = name + "[" + idx + "]"
		}
		if v, found := bind[key]; found {
			return v, false, true
		}
		if idx == "0" {
			if v, found := bind[name+"[0]"]; found {
				return v, false, true
			}
		}
		if hasDef {
			return def, false, true
		}
		return "", true, true
	}
	return "", false, false
}

func resolveCommandText(inner string) (string, bool, bool) {
	cmds := commandWords(inner)
	if len(cmds) > 0 && (decoding(cmds[0].words) || stageDecodes(cmds[0])) {
		return "", true, true
	}
	if len(cmds) == 1 {
		if produced, ok := pipeScript(cmds[0].words); ok && strings.TrimSpace(produced) != "" {
			return produced, false, true
		}
	}
	return "", true, true
}

func parseParam(raw string) (name, idx, def string, hasDef, ok bool) {
	if strings.HasPrefix(raw, "${") && strings.HasSuffix(raw, "}") && len(raw) > 3 {
		body := raw[2 : len(raw)-1]
		name, rest := ident(body)
		if name == "" {
			return "", "", "", false, false
		}
		if strings.HasPrefix(rest, "[") {
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				return "", "", "", false, false
			}
			idx = rest[1:end]
			rest = rest[end+1:]
		}
		for _, op := range []string{":-", "-", ":=", "="} {
			if strings.HasPrefix(rest, op) {
				return name, idx, rest[len(op):], true, true
			}
		}
		if rest == "" {
			return name, idx, "", false, true
		}
		return "", "", "", false, false
	}
	if strings.HasPrefix(raw, "$") && len(raw) > 1 {
		name, rest := ident(raw[1:])
		if name != "" && rest == "" {
			return name, "", "", false, true
		}
	}
	return "", "", "", false, false
}

func ident(s string) (string, string) {
	i := 0
	for i < len(s) {
		r := rune(s[i])
		if i == 0 && !isNameStart(s[i]) && r != '_' {
			break
		}
		if !isNameCont(s[i]) {
			break
		}
		i++
	}
	return s[:i], s[i:]
}

func noteBind(bind map[string]string, c scannedCmd) {
	for _, w := range c.words {
		if !isAssign(w) {
			break
		}
		k, v, ok := splitAssign(w)
		if !ok {
			continue
		}
		v = strings.TrimPrefix(v, "\x00")
		if strings.ContainsAny(v, "$`") {
			delete(bind, k)
			continue
		}
		bind[k] = v
	}
	i := commandStart(c.words)
	if i >= len(c.words) {
		return
	}
	n := base(c.words[i])
	if n != "readarray" && n != "mapfile" {
		return
	}
	body := firstNonEmpty(c.hereArg, c.stdinCode, c.hereBody)
	if body == "" {
		return
	}
	name := arrayName(c.words[i+1:])
	if name == "" {
		return
	}
	line := body
	if j := strings.IndexByte(line, '\n'); j >= 0 {
		line = line[:j]
	}
	bind[name] = body
	bind[name+"[0]"] = line
}

func splitAssign(w string) (string, string, bool) {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return "", "", false
	}
	return w[:eq], w[eq+1:], true
}

func arrayName(rest []string) string {
	for i := 0; i < len(rest); i++ {
		w := strings.TrimPrefix(rest[i], "\x00")
		switch w {
		case "-d", "-n", "-O", "-u", "-C", "-c", "-s":
			if i+1 < len(rest) {
				i++
			}
			continue
		}
		if strings.HasPrefix(w, "-") {
			continue
		}
		return w
	}
	return ""
}

func destructivePlain(script string) bool {
	for _, c := range commandWords(script) {
		if c.openSub || c.closeSub || len(c.words) == 0 {
			continue
		}
		i := commandStart(c.words)
		if i >= len(c.words) {
			continue
		}
		name := base(c.words[i])
		rest := c.words[i+1:]
		switch name {
		case "rm":
			if recursiveRM(rest) && len(rmOperands(rest)) > 0 {
				return true
			}
		case "find":
			if findDeletes(rest) {
				return true
			}
		}
	}
	return false
}

func recursiveRM(rest []string) bool {
	for _, w := range rest {
		if w == "--recursive" || w == "-r" || w == "-R" {
			return true
		}
		if strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--") && len(w) > 1 {
			if strings.ContainsAny(w[1:], "rR") {
				return true
			}
		}
	}
	return false
}

func rmOperands(rest []string) []string {
	var ops []string
	for _, w := range rest {
		if w == "--" {
			continue
		}
		if strings.HasPrefix(w, "-") && w != "-" && !strings.HasPrefix(w, "-/") {
			continue
		}
		ops = append(ops, w)
	}
	return ops
}

func findDeletes(rest []string) bool {
	for i := 0; i < len(rest); i++ {
		w := strings.TrimPrefix(rest[i], "\x00")
		if w == "-delete" {
			return true
		}
		if (w == "-exec" || w == "-execdir") && i+1 < len(rest) && base(strings.TrimPrefix(rest[i+1], "\x00")) == "rm" {
			return true
		}
	}
	return false
}

func fedPayload(script string) (Result, bool) {
	if substDecodes(script) {
		return catchCase("encoded-exec", "decoded text fed to a shell or interpreter"), true
	}
	return Result{}, false
}

func codePayload(name string, rest []string) (string, bool) {
	switch name {
	case "bash", "sh", "dash", "zsh", "ksh", "python", "python2", "python3":
		return flagArg(rest, "-c")
	case "perl", "ruby":
		return flagArg(rest, "-e")
	case "node", "nodejs":
		return flagArg(rest, "-e")
	case "php":
		return flagArg(rest, "-r")
	default:
		return "", false
	}
}

func interpreterPayload(code string) (Result, bool) {
	code = strings.TrimPrefix(code, "\x00")
	if strings.TrimSpace(code) == "" {
		return Result{}, false
	}
	if r, ok := interpreterWipe(code); ok {
		return r, true
	}
	if interpreterFork(code) {
		return block("fork bomb", "an interpreter loop that forks or spawns processes"), true
	}
	if encodedIntoExec(code) {
		return catchCase("encoded-exec", "decoded text fed to a shell or interpreter"), true
	}
	for _, call := range []string{"system", "popen", "check_output", "check_call", "os.system"} {
		for _, arg := range callArgs(code, call) {
			if r, ok := verdictScript(arg, 3, true); ok && (r.Action == "hardblock" || r.Action == "catch") {
				return r, true
			}
		}
	}
	return Result{}, false
}

func interpreterWipe(code string) (Result, bool) {
	names := []string{"rmtree", "rm_rf", "rm_r", "rmSync", "rmdirSync", "remove_all", "rmtreeSync"}
	for _, arg := range callArgs(code, names...) {
		a := strings.TrimSpace(arg)
		a = strings.Trim(a, `"'`)
		if a == "/" {
			return block("rmtree", "interpreter delete of /"), true
		}
		if rootishPath(arg) {
			return blockHeuristic("rmtree", "interpreter delete of a filesystem root or home"), true
		}
	}
	return Result{}, false
}

func interpreterFork(code string) bool {
	plain := stripCodeLiterals(code)
	if !spawnCall(plain) || !unboundedCodeLoop(plain) {
		return false
	}
	return true
}

func stripCodeLiterals(s string) string {
	var b strings.Builder
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inS:
			if c == '\\' && i+1 < len(s) {
				i++
				b.WriteByte(' ')
				continue
			}
			if c == '\'' {
				inS = false
			}
			b.WriteByte(' ')
		case inD:
			if c == '\\' && i+1 < len(s) {
				i++
				b.WriteByte(' ')
				continue
			}
			if c == '"' {
				inD = false
			}
			b.WriteByte(' ')
		case c == '#':
			for i < len(s) && s[i] != '\n' {
				b.WriteByte(' ')
				i++
			}
			if i < len(s) {
				b.WriteByte('\n')
			}
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

func spawnCall(s string) bool {
	low := strings.ToLower(s)
	for _, name := range []string{"os.fork", "os.spawn", ".fork", ".spawn", "rfork", "posix_spawn"} {
		if strings.Contains(low, name) {
			return true
		}
	}
	// perl/ruby/php: a bare fork call, not the letters inside another word.
	for i := 0; i < len(s); i++ {
		if !wordAt(s, i, "fork") && !wordAt(s, i, "spawn") {
			continue
		}
		return true
	}
	return false
}

func unboundedCodeLoop(s string) bool {
	low := strings.ToLower(s)
	if strings.Contains(low, "for(;;)") || strings.Contains(low, "for (;;)") || strings.Contains(low, "for(;; )") {
		return true
	}
	if strings.Contains(low, "loop do") || strings.Contains(low, "loop{") || strings.Contains(low, "loop {") {
		return true
	}
	for _, kw := range []string{"while", "until"} {
		from := 0
		for {
			j := strings.Index(low[from:], kw)
			if j < 0 {
				break
			}
			j += from
			if j > 0 && isNameCont(low[j-1]) {
				from = j + len(kw)
				continue
			}
			rest := low[j+len(kw):]
			cond := rest
			for _, stop := range []string{":", "{", "\n", ";"} {
				if k := strings.Index(cond, stop); k >= 0 && k < len(cond) {
					if stop == ":" || len(cond) > k {
						// take the shortest useful prefix
					}
				}
			}
			end := len(rest)
			for _, stop := range []string{"\n", "{", ":"} {
				if k := strings.Index(rest, stop); k >= 0 && k < end {
					end = k
				}
			}
			cond = strings.TrimSpace(rest[:end])
			cond = strings.Trim(cond, "() ")
			switch cond {
			case "1", "true", "true:", "1:", "fork", "spawn":
				return true
			}
			if strings.HasPrefix(cond, "true") || cond == "1" || strings.Contains(cond, "fork") || strings.Contains(cond, "spawn") {
				return true
			}
			// perl: fork while 1 — the condition is the constant after while
			fields := strings.Fields(cond)
			if len(fields) == 1 && (fields[0] == "1" || fields[0] == "true") {
				return true
			}
			from = j + len(kw)
		}
	}
	return false
}

func loopBomb(s string) bool {
	plain := hideQuotes(dropHereBodies(stripComments(s)))
	for i := 0; i < len(plain); {
		if wordAt(plain, i, "while") || wordAt(plain, i, "until") {
			kw := "while"
			if wordAt(plain, i, "until") {
				kw = "until"
			}
			cond, body, next, ok := splitLoop(plain, i)
			if !ok || next <= i {
				i++
				continue
			}
			if constantLoop(kw, cond) && backgrounds(body) {
				return true
			}
			i = next
			continue
		}
		if wordAt(plain, i, "for") {
			arith, body, next, ok := arithFor(plain, i)
			if ok && next > i {
				if arithUnbounded(arith) && backgrounds(body) {
					return true
				}
				i = next
				continue
			}
		}
		i++
	}
	return false
}

func constantLoop(kw, cond string) bool {
	c := strings.Join(strings.Fields(cond), " ")
	c = strings.Trim(c, "; ")
	switch c {
	case ":", "true", "[ 1 ]", "[[ 1 ]]", "test 1", "(( 1 ))", "((1))":
		return kw == "while"
	case "false":
		return kw == "until"
	default:
		return false
	}
}

func splitLoop(s string, kwAt int) (cond, body string, next int, ok bool) {
	i := kwAt
	for i < len(s) && isNameCont(s[i]) {
		i++
	}
	i = skipSpace(s, i)
	start := i
	depth := 0
	for i < len(s) {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && wordAt(s, i, "do") {
				b, n, good := doBody(s, i)
				return s[start:i], b, n, good
			}
			if depth == 0 && s[i] == '{' {
				b, n, good := funcBody(s, i)
				return s[start:i], b, n, good
			}
		}
		i++
	}
	return "", "", kwAt, false
}

func doBody(s string, doAt int) (string, int, bool) {
	if !wordAt(s, doAt, "do") {
		return "", doAt, false
	}
	i := doAt + 2
	start := i
	depth := 0
	for i < len(s) {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && cmdWord(s, i, "done") {
				return s[start:i], i + len("done"), true
			}
		}
		i++
	}
	return "", doAt, false
}

func arithFor(s string, forAt int) (arith, body string, next int, ok bool) {
	i := forAt + len("for")
	i = skipSpace(s, i)
	if i+1 >= len(s) || s[i] != '(' || s[i+1] != '(' {
		return "", "", forAt, false
	}
	i += 2
	end := strings.Index(s[i:], "))")
	if end < 0 {
		return "", "", forAt, false
	}
	arith = s[i : i+end]
	i = skipSpace(s, i+end+2)
	if i < len(s) && s[i] == ';' {
		i = skipSpace(s, i+1)
	}
	if i < len(s) && s[i] == '{' {
		b, n, good := funcBody(s, i)
		return arith, b, n, good
	}
	if wordAt(s, i, "do") {
		b, n, good := doBody(s, i)
		return arith, b, n, good
	}
	return "", "", forAt, false
}

func arithUnbounded(arith string) bool {
	parts := strings.Split(arith, ";")
	if len(parts) < 3 {
		return false
	}
	cond := strings.TrimSpace(parts[1])
	return cond == "" || cond == "1" || cond == "true"
}

func backgrounds(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '&' {
			continue
		}
		if i+1 < len(s) && s[i+1] == '&' {
			i++
			continue
		}
		if i > 0 && (s[i-1] == '>' || s[i-1] == '<' || s[i-1] == '|') {
			continue
		}
		return true
	}
	return false
}

// cmdWord is a keyword in command position, not an argument named done.
func cmdWord(s string, i int, w string) bool {
	if !wordAt(s, i, w) {
		return false
	}
	j := i
	for j > 0 && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	if j == 0 {
		return true
	}
	switch s[j-1] {
	case ';', '\n', '&', '|', '{', '(':
		return true
	default:
		return false
	}
}

func commandWord(words []string) string {
	i := commandStart(words)
	if i >= len(words) {
		return ""
	}
	return words[i]
}

func matchTee(rest []string) (Result, bool) {
	for _, w := range rest {
		w = strings.TrimPrefix(w, "\x00")
		if w == "--" || w == "-" || (strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "-/")) {
			continue
		}
		if isSystemDisk(w) {
			return block("raw-disk", "tee writing a system disk"), true
		}
		if protectedName(w) {
			return catchCase("redirect", "tee onto a protected file ("+w+")"), true
		}
	}
	return Result{}, false
}

func protectedName(p string) bool {
	switch filepath.Clean(p) {
	case "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers",
		"/etc/fstab", "/etc/hosts", "/etc/resolv.conf", "/etc/crontab":
		return true
	}
	baseName := filepath.Base(p)
	switch baseName {
	case ".bashrc", ".bash_profile", ".profile", ".zshrc":
		if strings.HasPrefix(p, "~") || strings.Contains(p, "/.") || strings.HasPrefix(p, ".") {
			return true
		}
	}
	return false
}

func systemDirNode(p string) bool {
	switch filepath.Clean(strings.TrimPrefix(p, "\x00")) {
	case "/bin", "/sbin", "/usr", "/usr/bin", "/usr/sbin", "/usr/local", "/usr/local/bin",
		"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/etc", "/boot", "/opt", "/var":
		return true
	default:
		return false
	}
}

func weightedHomeOperands(ops []string) bool {
	n := 0
	for _, op := range ops {
		if homeTreeOperand(strings.TrimPrefix(op, "\x00")) {
			n++
		}
	}
	// A recursive directory in a home or sensitive tree weighs a quarter of the
	// flat bulk threshold. Four of them are a bulk delete. Three still are not.
	return n >= 4
}

func homeTreeOperand(op string) bool {
	switch {
	case strings.HasPrefix(op, "~/"), strings.HasPrefix(op, "$HOME/"), strings.HasPrefix(op, "${HOME}/"):
		return true
	case strings.HasPrefix(op, "/root/"):
		return true
	case strings.HasPrefix(op, "/home/"):
		rest := strings.TrimPrefix(op, "/home/")
		return strings.Contains(rest, "/")
	default:
		return false
	}
}
