// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"strings"
	"unicode"
)

// sqlVerdict is the lexer's reading of one script.
type sqlVerdict struct {
	Destructive bool
	Unparsed    bool
	Ambiguous   bool
	What        string
	Statement   string
}

// lexSQL tokenizes SQL enough to see unbounded destruction.
// Text the lexer cannot structure is Unparsed (allow), not a pause.
func lexSQL(src string) sqlVerdict {
	toks, ok := tokenizeSQL(src)
	if !ok {
		return sqlVerdict{Unparsed: true}
	}
	if len(toks) == 0 {
		return sqlVerdict{}
	}
	// Split on semicolons that are tokens.
	var stmts [][]string
	var cur []string
	for _, t := range toks {
		if t == ";" {
			if len(cur) > 0 {
				stmts = append(stmts, cur)
				cur = nil
			}
			continue
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		stmts = append(stmts, cur)
	}
	var out sqlVerdict
	for _, st := range stmts {
		if v, what := stmtDestructive(st); v {
			out.Destructive = true
			out.What = what
			out.Statement = strings.Join(st, " ")
			return out
		}
	}
	return out
}

func tokenizeSQL(src string) ([]string, bool) {
	var toks []string
	s := src
	i := 0
	for i < len(s) {
		if isSpace(s[i]) {
			i++
			continue
		}
		// line comment
		if strings.HasPrefix(s[i:], "--") {
			nl := strings.IndexByte(s[i:], '\n')
			if nl < 0 {
				break
			}
			i += nl + 1
			continue
		}
		// executable mysql comment /*! ... */
		if strings.HasPrefix(s[i:], "/*!") {
			end := strings.Index(s[i:], "*/")
			if end < 0 {
				return nil, false
			}
			inner := s[i+3 : i+end]
			// drop the optional version digits after /*!
			j := 0
			for j < len(inner) && inner[j] >= '0' && inner[j] <= '9' {
				j++
			}
			sub, ok := tokenizeSQL(inner[j:])
			if !ok {
				return nil, false
			}
			toks = append(toks, sub...)
			i += end + 2
			continue
		}
		if strings.HasPrefix(s[i:], "/*") {
			end := strings.Index(s[i:], "*/")
			if end < 0 {
				return nil, false
			}
			i += end + 2
			continue
		}
		// dollar quote
		if s[i] == '$' {
			body, next, ok := takeDollar(s, i)
			if ok {
				_ = body
				i = next
				toks = append(toks, "''") // a string, not keywords
				continue
			}
		}
		if s[i] == '\'' || s[i] == '"' || s[i] == '`' {
			q := s[i]
			j := i + 1
			for j < len(s) {
				if s[j] == '\\' && j+1 < len(s) {
					j += 2
					continue
				}
				if s[j] == q {
					if q == '\'' && j+1 < len(s) && s[j+1] == '\'' {
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			if j > len(s) {
				return nil, false
			}
			toks = append(toks, "''")
			i = j
			continue
		}
		if s[i] == '(' || s[i] == ')' || s[i] == ',' || s[i] == ';' || s[i] == '=' || s[i] == '*' {
			toks = append(toks, s[i:i+1])
			i++
			continue
		}
		j := i
		for j < len(s) && !isSpace(s[j]) && !strings.ContainsRune("(),;=*'\""+"`$", rune(s[j])) {
			j++
		}
		if j == i {
			return nil, false
		}
		toks = append(toks, s[i:j])
		i = j
	}
	return toks, true
}

func takeDollar(s string, i int) (body string, next int, ok bool) {
	if i >= len(s) || s[i] != '$' {
		return "", 0, false
	}
	j := i + 1
	for j < len(s) && (unicode.IsLetter(rune(s[j])) || unicode.IsDigit(rune(s[j])) || s[j] == '_') {
		j++
	}
	if j >= len(s) || s[j] != '$' {
		return "", 0, false
	}
	tag := s[i : j+1]
	rest := s[j+1:]
	end := strings.Index(rest, tag)
	if end < 0 {
		return "", 0, false
	}
	return rest[:end], j + 1 + end + len(tag), true
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func stmtDestructive(toks []string) (bool, string) {
	up := make([]string, len(toks))
	for i, t := range toks {
		up[i] = strings.ToUpper(t)
	}
	for i := 0; i < len(up); i++ {
		switch up[i] {
		case "DROP":
			if i+1 < len(up) {
				switch up[i+1] {
				case "DATABASE", "SCHEMA", "TABLE", "COLLECTION":
					return true, "DROP " + up[i+1]
				}
			}
		case "TRUNCATE":
			return true, "TRUNCATE"
		case "DELETE":
			if whereBad(up[i:]) {
				return true, "DELETE without a real WHERE"
			}
		case "UPDATE":
			// skip if this UPDATE is not a statement keyword (inside a name). Treat any UPDATE as a statement.
			if whereBad(up[i:]) {
				return true, "UPDATE without a real WHERE"
			}
		case "ALTER":
			if hasSeq(up[i:], "ALTER", "TABLE") && sqlHasWord(up[i:], "DROP") {
				return true, "ALTER TABLE DROP"
			}
		}
	}
	return false, ""
}

func whereBad(toks []string) bool {
	// DELETE/UPDATE ... find WHERE. No WHERE → bad.
	// WHERE 1 / 1=1 / true / <col> IS NOT NULL → bad.
	idx := -1
	for i, t := range toks {
		if t == "WHERE" {
			idx = i
			break
		}
	}
	if idx < 0 {
		return true
	}
	rest := toks[idx+1:]
	if len(rest) == 0 {
		return true
	}
	// stop at clause boundaries
	end := len(rest)
	for i, t := range rest {
		switch t {
		case "ORDER", "GROUP", "LIMIT", "RETURNING", "UNION", "SET":
			end = i
		}
		if i > 0 && end != len(rest) {
			break
		}
	}
	rest = rest[:end]
	joined := strings.Join(rest, " ")
	switch strings.TrimSpace(joined) {
	case "1", "TRUE", "1 = 1", "1=1":
		return true
	}
	if strings.Contains(joined, "IS NOT NULL") && !strings.Contains(joined, " AND ") && !strings.Contains(joined, " OR ") {
		// WHERE id IS NOT NULL — degenerate
		return true
	}
	if joined == "1" || strings.HasPrefix(joined, "1 ") && !strings.Contains(joined, "=") && !strings.Contains(joined, "AND") {
		return true
	}
	return false
}

func hasSeq(toks []string, a, b string) bool {
	for i := 0; i+1 < len(toks); i++ {
		if toks[i] == a && toks[i+1] == b {
			return true
		}
	}
	return false
}

func sqlHasWord(toks []string, w string) bool {
	for _, t := range toks {
		if t == w {
			return true
		}
	}
	return false
}

// mongoDanger inspects a mongosh eval or script body.
func mongoDanger(src string) (bool, string) {
	s := stripJSStrings(src)
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "dropdatabase"):
		return true, "dropDatabase"
	case strings.Contains(l, "deletemany({})") || strings.Contains(l, "deletemany( {} )") || strings.Contains(strings.ReplaceAll(l, " ", ""), "deletemany({})"):
		return true, "deleteMany({})"
	case strings.Contains(strings.ReplaceAll(l, " ", ""), "remove({})"):
		return true, "remove({})"
	case strings.Contains(l, ".drop()"):
		return true, "drop()"
	default:
		return false, ""
	}
}

func stripJSStrings(s string) string {
	var b strings.Builder
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inS:
			if c == '\\' {
				i++
				continue
			}
			if c == '\'' {
				inS = false
			}
		case inD:
			if c == '\\' {
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

// redisDanger reports a dangerous redis-cli command word list.
func redisDanger(args []string) (bool, string) {
	if len(args) == 0 {
		return false, ""
	}
	cmd := strings.ToUpper(args[0])
	switch cmd {
	case "FLUSHALL", "FLUSHDB":
		return true, cmd
	case "SHUTDOWN":
		return true, "SHUTDOWN"
	case "CONFIG":
		if len(args) > 1 && strings.EqualFold(args[1], "RESETSTAT") {
			return true, "CONFIG RESETSTAT"
		}
	case "KEYS":
		if len(args) > 1 && args[1] == "*" {
			return true, "KEYS *"
		}
	}
	return false, ""
}
