// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// parseTOML reads the subset of TOML spotter-sh configs use:
// assignments, dotted keys, tables, booleans, integers, strings, and arrays.
func parseTOML(s string) (*rawDoc, error) {
	doc := &rawDoc{keys: map[string]rawVal{}}
	section := ""
	lines := strings.Split(s, "\n")
	for i := 0; i < len(lines); i++ {
		line := stripComment(lines[i])
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if strings.HasPrefix(section, "[") || strings.Contains(section, "]") {
				return nil, fmt.Errorf("line %d: bad table", i+1)
			}
			ensureTable(doc, section)
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", i+1)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", i+1)
		}
		full := key
		if section != "" {
			full = section + "." + key
		}
		parsed, err := parseValue(val)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if err := put(doc, full, parsed); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
	}
	return doc, nil
}

func stripComment(line string) string {
	inS, inD := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inS:
			if c == '\'' {
				inS = false
			}
		case inD:
			if c == '\\' && i+1 < len(line) {
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
		case c == '#':
			return line[:i]
		}
	}
	return line
}

func parseValue(s string) (rawVal, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return rawVal{}, fmt.Errorf("empty value")
	}
	if s == "true" || s == "false" {
		return rawVal{kind: "bool", b: s == "true"}, nil
	}
	if s[0] == '"' || s[0] == '\'' {
		str, err := unquote(s)
		if err != nil {
			return rawVal{}, err
		}
		return rawVal{kind: "string", s: str}, nil
	}
	if s[0] == '[' {
		list, err := parseArray(s)
		if err != nil {
			return rawVal{}, err
		}
		return rawVal{kind: "list", list: list}, nil
	}
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		n, _ := strconv.ParseInt(s, 10, 64)
		return rawVal{kind: "int", n: n, s: s}, nil
	}
	// Bare size tokens such as 1GB are stored as strings.
	if isBare(s) {
		return rawVal{kind: "string", s: s}, nil
	}
	return rawVal{}, fmt.Errorf("unsupported value %q", s)
}

func isBare(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '/' || r == '.' || r == '*' {
			continue
		}
		return false
	}
	return s != ""
}

func unquote(s string) (string, error) {
	if len(s) < 2 {
		return "", fmt.Errorf("bad string")
	}
	q := s[0]
	if s[len(s)-1] != q {
		return "", fmt.Errorf("unterminated string")
	}
	body := s[1 : len(s)-1]
	if q == '\'' {
		return body, nil
	}
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' && i+1 < len(body) {
			i++
			switch body[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case '\\', '"':
				b.WriteByte(body[i])
			default:
				b.WriteByte(body[i])
			}
			continue
		}
		b.WriteByte(body[i])
	}
	return b.String(), nil
}

func parseArray(s string) ([]string, error) {
	if len(s) < 2 || s[0] != '[' || s[len(s)-1] != ']' {
		return nil, fmt.Errorf("bad array")
	}
	body := strings.TrimSpace(s[1 : len(s)-1])
	if body == "" {
		return []string{}, nil
	}
	var out []string
	var cur strings.Builder
	inS, inD := false, false
	flush := func() error {
		item := strings.TrimSpace(cur.String())
		cur.Reset()
		if item == "" {
			return nil
		}
		v, err := parseValue(item)
		if err != nil {
			return err
		}
		if v.kind == "string" {
			out = append(out, v.s)
			return nil
		}
		out = append(out, v.s)
		return nil
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case inS:
			cur.WriteByte(c)
			if c == '\'' {
				inS = false
			}
		case inD:
			cur.WriteByte(c)
			if c == '\\' && i+1 < len(body) {
				i++
				cur.WriteByte(body[i])
				continue
			}
			if c == '"' {
				inD = false
			}
		case c == '\'':
			inS = true
			cur.WriteByte(c)
		case c == '"':
			inD = true
			cur.WriteByte(c)
		case c == ',':
			if err := flush(); err != nil {
				return nil, err
			}
		default:
			cur.WriteByte(c)
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

func ensureTable(doc *rawDoc, section string) {
	parts := strings.Split(section, ".")
	cur := doc.keys
	for _, p := range parts {
		v, ok := cur[p]
		if !ok {
			v = rawVal{kind: "table", tab: map[string]rawVal{}}
			cur[p] = v
		}
		if v.tab == nil {
			v.tab = map[string]rawVal{}
			v.kind = "table"
			cur[p] = v
		}
		cur = v.tab
	}
}

func put(doc *rawDoc, path string, val rawVal) error {
	parts := strings.Split(path, ".")
	cur := doc.keys
	for i, p := range parts {
		if i == len(parts)-1 {
			cur[p] = val
			return nil
		}
		v, ok := cur[p]
		if !ok {
			v = rawVal{kind: "table", tab: map[string]rawVal{}}
			cur[p] = v
		}
		if v.kind != "table" {
			return fmt.Errorf("%s is not a table", strings.Join(parts[:i+1], "."))
		}
		if v.tab == nil {
			v.tab = map[string]rawVal{}
			cur[p] = v
		}
		cur = v.tab
	}
	return nil
}
