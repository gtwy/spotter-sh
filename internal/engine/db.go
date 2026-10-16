// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"os"
	"path/filepath"
	"strings"
)

func (in Input) decideDB(name string, argv []string) Outcome {
	switch name {
	case "redis-cli":
		return in.decideRedis(argv)
	case "mongosh", "mongo":
		return in.decideMongo(argv)
	case "sqlite3":
		return in.decideSQLite(argv)
	default:
		return in.decideSQLClient(name, argv)
	}
}

func (in Input) decideSQLClient(name string, argv []string) Outcome {
	cmds, files := sqlInputs(name, argv)
	for _, c := range cmds {
		o := in.judgeSQLBytes(name, []byte(c))
		if o.Action != "allow" {
			return o
		}
	}
	if len(cmds) > 0 {
		return allow()
	}
	for _, f := range files {
		var b []byte
		var ok bool
		if f == "-" {
			b, ok = in.StdinPeek, len(in.StdinPeek) > 0
		} else {
			b, ok = in.readSQLFile(f)
		}
		if !ok {
			o := allow()
			o.LogNote = "sql_unparsed"
			return o
		}
		o := in.judgeSQLBytes(name, b)
		if o.Action != "allow" {
			return o
		}
	}
	if len(files) > 0 {
		return allow()
	}
	switch in.StdinKind {
	case "pipe":
		o := allow()
		o.LogNote = "sql_unscanned"
		return o
	case "file":
		if len(in.StdinPeek) > 0 {
			return in.judgeSQLBytes(name, in.StdinPeek)
		}
		return allow()
	default:
		// no statement and no SQL on stdin → interactive session
		if in.StdinKind == "null" || in.StdinKind == "tty" || in.StdinKind == "" || in.StdinKind == "other" {
			o := in.danger("F", "interactive "+name, "inside this session spotter-sh cannot check individual statements. There is NO per-statement protection once you are in the REPL.", "an interactive database session is unguarded", "prefer "+name+" -c or -f. BACK UP FIRST.", nil, "interactive-session")
			o.InjectSafe = true
			return o
		}
	}
	return allow()
}

func (in Input) judgeSQLBytes(name string, b []byte) Outcome {
	return in.judgeSQL(name, b, 0)
}

func (in Input) judgeSQL(name string, b []byte, depth int) Outcome {
	if depth < 1 {
		if file, ok := sqlSourceFile(string(b)); ok {
			if body, good := in.readSQLFile(file); good {
				return in.judgeSQL(name, body, depth+1)
			}
		}
	}
	v := lexSQL(string(b))
	if v.Unparsed {
		o := allow()
		o.LogNote = "sql_unparsed"
		return o
	}
	if v.Destructive {
		return in.danger("F", name+" "+v.What, v.What, "the script contains an unbounded statement", "split the dangerous statement out", nil, v.What)
	}
	return allow()
}

func (in Input) decideSQLite(argv []string) Outcome {
	// sqlite3 db "sql", sqlite3 -cmd "sql", or sqlite3 db
	var ops []string
	args := argv[1:]
	for i := 0; i < len(args); i++ {
		w := args[i]
		if w == "-cmd" || w == "--cmd" {
			if i+1 < len(args) {
				if o := in.judgeSQLiteCmd(args[i+1]); o.Action != "allow" {
					return o
				}
				i++
			}
			continue
		}
		if strings.HasPrefix(w, "--cmd=") {
			if o := in.judgeSQLiteCmd(strings.TrimPrefix(w, "--cmd=")); o.Action != "allow" {
				return o
			}
			continue
		}
		if strings.HasPrefix(w, "-") {
			continue
		}
		ops = append(ops, w)
	}
	if len(ops) >= 2 {
		last := ops[len(ops)-1]
		if file, ok := sqliteRead(last); ok {
			if b, good := in.readSQLFile(file); good {
				return in.judgeSQLBytes("sqlite3", b)
			}
		}
		v := lexSQL(last)
		if v.Unparsed {
			o := allow()
			o.LogNote = "sql_unparsed"
			return o
		}
		if v.Destructive {
			return in.danger("F", "sqlite3 "+v.What, v.What, "the statement is unbounded", "add a WHERE", nil, v.What)
		}
		return allow()
	}
	if in.StdinKind == "pipe" {
		o := allow()
		o.LogNote = "sql_unscanned"
		return o
	}
	if in.StdinKind == "file" && len(in.StdinPeek) > 0 {
		return in.judgeSQLBytes("sqlite3", in.StdinPeek)
	}
	// A closed stdin, such as /dev/null, is EOF, not a person typing SQL.
	// A real terminal is still an unguarded session.
	if in.StdinKind == "null" {
		return allow()
	}
	if len(ops) == 1 {
		if file, ok := sqliteRead(ops[0]); ok {
			if b, good := in.readSQLFile(file); good {
				return in.judgeSQLBytes("sqlite3", b)
			}
		}
	}
	o := in.danger("F", "interactive sqlite3", "NO per-statement protection inside the session. BACK UP FIRST.", "statements typed live are not scanned", "use sqlite3 db \"SQL\"", nil, "interactive-session")
	return o
}

func (in Input) judgeSQLiteCmd(cmd string) Outcome {
	if file, ok := sqliteRead(cmd); ok {
		if b, good := in.readSQLFile(file); good {
			return in.judgeSQLBytes("sqlite3", b)
		}
	}
	return in.judgeSQLBytes("sqlite3", []byte(cmd))
}

func sqlSourceFile(s string) (string, bool) {
	for _, part := range strings.Split(s, ";") {
		if file, ok := sqlSourceStmt(part); ok {
			return file, true
		}
	}
	return "", false
}

func sqlSourceStmt(s string) (string, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "; \t")
	s = strings.TrimSpace(s)
	low := strings.ToLower(s)
	var rest string
	switch {
	case strings.HasPrefix(low, "source "):
		rest = strings.TrimSpace(s[len("source "):])
	case strings.HasPrefix(s, `\. `):
		rest = strings.TrimSpace(s[len(`\. `):])
	case strings.HasPrefix(s, `\ir `):
		rest = strings.TrimSpace(s[len(`\ir `):])
	case strings.HasPrefix(s, `\i `):
		rest = strings.TrimSpace(s[len(`\i `):])
	case strings.HasPrefix(low, `\include_relative `):
		rest = strings.TrimSpace(s[len(`\include_relative `):])
	case strings.HasPrefix(low, `\include `):
		rest = strings.TrimSpace(s[len(`\include `):])
	default:
		return "", false
	}
	rest = strings.Trim(rest, `"'`)
	if rest == "" || strings.ContainsAny(rest, "\n\r") {
		return "", false
	}
	return rest, true
}

func sqliteRead(sql string) (string, bool) {
	s := strings.TrimSpace(sql)
	low := strings.ToLower(s)
	if !strings.HasPrefix(low, ".read") {
		return "", false
	}
	rest := strings.TrimSpace(s[len(".read"):])
	rest = strings.Trim(rest, `"'`)
	if rest == "" {
		return "", false
	}
	return rest, true
}

func (in Input) decideMongo(argv []string) Outcome {
	if ev := firstFlag(argv, "--eval", "-e"); ev != "" {
		if bad, what := mongoDanger(ev); bad {
			return in.danger("F", "mongosh "+what, what, "this removes data without a filter", "pass a real filter", nil, what)
		}
		return allow()
	}
	// script file operand
	var ops []string
	for _, w := range argv[1:] {
		if !strings.HasPrefix(w, "-") {
			ops = append(ops, w)
		}
	}
	if len(ops) > 0 {
		return allow()
	}
	if in.StdinKind == "pipe" {
		o := allow()
		o.LogNote = "sql_unscanned"
		return o
	}
	return in.danger("F", "interactive mongosh", "NO per-statement protection inside the session. BACK UP FIRST.", "eval is the gated form", "use mongosh --eval", nil, "interactive-session")
}

func (in Input) decideRedis(argv []string) Outcome {
	var ops []string
	for i := 1; i < len(argv); i++ {
		w := argv[i]
		if w == "--" {
			ops = append(ops, argv[i+1:]...)
			break
		}
		if strings.HasPrefix(w, "-") {
			if (w == "-n" || w == "-h" || w == "-p" || w == "-a" || w == "--user" || w == "--pass" || w == "--eval") && i+1 < len(argv) && !strings.Contains(w, "=") {
				if w == "--eval" {
					return allow()
				}
				i++
			}
			continue
		}
		ops = append(ops, w)
	}
	if len(ops) == 0 {
		if in.StdinKind == "pipe" {
			o := allow()
			o.LogNote = "sql_unscanned"
			return o
		}
		return in.danger("F", "interactive redis-cli", "NO per-statement protection inside the session. BACK UP FIRST.", "FLUSHALL typed live would not be stopped", "pass the command on the command line", nil, "interactive-session")
	}
	if bad, what := redisDanger(ops); bad {
		return in.danger("F", "redis-cli "+what, what+" wipes or resets server state", "this command is unbounded", "operate on one key", nil, what)
	}
	return allow()
}

// sqlInputs splits inline SQL from script files per client.
// psql -q is quiet, not a statement. psql -f names a file, not stdin.
// mysql -f is force, not a file.
func sqlInputs(name string, argv []string) (cmds, files []string) {
	switch name {
	case "psql":
		return psqlInputs(argv)
	case "mysql", "mariadb":
		return flagValues(argv, []string{"-e", "--execute"}, nil), nil
	case "clickhouse-client":
		return flagValues(argv, []string{"-q", "--query"}, nil), nil
	case "cockroach":
		return flagValues(argv, []string{"-e", "--execute"}, nil), nil
	default:
		return flagValues(argv, []string{"-c", "-e", "--command", "--execute"}, nil), nil
	}
}

func psqlInputs(argv []string) (cmds, files []string) {
	takes := map[byte]bool{
		'd': true, 'h': true, 'p': true, 'U': true, 'v': true, 'o': true,
		'F': true, 'P': true, 'L': true, 'V': true,
	}
	args := argv[1:]
	for i := 0; i < len(args); i++ {
		w := args[i]
		if w == "--" {
			break
		}
		switch {
		case w == "-c" || w == "--command":
			if i+1 < len(args) {
				cmds = append(cmds, args[i+1])
				i++
			}
		case strings.HasPrefix(w, "--command="):
			cmds = append(cmds, strings.TrimPrefix(w, "--command="))
		case w == "-f" || w == "--file":
			if i+1 < len(args) {
				files = append(files, args[i+1])
				i++
			}
		case strings.HasPrefix(w, "--file="):
			files = append(files, strings.TrimPrefix(w, "--file="))
		case strings.HasPrefix(w, "--"):
			if psqlLongTakes(w) && !strings.Contains(w, "=") && i+1 < len(args) {
				i++
			}
		case strings.HasPrefix(w, "-") && len(w) > 1:
			cluster := w[1:]
			for j := 0; j < len(cluster); j++ {
				c := cluster[j]
				rest := cluster[j+1:]
				switch c {
				case 'c':
					if rest != "" {
						cmds = append(cmds, rest)
					} else if i+1 < len(args) {
						cmds = append(cmds, args[i+1])
						i++
					}
					j = len(cluster)
				case 'f':
					if rest != "" {
						files = append(files, rest)
					} else if i+1 < len(args) {
						files = append(files, args[i+1])
						i++
					}
					j = len(cluster)
				default:
					if takes[c] {
						if rest == "" && i+1 < len(args) {
							i++
						}
						j = len(cluster)
					}
				}
			}
		}
	}
	return cmds, files
}

func psqlLongTakes(w string) bool {
	switch w {
	case "--host", "--port", "--username", "--dbname", "--set", "--variable",
		"--output", "--field-separator", "--pset", "--log-file", "--command", "--file":
		return true
	default:
		return false
	}
}

func flagValues(argv []string, inline, files []string) []string {
	want := map[string]bool{}
	for _, f := range inline {
		want[f] = true
	}
	file := map[string]bool{}
	for _, f := range files {
		file[f] = true
	}
	var out []string
	for i := 1; i < len(argv); i++ {
		w := argv[i]
		if w == "--" {
			break
		}
		for f := range want {
			if w == f && i+1 < len(argv) {
				out = append(out, argv[i+1])
				i++
				break
			}
			if strings.HasPrefix(w, f+"=") {
				out = append(out, strings.TrimPrefix(w, f+"="))
				break
			}
		}
		_ = file
	}
	return out
}

func (in Input) readSQLFile(path string) ([]byte, bool) {
	if path == "" {
		return nil, false
	}
	p := path
	if !filepath.IsAbs(p) {
		p = filepath.Join(in.Cwd, p)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	n := in.Config.DB.SQLScanKB
	if n <= 0 {
		n = 256
	}
	buf := make([]byte, n*1024)
	got, _ := f.Read(buf)
	if got == 0 {
		return nil, false
	}
	return buf[:got], true
}

func firstFlag(argv []string, flags ...string) string {
	want := map[string]bool{}
	for _, f := range flags {
		want[f] = true
	}
	for i := 1; i < len(argv); i++ {
		w := argv[i]
		for f := range want {
			if w == f && i+1 < len(argv) {
				return argv[i+1]
			}
			if strings.HasPrefix(w, f+"=") {
				return strings.TrimPrefix(w, f+"=")
			}
		}
	}
	return ""
}
