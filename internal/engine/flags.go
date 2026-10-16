// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import "strings"

type flagSet struct {
	rec   []string
	takes map[string]bool
}

type parsed struct {
	rec  bool
	ops  []string
	seen map[string]bool
}

func (p parsed) has(short string) bool {
	return p.seen[short]
}

func parseArgs(argv []string, spec flagSet) parsed {
	out := parsed{seen: map[string]bool{}}
	if len(argv) == 0 {
		return out
	}
	takes := spec.takes
	if takes == nil {
		takes = map[string]bool{}
	}
	rec := map[string]bool{}
	for _, r := range spec.rec {
		rec[r] = true
	}
	args := argv[1:]
	for i := 0; i < len(args); i++ {
		w := args[i]
		if w == "--" {
			out.ops = append(out.ops, args[i+1:]...)
			break
		}
		if strings.HasPrefix(w, "--") {
			name := strings.TrimPrefix(w, "--")
			val := ""
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				val = name[eq+1:]
				name = name[:eq]
			}
			out.seen[name] = true
			if rec[name] {
				out.rec = true
			}
			if takes[name] && val == "" && i+1 < len(args) {
				i++
			}
			continue
		}
		if strings.HasPrefix(w, "-") && len(w) > 1 && !strings.HasPrefix(w, "-/") {
			cluster := w[1:]
			for j := 0; j < len(cluster); j++ {
				c := string(cluster[j])
				out.seen[c] = true
				if rec[c] {
					out.rec = true
				}
				if takes[c] {
					rest := cluster[j+1:]
					if rest == "" && i+1 < len(args) {
						i++
					}
					break
				}
			}
			continue
		}
		out.ops = append(out.ops, w)
	}
	return out
}

func operandsLoose(argv []string) []string {
	if len(argv) < 2 {
		return nil
	}
	return parseArgs(argv, flagSet{}).ops
}

func base(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func hasSub(argv []string, flag string) bool {
	for _, w := range argv {
		if w == flag || strings.HasPrefix(w, flag+"=") {
			return true
		}
	}
	return false
}

func hasShort(argv []string, c byte) bool {
	for _, w := range argv[1:] {
		if strings.HasPrefix(w, "--") || !strings.HasPrefix(w, "-") || w == "-" {
			continue
		}
		if strings.ContainsRune(w[1:], rune(c)) {
			return true
		}
	}
	return false
}

func isWrapper(name string) bool {
	switch name {
	case "timeout", "nice", "ionice", "setsid", "nohup", "flock", "watch", "stdbuf", "env", "command":
		return true
	default:
		return false
	}
}

func unwrapWrapper(name string, argv []string) []string {
	args := argv[1:]
	switch name {
	case "env":
		i := 0
		for i < len(args) {
			w := args[i]
			if w == "--" {
				i++
				break
			}
			if strings.HasPrefix(w, "-") {
				if (w == "-u" || w == "-C" || w == "--unset" || w == "--chdir") && i+1 < len(args) {
					i += 2
					continue
				}
				i++
				continue
			}
			if strings.Contains(w, "=") && !strings.HasPrefix(w, "=") {
				i++
				continue
			}
			break
		}
		return args[i:]
	case "timeout":
		i := 0
		for i < len(args) {
			if strings.HasPrefix(args[i], "-") {
				if (args[i] == "--signal" || args[i] == "-s" || args[i] == "--kill-after" || args[i] == "-k") && i+1 < len(args) {
					i += 2
					continue
				}
				i++
				continue
			}
			i++ // duration
			break
		}
		return args[i:]
	case "nice":
		i := 0
		for i < len(args) {
			if args[i] == "-n" || args[i] == "--adjustment" {
				i += 2
				continue
			}
			if strings.HasPrefix(args[i], "-") {
				i++
				continue
			}
			break
		}
		return args[i:]
	case "ionice":
		i := 0
		for i < len(args) {
			if strings.HasPrefix(args[i], "-") {
				if (args[i] == "-c" || args[i] == "-n" || args[i] == "-p" || args[i] == "-t") && i+1 < len(args) && !strings.HasPrefix(args[i], "--") {
					i += 2
					continue
				}
				i++
				continue
			}
			break
		}
		return args[i:]
	case "flock":
		i := 0
		for i < len(args) {
			if strings.HasPrefix(args[i], "-") {
				i++
				continue
			}
			i++ // lock file
			break
		}
		return args[i:]
	case "watch":
		i := 0
		for i < len(args) {
			if strings.HasPrefix(args[i], "-") {
				if (args[i] == "-n" || args[i] == "-d" || args[i] == "-e") && i+1 < len(args) {
					i += 2
					continue
				}
				i++
				continue
			}
			break
		}
		return args[i:]
	default:
		i := 0
		for i < len(args) && strings.HasPrefix(args[i], "-") {
			i++
		}
		return args[i:]
	}
}
