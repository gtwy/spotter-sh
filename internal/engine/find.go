// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

type findSpec struct {
	roots     []string
	delete    bool
	execPlus  bool
	execPer   bool
	execArgv  []string
	execSlot  int
	narrow    bool
	selective bool
	modeled   bool
	maxDepth  int
	minDepth  int
	names     []string
	iname     []string
	types     string
	// follow is -L/-follow. followArg is -H (command-line symlink only).
	follow      bool
	followArg   bool
	expr        *fnode
	nameGuarded bool
}

// fnode is a find expression. Juxtaposition is AND and short-circuits.
// -o is OR and short-circuits. An action runs only when evaluation reaches it,
// so -delete before -name deletes every entry and -name before -delete does not.
type fnode struct {
	op       string
	kids     []*fnode
	val      string
	execPlus bool
	execPer  bool
	execArgv []string
	execSlot int
}

func parseFind(argv []string) findSpec {
	spec := findSpec{maxDepth: -1, modeled: true, execSlot: -1}
	p := findParser{args: argv[1:], spec: &spec}
	spec.expr = p.parseComma()
	if spec.expr == nil {
		spec.expr = &fnode{op: "true"}
	}
	acts, guarded := spec.expr.countActions(false)
	spec.nameGuarded = acts > 0 && guarded == acts
	return spec
}

type findParser struct {
	args []string
	i    int
	spec *findSpec
}

func (p *findParser) peek() string {
	if p.i >= len(p.args) {
		return ""
	}
	return p.args[p.i]
}

func (p *findParser) parseComma() *fnode {
	left := p.parseOr()
	for p.peek() == "," {
		p.i++
		right := p.parseOr()
		left = &fnode{op: "comma", kids: []*fnode{left, right}}
	}
	return left
}

func (p *findParser) parseOr() *fnode {
	left := p.parseAnd()
	for p.peek() == "-o" || p.peek() == "-or" {
		p.i++
		right := p.parseAnd()
		left = &fnode{op: "or", kids: []*fnode{left, right}}
	}
	return left
}

func (p *findParser) parseAnd() *fnode {
	var kids []*fnode
	for p.i < len(p.args) {
		w := p.peek()
		if w == "-o" || w == "-or" || w == ")" || w == "," {
			break
		}
		if w == "-a" || w == "-and" {
			p.i++
			continue
		}
		if k := p.parsePrimary(); k != nil {
			kids = append(kids, k)
		}
	}
	if len(kids) == 0 {
		return &fnode{op: "true"}
	}
	if len(kids) == 1 {
		return kids[0]
	}
	return &fnode{op: "and", kids: kids}
}

func (p *findParser) parsePrimary() *fnode {
	if p.i >= len(p.args) {
		return nil
	}
	w := p.args[p.i]
	switch w {
	case "!", "-not":
		p.i++
		return &fnode{op: "not", kids: []*fnode{p.parsePrimary()}}
	case "(":
		p.i++
		n := p.parseComma()
		if p.peek() == ")" {
			p.i++
		}
		return n
	case ")":
		return nil
	}
	if !strings.HasPrefix(w, "-") {
		p.spec.roots = append(p.spec.roots, w)
		p.i++
		return nil
	}
	p.i++
	switch w {
	case "-delete":
		p.spec.delete = true
		return &fnode{op: "delete"}
	case "-exec", "-execdir", "-ok", "-okdir":
		// parsePrimary already consumed the -exec word. findExec expects that index.
		form, cmd, words, slot, next := findExec(p.args, p.i-1)
		p.i = next + 1
		p.spec.execArgv = words
		p.spec.execSlot = slot
		per := false
		if form == "+" {
			p.spec.execPlus = true
		} else if cmd == "rm" || cmd == "sh" || cmd == "bash" || cmd == "dash" || cmd == "zsh" || cmd == "chmod" || cmd == "chown" || cmd == "chgrp" || cmd == "mv" || cmd == "cp" || cmd == "truncate" {
			p.spec.execPer = true
			per = true
		}
		return &fnode{op: "exec", execPlus: form == "+", execPer: per, execArgv: words, execSlot: slot}
	case "-follow":
		p.spec.follow = true
		return nil
	case "-H":
		p.spec.followArg = true
		return nil
	case "-L":
		p.spec.follow = true
		return nil
	case "-P":
		return nil
	}
	if !findTakes(w) {
		// Options such as -xdev are not predicates. They do not hide a later action.
		return nil
	}
	if p.i >= len(p.args) {
		return &fnode{op: "other"}
	}
	val := p.args[p.i]
	p.i++
	switch strings.TrimPrefix(w, "-") {
	case "name":
		p.spec.names = append(p.spec.names, val)
		p.spec.narrow = true
		p.spec.selective = true
		return &fnode{op: "name", val: val}
	case "iname":
		p.spec.iname = append(p.spec.iname, val)
		p.spec.narrow = true
		p.spec.selective = true
		return &fnode{op: "iname", val: val}
	case "path", "ipath", "regex", "iregex", "wholename", "iwholename":
		p.spec.narrow = true
		p.spec.selective = true
		p.spec.modeled = false
		return &fnode{op: "other", val: val}
	case "type", "xtype":
		if val != "" {
			p.spec.types = val[:1]
		}
		p.spec.narrow = true
		return &fnode{op: "type", val: val}
	case "maxdepth":
		p.spec.maxDepth = atoi(val)
		p.spec.narrow = true
		return nil
	case "mindepth":
		p.spec.minDepth = atoi(val)
		p.spec.narrow = true
		return nil
	default:
		p.spec.narrow = true
		p.spec.selective = true
		p.spec.modeled = false
		return &fnode{op: "other", val: val}
	}
}

func (n *fnode) isNameTest() bool {
	return n != nil && (n.op == "name" || n.op == "iname")
}

// countActions reports destructive actions and how many are reached only
// after a positive -name or -iname in the same AND chain.
func (n *fnode) countActions(gated bool) (actions, guarded int) {
	if n == nil {
		return 0, 0
	}
	switch n.op {
	case "and":
		g := gated
		for _, k := range n.kids {
			if k.isNameTest() {
				g = true
			}
			a, gd := k.countActions(g)
			actions += a
			guarded += gd
		}
		return actions, guarded
	case "or", "comma":
		for _, k := range n.kids {
			a, gd := k.countActions(gated)
			actions += a
			guarded += gd
		}
		return actions, guarded
	case "not":
		if len(n.kids) == 1 {
			return n.kids[0].countActions(gated)
		}
		return 0, 0
	case "delete", "exec":
		if gated {
			return 1, 1
		}
		return 1, 0
	default:
		return 0, 0
	}
}

// effects reports whether evaluation reaches -delete or -exec for this entry.
// truth is the predicate result. AND and OR stop early, so a test after an
// action does not protect the entry, and a test before it does.
func (n *fnode) effects(name string, mode fs.FileMode) (del, ex, truth bool) {
	if n == nil {
		return false, false, true
	}
	switch n.op {
	case "true", "other":
		return false, false, true
	case "and":
		truth = true
		for _, k := range n.kids {
			d, e, t := k.effects(name, mode)
			del = del || d
			ex = ex || e
			if !t {
				truth = false
				return del, ex, false
			}
		}
		return del, ex, true
	case "or":
		for _, k := range n.kids {
			d, e, t := k.effects(name, mode)
			del = del || d
			ex = ex || e
			if t {
				return del, ex, true
			}
		}
		return del, ex, false
	case "comma":
		truth = true
		for i, k := range n.kids {
			d, e, t := k.effects(name, mode)
			del = del || d
			ex = ex || e
			if i == len(n.kids)-1 {
				truth = t
			}
		}
		return del, ex, truth
	case "not":
		if len(n.kids) == 0 {
			return false, false, true
		}
		d, e, t := n.kids[0].effects(name, mode)
		return d, e, !t
	case "name":
		m, _ := filepath.Match(n.val, name)
		return false, false, m
	case "iname":
		m, _ := filepath.Match(strings.ToLower(n.val), strings.ToLower(name))
		return false, false, m
	case "type":
		return false, false, findType(mode, n.val)
	case "delete":
		return true, false, true
	case "exec":
		return false, true, true
	default:
		return false, false, true
	}
}

func findType(mode fs.FileMode, want string) bool {
	if want == "" {
		return true
	}
	want = want[:1]
	got := "f"
	if mode.IsDir() {
		got = "d"
	} else if mode&os.ModeSymlink != 0 {
		got = "l"
	}
	return want == got
}

// touches is true when this entry would be handed to -delete or -exec.
func (spec findSpec) touches(name string, mode fs.FileMode) bool {
	if spec.expr == nil {
		return true
	}
	del, ex, _ := spec.expr.effects(name, mode)
	if spec.delete && del {
		return true
	}
	if (spec.execPlus || spec.execPer) && ex && !spec.delete {
		return true
	}
	return false
}

// markerInTree reports a .spotter-sh-protect file at root or underneath it.
// A walk that hits the deadline is a timeout, which the caller catches.
func (in Input) markerInTree(root string, maxDepth int) (hit bool, timed bool) {
	name := in.Config.Paths.MarkerFile
	if name == "" {
		name = ".spotter-sh-protect"
	}
	deadline := in.walkDeadline()
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return false, false
	}
	if !info.IsDir() {
		if _, err := os.Lstat(filepath.Join(filepath.Dir(root), name)); err == nil {
			return true, false
		}
		return false, false
	}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if !deadline.IsZero() && time.Now().After(deadline) {
			timed = true
			return fs.SkipAll
		}
		if err != nil || d == nil {
			return nil
		}
		depth := 0
		if rel, relErr := filepath.Rel(root, p); relErr == nil && rel != "." {
			depth = strings.Count(rel, string(os.PathSeparator)) + 1
		}
		// -maxdepth stops the walk. A marker deeper than that is not deleted.
		if maxDepth >= 0 && depth > maxDepth {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() == name {
			hit = true
			return fs.SkipAll
		}
		if d.IsDir() && maxDepth >= 0 && depth >= maxDepth {
			return fs.SkipDir
		}
		return nil
	})
	return hit, timed
}

func findExec(args []string, i int) (form, cmd string, words []string, slot, next int) {
	slot = -1
	j := i + 1
	for j < len(args) {
		if args[j] == "+" || args[j] == `\;` || args[j] == ";" {
			form = ";"
			if args[j] == "+" {
				form = "+"
			}
			if len(words) > 0 {
				cmd = base(words[0])
			}
			if slot < 0 {
				slot = len(words)
			}
			return form, cmd, words, slot, j
		}
		if args[j] == "{}" || args[j] == "'{}'" {
			if slot < 0 {
				slot = len(words)
			}
		} else {
			words = append(words, args[j])
		}
		j++
	}
	if len(words) > 0 {
		cmd = base(words[0])
	}
	if slot < 0 {
		slot = len(words)
	}
	return "", cmd, words, slot, len(args) - 1
}

func findTakes(w string) bool {
	switch w {
	case "-name", "-iname", "-path", "-ipath", "-regex", "-iregex",
		"-wholename", "-iwholename", "-lname", "-ilname",
		"-type", "-xtype", "-user", "-group", "-uid", "-gid", "-perm", "-size",
		"-mtime", "-atime", "-ctime", "-mmin", "-amin", "-cmin", "-used",
		"-newer", "-anewer", "-cnewer", "-newermt", "-newerct", "-newerat",
		"-fstype", "-context", "-samefile", "-links", "-inum",
		"-maxdepth", "-mindepth", "-printf", "-fprintf", "-fprint", "-fls", "-fprint0":
		return true
	default:
		return false
	}
}

// countFind counts entries find -delete would remove under one root.
// Option values are not roots. The starting directory itself is not counted.
func countFind(root string, spec findSpec, deadline time.Time) (n, partial int, timed bool) {
	var files, dirs int
	var walk func(string, int)
	walk = func(dir string, depth int) {
		if timed {
			return
		}
		dirs++
		if !deadline.IsZero() && time.Now().After(deadline) {
			timed = true
			partial = files + dirs
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for i, e := range entries {
			if timed {
				return
			}
			if i&31 == 0 && !deadline.IsZero() && time.Now().After(deadline) {
				timed = true
				partial = files + dirs
				return
			}
			p := filepath.Join(dir, e.Name())
			mode := e.Type()
			childDepth := depth + 1
			if spec.maxDepth >= 0 && childDepth > spec.maxDepth {
				continue
			}
			if childDepth >= spec.minDepth && spec.touches(e.Name(), mode) {
				files++
				n++
			}
			if mode.IsDir() && mode&os.ModeSymlink == 0 {
				walk(p, childDepth)
			}
		}
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		if err == nil && spec.touches(filepath.Base(root), info.Mode()) {
			return 1, 0, false
		}
		return 0, 0, false
	}
	walk(root, 0)
	if timed && partial == 0 {
		partial = files + dirs
	}
	return n, partial, timed
}

// listFind returns the paths find would hand to -delete or -exec.
// The starting point is included when it matches. over is set once limit
// is passed so the caller can apply the bulk threshold without a full walk.
func (in Input) listFind(root string, spec findSpec, limit int) (paths []string, timed, over bool) {
	if limit < 1 {
		limit = 1
	}
	deadline := in.walkDeadline()
	add := func(p string) bool {
		paths = append(paths, p)
		if len(paths) > limit {
			over = true
			return false
		}
		return true
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, false, false
	}
	if info.Mode()&os.ModeSymlink != 0 && !spec.follow {
		if spec.minDepth <= 0 && spec.touches(filepath.Base(root), info.Mode()) {
			add(root)
		}
		return paths, false, over
	}
	if !info.IsDir() {
		if spec.minDepth <= 0 && spec.touches(filepath.Base(root), info.Mode()) {
			add(root)
		}
		return paths, false, over
	}
	if spec.minDepth <= 0 && spec.touches(filepath.Base(root), info.Mode()) {
		if !add(root) {
			return paths, false, true
		}
	}
	var walk func(string, int)
	walk = func(dir string, depth int) {
		if timed || over {
			return
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			timed = true
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for i, e := range entries {
			if timed || over {
				return
			}
			if i&31 == 0 && !deadline.IsZero() && time.Now().After(deadline) {
				timed = true
				return
			}
			p := filepath.Join(dir, e.Name())
			mode := e.Type()
			if spec.follow && mode&os.ModeSymlink != 0 {
				if st, err := os.Stat(p); err == nil {
					mode = st.Mode()
				}
			}
			childDepth := depth + 1
			if spec.maxDepth >= 0 && childDepth > spec.maxDepth {
				continue
			}
			if childDepth >= spec.minDepth && spec.touches(e.Name(), mode) {
				if !add(p) {
					return
				}
			}
			if mode.IsDir() && (spec.follow || mode&os.ModeSymlink == 0) {
				walk(p, childDepth)
			}
		}
	}
	walk(root, 0)
	return paths, timed, over
}

func findMatch(name string, info os.FileInfo, spec findSpec) bool {
	if spec.types != "" {
		want := spec.types
		got := "f"
		if info.IsDir() {
			got = "d"
		} else if info.Mode()&os.ModeSymlink != 0 {
			got = "l"
		}
		if want != got {
			return false
		}
	}
	if len(spec.names) > 0 {
		ok := false
		for _, pat := range spec.names {
			if m, _ := filepath.Match(pat, name); m {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(spec.iname) > 0 {
		ok := false
		low := strings.ToLower(name)
		for _, pat := range spec.iname {
			if m, _ := filepath.Match(strings.ToLower(pat), low); m {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// countRsyncDelete counts dest entries that are absent from every source.
// That is what --delete would remove, not the size of the destination.
func countRsyncDelete(srcs, dests []string, deadline time.Time) (n, partial int, timed bool) {
	for _, dest := range dests {
		c, part, to := countExtras(srcs, dest, deadline)
		n += c
		partial += part
		if to {
			return n, partial, true
		}
	}
	return n, partial, false
}

func countExtras(srcs []string, dest string, deadline time.Time) (n, partial int, timed bool) {
	st, err := os.Lstat(dest)
	if err != nil || !st.IsDir() {
		return 0, 0, false
	}
	var walk func(string)
	walk = func(dir string) {
		if timed {
			return
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			timed = true
			partial = n
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if timed {
				return
			}
			if !deadline.IsZero() && time.Now().After(deadline) {
				timed = true
				partial = n
				return
			}
			p := filepath.Join(dir, e.Name())
			rel, err := filepath.Rel(dest, p)
			if err != nil {
				continue
			}
			if !presentInAny(srcs, rel) {
				n++
				partial = n
			}
			info, err := e.Info()
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			walk(p)
		}
	}
	walk(dest)
	return n, partial, timed
}

func presentInAny(srcs []string, rel string) bool {
	if len(srcs) == 0 {
		return false
	}
	for _, src := range srcs {
		if src == "" {
			continue
		}
		if _, err := os.Lstat(filepath.Join(src, rel)); err == nil {
			return true
		}
	}
	return false
}
