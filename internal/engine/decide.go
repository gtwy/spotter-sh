// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"context"
	"github.com/gtwy/spotter-sh/internal/envx"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gtwy/spotter-sh/internal/config"
	"github.com/gtwy/spotter-sh/internal/precheck"
)

// Input is one already-expanded command.
type Input struct {
	Argv      []string
	Cwd       string
	Env       []string
	Home      string
	StdinKind string // pipe, file, null, tty, other
	StdinPeek []byte
	Config    config.Config
	Hostname  string
	Deadline  time.Time
	GitStatus func(cwd string) (string, error)
	StashN    func(cwd string) (int, error)
}

// Decide classifies argv. It does not execute the command.
func Decide(in Input) Outcome {
	if in.Cwd == "" {
		in.Cwd, _ = os.Getwd()
	}
	if in.Config.Mode == "" {
		in.Config = config.Defaults()
	}
	if len(in.Argv) == 0 {
		return allow()
	}
	name := base(in.Argv[0])
	argv := in.Argv

	if name == "busybox" || name == "toybox" || name == "coreutils" {
		if len(argv) < 2 {
			return fallthroughAllow()
		}
		in.Argv = argv[1:]
		return Decide(in)
	}
	if name == "sudo" || name == "doas" {
		return decideSudo(in, name)
	}
	if o, ok := in.decideLauncher(argv); ok {
		return o
	}
	if isWrapper(name) {
		if inner := unwrapWrapper(name, argv); len(inner) > 0 {
			in.Argv = inner
			return Decide(in)
		}
	}
	for _, pack := range extraPacks() {
		if o := pack(argv, in.Cwd); o != nil {
			return in.render(*o, argv)
		}
	}
	kind, pack := commandKind(name)
	if kind == "" || !in.Config.PackEnabled(pack, name) {
		return in.decideUnknown(argv)
	}
	var o Outcome
	switch kind {
	case "rm":
		o = in.decideRemove(argv, true)
	case "rmdir", "unlink", "shred", "trash-put":
		o = in.decideRemove(argv, false)
	case "chmod", "chown", "chgrp", "setfacl":
		o = in.decidePerm(name, argv)
	case "cp", "mv", "ln", "install":
		o = in.decideCopy(name, argv)
	case "rsync":
		o = in.decideRsync(argv)
	case "dd":
		o = in.decideDD(argv)
	case "find":
		o = in.decideFind(argv)
	case "shell":
		o = in.decideShell(argv)
	case "tar", "unzip", "sed", "perl", "truncate":
		o = in.decideOverwriteTool(name, argv)
	case "git":
		o = in.decideGit(argv)
	case "mysql", "mariadb", "psql", "sqlite3", "mongosh", "mongo", "redis-cli", "clickhouse-client", "cockroach":
		o = in.decideDB(name, argv)
	case "docker", "kubectl", "helm", "terraform", "aws", "gcloud", "gsutil", "crontab", "systemctl", "iptables", "userdel":
		o = in.decideInfra(name, argv)
	case "reboot", "shutdown", "halt", "poweroff":
		o = in.decidePower(name, argv)
	case "mkfs", "wipefs", "blkdiscard", "fdisk", "sgdisk", "parted":
		o = in.decideDiskTool(name, argv)
	default:
		if strings.HasPrefix(name, "mkfs.") {
			o = in.decideDiskTool(name, argv)
		} else {
			o = in.decideUnknown(argv)
		}
	}
	return in.render(o, argv)
}

func fallthroughAllow() Outcome {
	o := allow()
	o.ParseFallthrough = true
	o.LogNote = "parse_fallthrough"
	return o
}

func (in Input) decideUnknown(argv []string) Outcome {
	// Still honor resolved operands that are independently protected.
	ops := operandsLoose(argv)
	targets := in.resolveAll(ops)
	if why, ok := in.sweepNode(targets); ok {
		return in.danger("A", "protected path", why, "the operand set is a protected directory", "narrow the paths", targets, "delete")
	}
	for _, t := range targets {
		if hit, ok := in.protected(t); ok {
			return in.danger("E", "protected path", hit.Reason, "this path is protected", "leave it out", targets, "delete")
		}
		if isAncestor(t, in.Cwd) {
			return in.danger("A", "parent of cwd", t+" is a parent of the working directory", "a relative path walked upward", "name the directory you mean", targets, "delete")
		}
	}
	return fallthroughAllow()
}

func commandKind(name string) (kind, pack string) {
	switch name {
	case "rm", "rmdir", "unlink", "shred", "trash-put", "chmod", "chown", "chgrp", "setfacl",
		"cp", "mv", "ln", "install", "rsync", "dd", "find", "tar", "unzip", "sed", "perl", "truncate":
		return name, "files"
	case "bash", "sh", "dash", "zsh", "ksh":
		return "shell", "files"
	case "git":
		return name, "git"
	case "mysql", "mariadb", "psql", "sqlite3", "mongosh", "mongo", "redis-cli", "clickhouse-client", "cockroach":
		return name, "db"
	case "docker", "kubectl", "helm", "terraform", "aws", "gcloud", "gsutil", "crontab", "systemctl", "iptables", "userdel":
		return name, "infra"
	case "reboot", "shutdown", "halt", "poweroff":
		return name, "power"
	case "mkfs", "wipefs", "blkdiscard", "fdisk", "sgdisk", "parted":
		return name, "files"
	default:
		if strings.HasPrefix(name, "mkfs.") {
			return name, "files"
		}
		return "", ""
	}
}

func (in Input) decideRemove(argv []string, asRM bool) Outcome {
	p := parseArgs(argv, flagSet{
		rec:   []string{"r", "R", "recursive"},
		takes: nil,
	})
	// A directory glob is not one symlink. ~/ws/*/ follows every match
	// under a project folder. That is an approvable catch, including when
	// a parent link would otherwise collapse the star onto /.
	if p.rec {
		if why, ok := approvableGlob(p.ops, in.Home); ok {
			o := in.danger("E", "glob-delete", why, "a directory glob follows every match", "name the directories", p.ops, "recursive-delete")
			o.Approve = true
			return o
		}
	}
	targets := in.resolveDeletes(p.ops)
	if len(targets) == 0 {
		return allow()
	}
	// A recursive delete of /, of the home directory, of every top-level
	// directory (what bash expands /* into), or of a symlink that follows
	// to / is never approvable. Bash has already expanded the spelling.
	// A glob operand is not that target: the star was not expanded here.
	rootOps := p.ops
	if p.rec {
		rootOps = dropGlobOperands(p.ops)
	}
	if why, ok := in.blockedRoot(append(append([]string{}, rootOps...), targets...), p.rec); ok {
		return hardRoot(base(argv[0]), why)
	}
	for _, op := range append(append([]string{}, p.ops...), targets...) {
		if isSystemDiskPath(op) || isBlockDev(op) {
			return hardDisk(base(argv[0]))
		}
	}
	op := "delete"
	if p.rec {
		op = "recursive-delete"
	}
	if o, ok := in.brainDelete(targets); ok {
		return o
	}
	if o, ok := in.logWipe(targets, p.rec); ok {
		return o
	}
	if o, ok := in.forceTargets(targets, "A", op); ok {
		return o
	}
	// -r walks each directory, so one directory uses the tree threshold.
	// An expanded glob is already a list of paths. That list is a bulk
	// delete at the bulk threshold, including when -r is set.
	limit := in.Config.Thresholds.BulkTargets
	if limit <= 0 {
		limit = 100
	}
	if len(targets) > limit {
		return in.bulk("C", op, targets, "more than the bulk-delete threshold")
	}
	// A recursive directory is a tree, not one path. Several of them in the
	// home directory or another sensitive tree are a bulk delete even when
	// the operand count is still under the file threshold and each tree is
	// under the single-directory walk. One directory still uses that walk.
	if p.rec {
		if n := in.treeOperands(targets); n > 0 {
			// Four recursive directories in a home or sensitive tree meet
			// the flat file threshold. One directory still uses the tree walk.
			cost := limit / 4
			if cost < 1 {
				cost = 1
			}
			if n*cost >= limit {
				return in.bulk("C", op, targets, "recursive delete of several directories in a home or sensitive tree")
			}
		}
		for _, t := range targets {
			if systemDirNode(t) {
				return in.danger("E", "system-dir", "would recursively delete "+t, "that directory is a system tree", "name a path inside it, or leave it out", targets, op)
			}
		}
	}
	if !p.rec {
		if near(len(targets), limit) {
			o := allow()
			o.Near = true
			o.Affected.Count = len(targets)
			return o
		}
		return allow()
	}
	return in.treeOrAllow(targets, op, in.Config.Thresholds.TreeFiles, in.Config.Thresholds.TreeBytes)
}

// decideShell judges bash -c and the other shells. A script that Layer 1
// would catch or block does not get to run.
func (in Input) decideShell(argv []string) Outcome {
	script, ok := inlineC(argv)
	if !ok {
		return allow()
	}
	r := precheck.ScanAt(script, in.Cwd, in.Home)
	if r.Action != "hardblock" && r.Action != "catch" {
		return allow()
	}
	return outcomeFromPrecheck(r)
}

func (in Input) decidePerm(name string, argv []string) Outcome {
	p := parseArgs(argv, flagSet{rec: []string{"R", "r", "recursive"}})
	mode := ""
	var ops []string
	if name == "chmod" || name == "setfacl" {
		for _, op := range p.ops {
			if mode == "" && looksMode(op) {
				mode = op
				continue
			}
			ops = append(ops, op)
		}
	} else {
		// chown owner[:group] paths
		if len(p.ops) > 0 && strings.Contains(p.ops[0], ":") || (len(p.ops) > 0 && !strings.Contains(p.ops[0], "/") && !strings.HasPrefix(p.ops[0], ".")) {
			if len(p.ops) > 0 {
				mode = p.ops[0]
				ops = p.ops[1:]
			}
		} else {
			ops = p.ops
		}
	}
	targets := in.resolveAll(ops)
	if p.has("h") || p.seen["no-dereference"] {
		targets = in.resolveDeletes(ops)
	}
	if len(targets) == 0 {
		return allow()
	}
	if why, ok := in.blockedRoot(append(append([]string{}, ops...), targets...), p.rec); ok {
		return hardRoot(name, why)
	}
	op := name
	if p.rec {
		op = name + "-recursive"
	}
	if o, ok := in.forceTargets(targets, "E", op); ok {
		o.Affected.PermTo = mode
		o.Affected.PermFrom = "varies"
		return o
	}
	if br, path := in.permsBreak(targets, mode, p.rec); br {
		o := in.danger("E", "perms-break", "would change a required mode on "+path, "sensitive files have a required mode", "set the mode the file needs", targets, op)
		o.Affected.PermTo = mode
		o.Affected.PermFrom = "required"
		return o
	}
	if isAncestorAny(targets, in.Cwd) {
		o := in.danger("A", "parent of cwd", "a target is the parent of the working directory", "'.*' matches '..'", "use .[!.]*", targets, op)
		o.Affected.PermTo = mode
		return o
	}
	limit := in.Config.Thresholds.RecursivePermFiles
	if p.rec {
		return in.treeOrAllow(targets, op, limit, 0)
	}
	if len(targets) > in.Config.Thresholds.BulkTargets {
		return in.bulk("C", op, targets, "many permission changes")
	}
	return allow()
}

func (in Input) permsBreak(targets []string, mode string, rec bool) (bool, string) {
	if mode == "" {
		return false, ""
	}
	for _, t := range targets {
		if sensitiveBreak(t, mode) {
			return true, t
		}
	}
	if rec && (mode == "777" || mode == "0777" || strings.Contains(mode, "777")) {
		for _, t := range targets {
			if treeHasSetuid(t) {
				return true, t
			}
		}
	}
	return false, ""
}

func sensitiveBreak(path, mode string) bool {
	base := filepath.Base(path)
	low := strings.ToLower(path)
	if strings.Contains(low, "/.ssh/") || base == "authorized_keys" || isSSHKey(path) {
		m := strings.TrimLeft(mode, "0")
		if m != "600" && m != "400" && mode != "0600" && mode != "0400" {
			return true
		}
	}
	if path == "/tmp" || strings.HasSuffix(path, "/tmp") && stickyDir(path) {
		if !strings.Contains(mode, "1777") && mode != "1777" && !strings.Contains(mode, "+t") {
			if mode == "777" || mode == "0777" || mode == "755" {
				return true
			}
		}
	}
	if strings.HasPrefix(path, "/etc/sudoers") {
		m := strings.TrimLeft(mode, "0")
		if m != "440" && mode != "0440" {
			return true
		}
	}
	return false
}

func isSSHKey(path string) bool {
	base := filepath.Base(path)
	if strings.HasSuffix(base, ".pub") {
		return false
	}
	return strings.HasPrefix(base, "id_") && strings.Contains(path, ".ssh")
}

func stickyDir(path string) bool {
	st, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return st.IsDir() && st.Mode()&os.ModeSticky != 0
}

func treeHasSetuid(root string) bool {
	found := false
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.Mode()&os.ModeSetuid != 0 || info.Mode()&os.ModeSetgid != 0 {
			found = true
			return filepath.SkipAll
		}
		if info.IsDir() && p != root && strings.Count(p, string(os.PathSeparator))-strings.Count(root, string(os.PathSeparator)) > 2 {
			return filepath.SkipDir
		}
		return nil
	})
	return found
}

func (in Input) decideCopy(name string, argv []string) Outcome {
	p := parseArgs(argv, flagSet{rec: []string{"r", "R", "recursive"}, takes: map[string]bool{"t": true, "S": true, "target-directory": true}})
	tDest := optVal(argv, "t", "target-directory")
	if tDest == "" && len(p.ops) < 2 && name != "ln" {
		return allow()
	}
	ops := p.ops
	dest := ""
	var srcs []string
	if tDest != "" {
		dest = tDest
		srcs = append([]string{}, ops...)
	} else if len(ops) > 0 {
		dest = ops[len(ops)-1]
		srcs = ops[:len(ops)-1]
	}
	// mv keeps a bare symlink. ln -n/-h replaces the link instead of following it.
	follow := name != "mv"
	if name == "ln" && (p.has("n") || p.has("h") || p.has("no-dereference")) {
		follow = false
	}
	destRes := ""
	if dest != "" {
		destRes = in.resolveOneFollow(dest, follow)
	}
	srcRes := in.resolveAll(srcs)
	// mv of a symlink moves the link. A trailing slash follows it, which is
	// what mv and rm do with a directory operand.
	if name == "mv" {
		srcRes = in.resolveDeletes(srcs)
		for _, s := range append(append([]string{}, srcRes...), destRes) {
			if s == "/" {
				return hardSlash("mv")
			}
		}
		if o, ok := in.forceTargets(srcRes, "A", name+"-away"); ok {
			return o
		}
	}
	if destRes != "" {
		if isDir(destRes) && name != "ln" {
			seen := map[string]bool{}
			for _, s := range append(append([]string{}, srcs...), srcRes...) {
				baseName := filepath.Base(s)
				if baseName == "" || baseName == "." || baseName == ".." || seen[baseName] {
					continue
				}
				seen[baseName] = true
				child := filepath.Join(destRes, baseName)
				if underSystemBin(child) {
					return in.danger("E", "overwrite protected", "would create "+child, "a new file in a system directory is still that directory", "pick another destination", []string{child}, name)
				}
			}
		}
		if underSystemBin(destRes) && !isDir(destRes) {
			return in.danger("E", "overwrite protected", "destination is a system binary", "this would replace a program in a system directory", "pick another destination", []string{destRes}, name)
		}
		if hit, ok := in.protected(destRes); ok && !isDir(destRes) {
			return in.danger("E", "overwrite protected", "destination "+hit.Reason, "the destination is protected", "pick another destination", []string{destRes}, name)
		}
		// copying a file into a protected directory node (home) is allowed.
		if st, err := os.Lstat(destRes); err == nil && !st.IsDir() {
			if hit, ok := in.protected(destRes); ok {
				return in.danger("E", "overwrite protected", hit.Reason, "the file is protected", "pick another destination", []string{destRes}, name)
			}
		}
		if name == "ln" && (p.has("s") || p.has("symbolic")) {
			if hit, ok := in.protected(destRes); ok {
				// A link into an existing directory is a new name inside it.
				// Replacing the protected path itself, including with -f or -n, is a catch.
				if !isDir(destRes) || p.has("f") || p.has("force") || p.has("n") {
					return in.danger("E", "overwrite protected", hit.Reason, "the link destination is protected", "pick another path", []string{destRes}, "ln")
				}
			}
		}
	}
	// count existing files that would be clobbered
	n := existingCount(destRes, srcRes, p.rec)
	if n > in.Config.Thresholds.OverwriteFiles {
		return in.bulk("C", "overwrite", append(srcRes, destRes), "more than the overwrite threshold")
	}
	return allow()
}

func existingCount(dest string, srcs []string, rec bool) int {
	if dest == "" {
		return 0
	}
	st, err := os.Lstat(dest)
	if err != nil {
		return 0
	}
	if !st.IsDir() {
		return 1
	}
	n := 0
	for _, s := range srcs {
		cand := filepath.Join(dest, filepath.Base(s))
		if _, err := os.Lstat(cand); err == nil {
			n++
			if rec {
				w := walkTree(cand, 100000, 0, time.Now().Add(200*time.Millisecond))
				n += w.Files
			}
		}
	}
	return n
}

func (in Input) decideRsync(argv []string) Outcome {
	del := false
	dry := false
	var ops []string
	takes := map[string]bool{
		"-e": true, "--rsh": true, "--exclude": true, "--include": true,
		"--filter": true, "-f": true, "--files-from": true, "--backup-dir": true,
		"--chmod": true, "--chown": true, "--log-file": true, "-B": true,
		"--block-size": true, "--suffix": true, "--partial-dir": true,
		"--compare-dest": true, "--copy-dest": true, "--link-dest": true,
		"--exclude-from": true, "--include-from": true, "--out-format": true,
		"--password-file": true, "-M": true, "--remote-option": true,
	}
	args := argv[1:]
	for i := 0; i < len(args); i++ {
		w := args[i]
		if w == "--" {
			ops = append(ops, args[i+1:]...)
			break
		}
		if w == "--dry-run" || strings.HasPrefix(w, "--dry-run=") {
			dry = true
			continue
		}
		if strings.HasPrefix(w, "--delete") {
			del = true
			continue
		}
		if strings.HasPrefix(w, "--") {
			if !strings.Contains(w, "=") && takes[w] && i+1 < len(args) {
				i++
			}
			continue
		}
		if strings.HasPrefix(w, "-") {
			if strings.ContainsRune(w[1:], 'n') {
				dry = true
			}
			if takes[w] && i+1 < len(args) {
				i++
			}
			continue
		}
		ops = append(ops, w)
	}
	// -n and --dry-run change nothing.
	if dry {
		return allow()
	}
	if len(ops) == 0 {
		return allow()
	}
	dest := ops[len(ops)-1]
	if isRemote(dest) {
		if del {
			return in.bulk("C", "rsync --delete remote", nil, "remote delete cannot be counted")
		}
		o := allow()
		o.LogNote = "remote_target"
		return o
	}
	targets := in.resolveAll([]string{dest})
	if del {
		if o, ok := in.forceTargets(targets, "A", "rsync --delete"); ok {
			return o
		}
		srcs := ops[:len(ops)-1]
		n, partial, timed := countRsyncDelete(in.resolveAll(srcs), targets, in.walkDeadline())
		if timed {
			o := in.danger("C", "check timed out", "the check timed out", "a long scan likely means a very large target", "narrow the path", targets, "rsync --delete")
			o.Level = "bulk"
			o.Affected.TimedOut = true
			o.Affected.Partial = partial
			o.Affected.Count = partial
			return o
		}
		if n > in.Config.Thresholds.TreeFiles {
			o := in.bulk("C", "rsync --delete", targets, "more files would be deleted than the tree threshold")
			o.Affected.Count = n
			return o
		}
		return allow()
	}
	return allow()
}

func isRemote(s string) bool {
	if strings.HasPrefix(s, "rsync://") {
		return true
	}
	// host:/path but not a single-letter drive and not an absolute path
	if strings.Contains(s, ":") && !strings.HasPrefix(s, "/") && !strings.HasPrefix(s, ".") {
		return true
	}
	return false
}

func (in Input) decideDD(argv []string) Outcome {
	for _, w := range argv[1:] {
		if strings.HasPrefix(w, "of=") {
			dest := strings.TrimPrefix(w, "of=")
			if isSystemDiskPath(dest) {
				return hardDisk("dd")
			}
			r := in.resolveOne(dest)
			if underSystemBin(r) || underSystemBin(dest) {
				return in.danger("E", "dd protected", "system directory "+filepath.Dir(r), "dd would overwrite it", "write somewhere else", []string{r}, "dd")
			}
			if hit, ok := in.protected(r); ok {
				return in.danger("E", "dd protected", hit.Reason, "dd would overwrite it", "write somewhere else", []string{r}, "dd")
			}
		}
	}
	return allow()
}

func hardSlash(cmd string) Outcome {
	return hardRoot(cmd, "/")
}

func hardRoot(cmd, what string) Outcome {
	return Outcome{
		Action:      "hardblock",
		Level:       "hardblock",
		Case:        "root",
		Exit:        121,
		Consequence: cmd + " would change " + what + ".",
		Mistake:     "changing " + what + " is hard-blocked",
		Safer:       "a human runs it by hand if it is really intended",
		Message:     "Shell Spotter: BLOCKED — " + cmd + " aimed at " + what + ". This command is never allowed. If you truly mean it, a human must run it by hand.",
	}
}

// blockedRoot reports a non-approvable target. / is blocked even without
// -R. The home directory and a sweep of the top-level directories require
// a recursive operation, which find -delete always is.
func (in Input) blockedRoot(paths []string, rec bool) (string, bool) {
	var cleaned []string
	for _, t := range paths {
		switch t {
		case "/", "/*":
			return "/", true
		}
		// A tilde or $HOME that is still in argv was quoted or escaped.
		// Bash would have expanded a real one. The name is literal.
		c := filepath.Clean(t)
		if c == "/" {
			return "/", true
		}
		cleaned = append(cleaned, c)
	}
	if !rec {
		return "", false
	}
	for _, t := range cleaned {
		if in.homeRoot(t) {
			return "the home directory", true
		}
	}
	if coversSystemTop(cleaned) {
		return "the top-level directories", true
	}
	return "", false
}

func (in Input) homeRoot(path string) bool {
	path = filepath.Clean(path)
	if path == "" || path == "/" {
		return false
	}
	home := in.Home
	if home == "" {
		home = HomeDir()
	}
	if home != "" && path == filepath.Clean(home) {
		return true
	}
	if path == "/root" {
		return true
	}
	if strings.HasPrefix(path, "/home/") {
		rest := strings.TrimPrefix(path, "/home/")
		if rest != "" && !strings.Contains(rest, string(os.PathSeparator)) {
			if st, err := os.Lstat(path); err == nil && st.IsDir() {
				return true
			}
		}
	}
	return false
}

// coversSystemTop is bash's /* : every top-level directory that makes a
// root wipe, not one directory on its own.
func coversSystemTop(paths []string) bool {
	set := map[string]struct{}{}
	for _, t := range paths {
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

func hardDisk(name string) Outcome {
	return Outcome{
		Action:      "hardblock",
		Level:       "hardblock",
		Case:        "disk",
		Exit:        121,
		Consequence: name + " would write a raw disk.",
		Mistake:     "raw disk tools are hard-blocked",
		Safer:       "a human runs it by hand if it is really intended",
		Message:     "Shell Spotter: BLOCKED — " + name + " aimed at a disk. This command is never allowed. If you truly mean it, a human must run it by hand (/bin/" + name + ").",
	}
}

func isSystemDiskPath(p string) bool {
	return strings.HasPrefix(p, "/dev/sd") || strings.HasPrefix(p, "/dev/hd") || strings.HasPrefix(p, "/dev/nvme") || strings.HasPrefix(p, "/dev/mapper/") || strings.HasPrefix(p, "/dev/mmcblk") || strings.HasPrefix(p, "/dev/vd") || strings.HasPrefix(p, "/dev/xvd")
}

func (in Input) decideFind(argv []string) Outcome {
	spec := parseFind(argv)
	// rm \; is still one file at a time. mv and chmod \; are the bulk
	// command on the match set, including sudo find / -exec chmod.
	if spec.execPer && !spec.delete && !spec.execPlus && !judgedPerFile(spec) && !judgedSlowPer(spec) {
		o := allow()
		o.LogNote = "per_file_exec"
		return o
	}
	if !spec.delete && !spec.execPlus && !spec.execPer {
		return allow()
	}
	roots := spec.roots
	if len(roots) == 0 {
		roots = []string{"."}
	}
	targets := in.resolveFindRoots(roots, spec)
	home := ""
	if in.Home != "" {
		home = filepath.Clean(in.Home)
	}
	// A name test only filters an action that is evaluated after it.
	// -delete -name still deletes every entry.
	nameFiltered := spec.nameGuarded
	if why, ok := in.blockedRoot(targets, true); ok {
		// A name or depth filter under the home directory deletes matches,
		// not the home directory itself. / and a /* sweep do not.
		if why == "/" || !(nameFiltered || spec.narrow) {
			return hardRoot("find", why)
		}
	}
	for _, t := range targets {
		if t == "/" {
			return hardSlash("find")
		}
		if isMountRoot(t) && t != in.Cwd {
			if (spec.execPlus || spec.execPer) && (execCommand(spec) == "chmod" || execCommand(spec) == "mv") {
				return hardSlash(execCommand(spec))
			}
			return in.danger("A", "find-delete", t+" is a filesystem root", "find -delete from a root walks the machine", "start inside the directory you mean", targets, "find-delete")
		}
		hit, prot := in.protected(t)
		if !prot {
			continue
		}
		// A name filter deletes matches, not the search root. An empty
		// match set, one brain note, or a log name that matches nothing
		// is not a wipe of .config or the home directory.
		if nameFiltered {
			continue
		}
		// A narrowed search in the home directory deletes matches, not the home node.
		if spec.narrow && home != "" && t == home {
			continue
		}
		// A marker deeper than -maxdepth is not deleted. The depth-limited
		// walk below decides. An FHS node still catches with -maxdepth set.
		if spec.maxDepth >= 0 && strings.Contains(hit.Reason, ".spotter-sh-protect") {
			continue
		}
		return in.danger("E", "protected path", hit.Reason, "this path is protected", "leave it out", targets, "find-delete")
	}
	// -type and -mindepth still wipe /var/log. A name or path predicate does not.
	if !spec.selective {
		if o, ok := in.logWipe(targets, true); ok {
			return o
		}
	}
	// find -exec cmd {} + and judged \; forms use the paths find would pass.
	// An unknown exec is not rewritten as a delete of the search root.
	if (spec.execPlus || spec.execPer) && !spec.delete {
		if judgedExec(spec) {
			o, ok := in.judgeExecPlus(spec, targets)
			if !ok {
				return allow()
			}
			return o
		}
		if spec.execPer {
			o := allow()
			o.LogNote = "per_file_exec"
			return o
		}
		return allow()
	}
	// -delete of a name filter, or of a modeled depth/type filter, counts
	// the files find would remove. The bulk threshold is the same 100
	// find -exec rm {} + uses. The search root is not the target.
	if spec.delete && (nameFiltered || spec.modeled) {
		return in.judgeDelete(spec, targets)
	}
	for _, t := range targets {
		hit, timed := in.markerInTree(t, spec.maxDepth)
		if timed {
			o := in.danger("C", "check timed out", "the check timed out", "a long scan likely means a very large target", "narrow the path", targets, "find-delete")
			o.Level = "bulk"
			o.Affected.TimedOut = true
			o.Affected.Partial = 1
			o.Affected.Count = 1
			return o
		}
		if hit {
			return in.danger("E", "protected path", "directory marked .spotter-sh-protect", "a match is inside a protected directory", "leave that directory out", targets, "find-delete")
		}
	}
	if spec.narrow {
		return in.findScoped(spec, targets)
	}
	return in.treeOrAllow(targets, "find-delete", in.Config.Thresholds.TreeFiles, in.Config.Thresholds.TreeBytes)
}

// judgeExecPlus applies the exec command to the files find actually matches.
// The search root is not substituted, and -r is not invented. A handful of
// files under . or ~ stays under the bulk threshold. A few hundred files hits it.
func (in Input) judgeExecPlus(spec findSpec, roots []string) (Outcome, bool) {
	if len(spec.execArgv) == 0 {
		return Outcome{}, false
	}
	baseArgv := spec.execArgv
	slot := spec.execSlot
	if pre, ok := rewriteShellExec(spec.execArgv); ok {
		baseArgv = pre
		slot = len(pre)
	}
	name := base(baseArgv[0])
	switch name {
	case "rm", "unlink", "shred", "rmdir", "chmod", "chown", "chgrp", "setfacl", "mv", "cp", "truncate":
	default:
		return Outcome{}, false
	}
	limit := in.execMatchLimit(name, baseArgv)
	var matches []string
	for _, root := range roots {
		paths, timed, over := in.listFind(root, spec, limit+1)
		if timed {
			o := in.danger("C", "check timed out", "the check timed out", "a long scan likely means a very large target", "narrow the path", roots, "find-exec")
			o.Level = "bulk"
			o.Affected.TimedOut = true
			o.Affected.Partial = len(paths)
			o.Affected.Count = len(paths)
			return o, true
		}
		matches = append(matches, paths...)
		if over || len(matches) > limit {
			break
		}
	}
	if len(matches) == 0 {
		return allow(), true
	}
	if slot < 0 || slot > len(baseArgv) {
		slot = len(baseArgv)
	}
	argv := append([]string{}, baseArgv[:slot]...)
	argv = append(argv, matches...)
	argv = append(argv, baseArgv[slot:]...)
	switch name {
	case "rm", "unlink", "shred", "rmdir":
		return in.decideRemove(argv, name == "rm" || name == "shred"), true
	case "mv", "cp":
		return in.decideCopy(name, argv), true
	case "truncate":
		z := append([]string{"truncate", "-s", "0"}, matches...)
		return in.decideOverwriteTool("truncate", z), true
	default:
		return in.decidePerm(name, argv), true
	}
}

// rewriteShellExec turns `sh -c 'rm "$@"' _` into rm so the match set is
// judged as the command the shell would run. The placeholder before {} is $0.
func rewriteShellExec(argv []string) ([]string, bool) {
	if len(argv) == 0 {
		return nil, false
	}
	switch base(argv[0]) {
	case "sh", "bash", "dash", "zsh", "ksh":
	default:
		return nil, false
	}
	script := ""
	for i := 1; i < len(argv); i++ {
		if argv[i] == "-c" && i+1 < len(argv) {
			script = strings.TrimPrefix(argv[i+1], "\x00")
			break
		}
	}
	if script == "" {
		return nil, false
	}
	if shellTruncatesArg(script) {
		return []string{"truncate", "-s", "0"}, true
	}
	fields := splitShellWords(script)
	var pre []string
	for _, f := range fields {
		if f == "$@" || f == "$*" || strings.Contains(f, "$@") {
			continue
		}
		pre = append(pre, f)
	}
	if len(pre) == 0 {
		return nil, false
	}
	switch base(pre[0]) {
	case "rm", "unlink", "shred", "rmdir", "chmod", "chown", "chgrp", "setfacl", "mv", "cp", "truncate":
		return pre, true
	default:
		return nil, false
	}
}

func splitShellWords(s string) []string {
	var out []string
	var b strings.Builder
	var q byte
	flush := func() {
		if b.Len() == 0 {
			return
		}
		out = append(out, b.String())
		b.Reset()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if q != 0 {
			if c == q {
				q = 0
				continue
			}
			b.WriteByte(c)
			continue
		}
		if c == '\'' || c == '"' {
			q = c
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' {
			flush()
			continue
		}
		b.WriteByte(c)
	}
	flush()
	return out
}

// shellTruncatesArg reports a redirect that replaces the find match.
// `cat /dev/null > "$1"` empties that file. A redirect to another path does not.
func shellTruncatesArg(script string) bool {
	inS, inD := false, false
	for i := 0; i < len(script); i++ {
		c := script[i]
		switch {
		case inS:
			if c == '\'' {
				inS = false
			}
		case inD:
			if c == '"' {
				inD = false
			}
		case c == '\'':
			inS = true
		case c == '"':
			inD = true
		case c == '>':
			if i > 0 && script[i-1] == '>' {
				continue
			}
			if i+1 < len(script) && script[i+1] == '>' {
				continue
			}
			j := i + 1
			if j < len(script) && script[j] == '|' {
				j++
			}
			for j < len(script) && (script[j] == ' ' || script[j] == '\t') {
				j++
			}
			var b strings.Builder
			if j < len(script) && (script[j] == '\'' || script[j] == '"') {
				q := script[j]
				j++
				for j < len(script) && script[j] != q {
					b.WriteByte(script[j])
					j++
				}
			} else {
				for j < len(script) && script[j] != ' ' && script[j] != '\t' && script[j] != ';' && script[j] != '&' && script[j] != '|' && script[j] != '\n' {
					b.WriteByte(script[j])
					j++
				}
			}
			switch b.String() {
			case "$1", "${1}", "$@", "${@}", "$*", "${*}", "{}":
				return true
			}
		}
	}
	return false
}

func execCommand(spec findSpec) string {
	if len(spec.execArgv) == 0 {
		return ""
	}
	return base(spec.execArgv[0])
}

// judgedSlowPer is a per-file exec that still rewrites or removes the match.
// rm \; stays one file at a time. cp, truncate, and sh -c rm do not.
func judgedSlowPer(spec findSpec) bool {
	if _, ok := rewriteShellExec(spec.execArgv); ok {
		return true
	}
	switch execCommand(spec) {
	case "cp", "truncate":
		return true
	default:
		return false
	}
}

func judgedPerFile(spec findSpec) bool {
	switch execCommand(spec) {
	case "mv", "chmod", "chown", "chgrp":
		return true
	default:
		return false
	}
}

func judgedExec(spec findSpec) bool {
	if _, ok := rewriteShellExec(spec.execArgv); ok {
		return true
	}
	switch execCommand(spec) {
	case "rm", "unlink", "shred", "rmdir", "chmod", "chown", "chgrp", "setfacl", "mv", "cp", "truncate":
		return true
	default:
		return false
	}
}

// judgeDelete applies rm's bulk and protected-file rules to the paths
// find -delete would remove. A directory is not a hit only because a
// marker sits deeper than -maxdepth.
func (in Input) judgeDelete(spec findSpec, roots []string) Outcome {
	limit := in.Config.Thresholds.BulkTargets
	if limit <= 0 {
		limit = 100
	}
	// An unfiltered -delete is the whole tree. The tree ceiling still applies,
	// and so does the bulk ceiling. A name filter counts only its matches.
	if !spec.nameGuarded {
		if tree := in.Config.Thresholds.TreeFiles; tree > 0 && tree < limit {
			limit = tree
		}
	}
	var matches []string
	for _, root := range roots {
		paths, timed, over := in.listFind(root, spec, limit+1)
		if timed && !(spec.nameGuarded && !over && len(paths) <= limit) {
			o := in.danger("C", "check timed out", "the check timed out", "a long scan likely means a very large target", "narrow the path", roots, "find-delete")
			o.Level = "bulk"
			o.Affected.TimedOut = true
			o.Affected.Partial = len(paths)
			o.Affected.Count = len(paths)
			return o
		}
		matches = append(matches, paths...)
		if over || len(matches) > limit {
			o := in.bulk("C", "find-delete", matches, "more than the bulk-delete threshold")
			o.Affected.Count = len(matches)
			return o
		}
	}
	if len(matches) == 0 {
		return allow()
	}
	if o, ok := in.brainDelete(matches); ok {
		return o
	}
	for _, p := range matches {
		st, err := os.Lstat(p)
		if err == nil && st.IsDir() {
			if hit, ok := in.protected(p); ok && !strings.Contains(hit.Reason, ".spotter-sh-protect") {
				return in.danger("E", "protected path", hit.Reason, "this path is protected", "leave it out", []string{p}, "find-delete")
			}
			continue
		}
		if hit, ok := in.protected(p); ok && !configLog(p) {
			return in.danger("E", "protected path", hit.Reason, "this path is protected", "leave it out", []string{p}, "find-delete")
		}
		if underSystemBin(p) {
			return in.danger("E", "protected path", "system directory "+filepath.Dir(p), "this path is protected", "leave it out", []string{p}, "find-delete")
		}
	}
	if len(matches) > limit {
		return in.bulk("C", "find-delete", matches, "more than the bulk-delete threshold")
	}
	return allow()
}

// execMatchLimit is the threshold the exec command itself would use.
// A plain rm catches at the bulk count. rm -r and chmod -R use the tree count.
func (in Input) execMatchLimit(name string, argv []string) int {
	if !execRecursive(argv) {
		n := in.Config.Thresholds.BulkTargets
		if n <= 0 {
			return 100
		}
		return n
	}
	n := in.Config.Thresholds.TreeFiles
	if name == "chmod" || name == "chown" || name == "chgrp" || name == "setfacl" {
		n = in.Config.Thresholds.RecursivePermFiles
	}
	if n <= 0 {
		return 2000
	}
	return n
}

func execRecursive(argv []string) bool {
	for _, w := range argv[1:] {
		if w == "--" {
			break
		}
		if w == "-r" || w == "-R" || w == "--recursive" {
			return true
		}
		if strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--") {
			for _, c := range w[1:] {
				if c == 'r' || c == 'R' {
					return true
				}
			}
		}
	}
	return false
}

func (in Input) findScoped(spec findSpec, targets []string) Outcome {
	limit := in.Config.Thresholds.TreeFiles
	if limit <= 0 {
		limit = 1
	}
	total := 0
	for _, t := range targets {
		paths, timed, over := in.listFind(t, spec, limit+1)
		if timed {
			o := in.danger("C", "check timed out", "the check timed out", "a long scan likely means a very large target", "narrow the path", targets, "find-delete")
			o.Level = "bulk"
			o.Affected.TimedOut = true
			o.Affected.Partial = len(paths)
			o.Affected.Count = len(paths)
			return o
		}
		// Name filters are the matches find will really delete. Other predicates
		// (-newer, -maxdepth alone) are not modeled file by file, so a .git
		// child must not turn the whole search into a catch.
		if len(spec.names) > 0 || len(spec.iname) > 0 {
			for _, p := range paths {
				st, err := os.Lstat(p)
				if err == nil && st.IsDir() {
					if hit, ok := in.protected(p); ok && !strings.Contains(hit.Reason, ".spotter-sh-protect") {
						return in.danger("E", "protected path", hit.Reason, "this path is protected", "leave it out", []string{p}, "find-delete")
					}
					continue
				}
				if hit, ok := in.protected(p); ok {
					return in.danger("E", "protected path", hit.Reason, "this path is protected", "leave it out", []string{p}, "find-delete")
				}
				if underSystemBin(p) {
					return in.danger("E", "protected path", "system directory "+filepath.Dir(p), "this path is protected", "leave it out", []string{p}, "find-delete")
				}
			}
		}
		total += len(paths)
		if over || total > limit {
			o := in.bulk("C", "find-delete", targets, "more matches than the tree threshold")
			o.Affected.Count = total
			return o
		}
	}
	return allow()
}

func (in Input) decideDiskTool(name string, argv []string) Outcome {
	for _, op := range operandsLoose(argv) {
		if isSystemDiskPath(op) {
			return hardDisk(name)
		}
		r := in.resolveOne(op)
		if isBlockDev(r) {
			return hardDisk(name)
		}
	}
	return allow()
}

func isBlockDev(path string) bool {
	st, err := os.Lstat(path)
	if err != nil {
		return false
	}
	mode := st.Mode()
	return mode&os.ModeDevice != 0 && mode&os.ModeCharDevice == 0
}

func (in Input) decideOverwriteTool(name string, argv []string) Outcome {
	switch name {
	case "tar":
		if !hasSub(argv, "--overwrite") && !hasSub(argv, "--recursive-unlink") {
			return allow()
		}
	case "unzip":
		if !hasShort(argv, 'o') {
			return allow()
		}
	case "sed":
		if !hasSub(argv, "-i") && !hasShort(argv, 'i') {
			return allow()
		}
	case "perl":
		hit := false
		for _, w := range argv[1:] {
			if strings.HasPrefix(w, "-") && strings.Contains(w, "p") && strings.Contains(w, "i") {
				hit = true
			}
		}
		if !hit {
			return allow()
		}
	case "truncate":
		zero := false
		for _, w := range argv[1:] {
			if w == "-s0" || w == "-s" || strings.HasPrefix(w, "--size=0") || w == "--size=0" {
				zero = true
			}
		}
		if !zero {
			return allow()
		}
	}
	ops := operandsLoose(argv)
	targets := in.resolveAll(ops)
	if o, ok := in.forceTargets(targets, "E", name+"-overwrite"); ok {
		return o
	}
	n := 0
	for _, t := range targets {
		if _, err := os.Lstat(t); err == nil {
			n++
		}
	}
	if n > in.Config.Thresholds.OverwriteFiles {
		return in.bulk("C", name+"-overwrite", targets, "many existing files")
	}
	return allow()
}

func (in Input) forceTargets(targets []string, caseID, op string) (Outcome, bool) {
	if why, ok := in.sweepNode(targets); ok {
		return in.danger(caseID, "protected sweep", why, "this deletes or rewrites a protected directory", "name a narrower path", targets, op), true
	}
	for _, t := range targets {
		if isAncestor(t, in.Cwd) {
			return in.danger("A", "parent of cwd", t+" is a parent of the working directory", "'.*' or an empty variable walked upward", "use .[!.]* or set the variable", targets, op), true
		}
		if hit, ok := in.protected(t); ok {
			return in.danger("E", "protected path", hit.Reason, "this path is protected", "leave it out", targets, op), true
		}
		if underSystemBin(t) {
			return in.danger("E", "protected path", "system directory "+filepath.Dir(t), "this path is protected", "leave it out", targets, op), true
		}
		if isMountRoot(t) && t != in.Cwd {
			return in.danger("A", "mount root", t+" is a mount root", "the path is a filesystem root", "stay inside one filesystem", targets, op), true
		}
	}
	return Outcome{}, false
}

func (in Input) treeOrAllow(targets []string, op string, maxFiles int, maxBytes int64) Outcome {
	totalN := 0
	var totalB int64
	for _, t := range targets {
		if in.buildExempt(t) {
			continue
		}
		st, err := os.Lstat(t)
		if err != nil || !st.IsDir() {
			// find -exec rm -r {} + hands over the files themselves.
			// Those count toward the tree threshold without a directory walk.
			totalN++
			if err == nil {
				totalB += st.Size()
			}
		} else {
			deadline := in.walkDeadline()
			w := walkTree(t, maxFiles, maxBytes, deadline)
			if w.Cross {
				return in.danger("A", "mount cross", "walk crossed a mount at "+w.CrossAt, "a recursive op followed into another filesystem", "pass --one-file-system", targets, op)
			}
			if w.Timeout {
				o := in.danger("C", "check timed out", "the check timed out", "a long scan likely means a very large target", "narrow the path", targets, op)
				o.Level = "bulk"
				if o.Affected.Protected {
					o.Level = "danger"
				}
				o.Affected.TimedOut = true
				o.Affected.Partial = w.Partial
				if w.Partial == 0 {
					o.Affected.Partial = w.Files + w.Dirs
				}
				o.Affected.Count = o.Affected.Partial
				return o
			}
			// Count directories as well as files. A tree of empty directories
			// that finishes under the deadline is still a large delete.
			// A timeout above is always a catch, including a dir-only tree.
			totalN += w.Files + w.Dirs
			totalB += w.Bytes
		}
		if (maxFiles > 0 && totalN > maxFiles) || (maxBytes > 0 && totalB > maxBytes) {
			o := in.bulk("C", op, targets, "tree is over the file or size threshold")
			o.Affected.Count = totalN
			o.Affected.Bytes = totalB
			o.Affected.HaveBytes = maxBytes > 0
			return o
		}
	}
	if maxFiles > 0 && near(totalN, maxFiles) {
		o := allow()
		o.Near = true
		o.Affected.Count = totalN
		return o
	}
	return allow()
}

func (in Input) walkDeadline() time.Time {
	d := in.Config.WalkTimeout
	if d <= 0 {
		d = 1500 * time.Millisecond
	}
	dl := time.Now().Add(d)
	if !in.Deadline.IsZero() && in.Deadline.Before(dl) {
		return in.Deadline
	}
	return dl
}

func (in Input) buildExempt(path string) bool {
	base := filepath.Base(filepath.Clean(path))
	ok := false
	for _, n := range in.Config.Commands.BuildOutput {
		if n == base {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	parent := filepath.Dir(filepath.Clean(path))
	root, yes := projectRoot(parent, in.Home)
	if !yes {
		return false
	}
	if filepath.Clean(path) == root {
		return false
	}
	return true
}

func projectRoot(dir, home string) (string, bool) {
	dir = filepath.Clean(dir)
	for {
		if refusedProject(dir, home) {
			return "", false
		}
		if exists(filepath.Join(dir, ".git")) || exists(filepath.Join(dir, ".spotter-sh-root")) {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

func refusedProject(dir, home string) bool {
	dir = filepath.Clean(dir)
	if dir == "/" || dir == "/etc" || dir == "/root" {
		return true
	}
	if home != "" && dir == filepath.Clean(home) {
		return true
	}
	if isMountRoot(dir) && dir != "/" {
		// mount roots are never project roots; "/" already handled
		return true
	}
	if dir == "/" {
		return true
	}
	return false
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func (in Input) danger(caseID, op, consequence, mistake, safer string, targets []string, effect string) Outcome {
	top := targets
	if len(top) > 20 {
		top = top[:20]
	}
	return Outcome{
		Action:      "catch",
		Level:       "danger",
		Case:        caseID,
		Exit:        120,
		Consequence: consequence,
		Mistake:     mistake,
		Safer:       safer,
		Affected: Affected{
			Op:        effect,
			Count:     len(targets),
			Top:       append([]string{}, top...),
			Protected: true,
		},
	}
}

func (in Input) bulk(caseID, op string, targets []string, why string) Outcome {
	top := targets
	if len(top) > 20 {
		top = append([]string{}, top[:20]...)
	} else {
		top = append([]string{}, top...)
	}
	return Outcome{
		Action:      "catch",
		Level:       "bulk",
		Case:        caseID,
		Exit:        120,
		Consequence: why,
		Mistake:     "the expanded target set is larger than usual",
		Safer:       "narrow the glob or the directory",
		Affected:    Affected{Op: op, Count: len(targets), Top: top},
	}
}

func near(n, limit int) bool {
	if limit <= 0 || n <= 0 {
		return false
	}
	return n >= limit*8/10 && n <= limit
}

func isAncestorAny(targets []string, cwd string) bool {
	for _, t := range targets {
		if isAncestor(t, cwd) {
			return true
		}
	}
	return false
}

func (in Input) resolveAll(ops []string) []string {
	return in.resolveFollow(ops, true)
}

// resolveDeletes keeps a symlink as itself. rm and unlink remove the link.
func (in Input) resolveDeletes(ops []string) []string {
	return in.resolveFollow(ops, false)
}

func (in Input) resolveFollow(ops []string, follow bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, op := range ops {
		r := in.resolveOneFollow(op, follow)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

func (in Input) resolveOne(op string) string {
	return in.resolveOneFollow(op, true)
}

// resolveFindRoots keeps a symlink root unless find was asked to follow it
// or the operand has a trailing slash. find homelink -maxdepth 0 -delete
// removes the link, not the directory it names.
func (in Input) resolveFindRoots(roots []string, spec findSpec) []string {
	var out []string
	seen := map[string]bool{}
	for _, op := range roots {
		follow := spec.follow || spec.followArg || operandFollows(op)
		r := in.resolveOneFollow(op, follow)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

func optVal(argv []string, short, long string) string {
	args := []string{}
	if len(argv) > 1 {
		args = argv[1:]
	}
	for i := 0; i < len(args); i++ {
		w := args[i]
		if w == "--" {
			break
		}
		if w == "--"+long {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(w, "--"+long+"=") {
			return strings.TrimPrefix(w, "--"+long+"=")
		}
		if strings.HasPrefix(w, "--") || !strings.HasPrefix(w, "-") || w == "-" {
			continue
		}
		cluster := w[1:]
		for j := 0; j < len(cluster); j++ {
			if string(cluster[j]) != short {
				continue
			}
			rest := cluster[j+1:]
			if rest != "" {
				return rest
			}
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
	}
	return ""
}

// operandFollows reports a trailing slash or a final . or .. .
// rm and mv follow the symlink in that case; a bare link removes only the link.
func operandFollows(op string) bool {
	if op == "" {
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

func (in Input) resolveOneFollow(op string, follow bool) string {
	if op == "" {
		return ""
	}
	// A trailing slash or /. is a directory operand. Bash and rm follow
	// the symlink. filepath.Clean would erase that marker.
	follow = follow || operandFollows(op)
	// A leading ~ that survived bash is a literal relative path. Quoted
	// "~/..." and $'\x7e' are not the home directory.
	p := op
	if !filepath.IsAbs(p) {
		p = filepath.Join(in.Cwd, p)
	}
	p = filepath.Clean(p)
	// A protected directory node that is itself a symlink (/bin -> /usr/bin)
	// stays the node. Following it would judge the target instead.
	if in.keepsLiteral(p) {
		return p
	}
	parent := filepath.Dir(p)
	baseName := filepath.Base(p)
	if real, err := filepath.EvalSymlinks(parent); err == nil {
		p = filepath.Join(real, baseName)
	}
	if in.keepsLiteral(p) {
		return p
	}
	if !follow {
		return filepath.Clean(p)
	}
	if st, err := os.Lstat(p); err == nil && st.Mode()&os.ModeSymlink != 0 {
		if real, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Clean(real)
		}
	}
	return filepath.Clean(p)
}

func (in Input) keepsLiteral(path string) bool {
	path = filepath.Clean(path)
	for _, r := range in.rules() {
		if r.node && path == r.prefix {
			return true
		}
	}
	return false
}

func isDir(path string) bool {
	st, err := os.Lstat(path)
	return err == nil && st.IsDir()
}

func looksMode(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '7') && !strings.ContainsRune("ugoa+-=rwxXst", c) {
			return false
		}
	}
	return true
}

// precheck of a string, used by the sudo -c limit.
func outcomeFromPrecheck(r precheck.Result) Outcome {
	o := Outcome{
		Action:      r.Action,
		Exit:        r.Exit,
		Case:        r.Case,
		Message:     r.Message,
		Consequence: r.Message,
		Approve:     r.Approve,
	}
	if r.Action == "hardblock" {
		o.Level = "hardblock"
		if o.Exit == 0 {
			o.Exit = 121
		}
	} else if r.Action == "catch" {
		o.Level = "danger"
		if o.Exit == 0 {
			o.Exit = 120
		}
	}
	return o
}

func hardBlockText(s string) (Outcome, bool) {
	r := precheck.Scan(s)
	if r.Action != "hardblock" {
		return Outcome{}, false
	}
	return Outcome{Action: "hardblock", Level: "hardblock", Exit: 121, Case: r.Case, Message: r.Message, Consequence: r.Message, Approve: r.Approve}, true
}

func (in Input) brainRoots() []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		p = filepath.Clean(strings.TrimSpace(p))
		if p == "" || p == "." || p == "/" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range strings.Split(envx.Get("BRAIN"), string(os.PathListSeparator)) {
		add(p)
	}
	return out
}

func underBrain(path string, roots []string) (rel string, ok bool) {
	path = filepath.Clean(path)
	for _, r := range roots {
		r = filepath.Clean(r)
		if path == r {
			return "", true
		}
		sep := string(os.PathSeparator)
		if strings.HasPrefix(path, r+sep) {
			return path[len(r)+1:], true
		}
	}
	return "", false
}

// configLog is a log file inside ~/.config. A name filter that selects
// those files is cleanup, not a wipe of the config tree.
func configLog(path string) bool {
	if !strings.HasSuffix(path, ".log") {
		return false
	}
	return strings.Contains(filepath.Clean(path), string(filepath.Separator)+".config"+string(filepath.Separator))
}

// brainDelete allows one note file. A directory, a recursive delete, or more
// than one note (a shell wildcard) is a catch.
func (in Input) brainDelete(targets []string) (Outcome, bool) {
	roots := in.brainRoots()
	if len(roots) == 0 {
		return Outcome{}, false
	}
	var files []string
	for _, t := range targets {
		rel, ok := underBrain(t, roots)
		if !ok {
			continue
		}
		st, err := os.Lstat(t)
		isDir := err == nil && st.IsDir()
		if rel == "" || isDir {
			o := in.danger("E", "brain folder", "this deletes a brain folder, not one note", "brain folders hold many notes", "delete the single note file", targets, "brain")
			return o, true
		}
		files = append(files, t)
	}
	// One note file is a normal delete. Returning unset would fall through
	// into a recursive protected-path rule and catch the note.
	if len(files) == 1 && len(targets) == len(files) {
		return allow(), true
	}
	if len(files) <= 1 {
		return Outcome{}, false
	}
	o := in.danger("E", "brain notes", "this deletes more than one brain note", "a wildcard across brain folders is not one note", "name the single note", files, "brain")
	return o, true
}

// logWipe catches a recursive delete or a wipe of /var/log.
// One log file, including rotation of a single file, passes.
func (in Input) logWipe(targets []string, rec bool) (Outcome, bool) {
	const root = "/var/log"
	var dirs int
	whole := false
	var hit []string
	for _, t := range targets {
		t = filepath.Clean(t)
		if t != root && !strings.HasPrefix(t, root+string(os.PathSeparator)) {
			continue
		}
		hit = append(hit, t)
		if t == root {
			whole = true
		}
		st, err := os.Lstat(t)
		// A missing path with -r is still a recursive delete of that log path.
		if err != nil || st.IsDir() {
			if rec || t == root {
				dirs++
			}
			continue
		}
	}
	if len(hit) == 0 {
		return Outcome{}, false
	}
	if whole || (rec && dirs > 0) || in.coversDir(root, targets) {
		o := in.danger("E", "log directory", "this wipes /var/log or a log directory", "recursive log cleanup removes more than one file", "delete or rotate the single log file", hit, "log")
		return o, true
	}
	return Outcome{}, false
}

func (in Input) coversDir(dir string, targets []string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return false
	}
	set := map[string]struct{}{}
	for _, t := range targets {
		set[filepath.Clean(t)] = struct{}{}
	}
	n := 0
	for _, e := range entries {
		if _, ok := set[filepath.Join(dir, e.Name())]; ok {
			n++
		}
	}
	return n == len(entries) && n > 1
}

func probeTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return 1500 * time.Millisecond
	}
	return d
}

func runProbe(ctx context.Context, cwd string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = cwd
	var out []byte
	var cmdErr error
	if err := PrepareChild(cmd); err != nil {
		return "", err
	}
	out, cmdErr = cmd.Output()
	return string(out), cmdErr
}
