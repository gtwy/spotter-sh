// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"os"
	"path/filepath"
	"strings"
)

// systemDirNode is a directory whose recursive removal is the directory
// itself, not a file count inside a sparse tree.
func systemDirNode(p string) bool {
	switch filepath.Clean(p) {
	case "/bin", "/sbin", "/usr", "/usr/bin", "/usr/sbin", "/usr/local", "/usr/local/bin",
		"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/etc", "/boot", "/opt", "/var":
		return true
	default:
		return false
	}
}

// treeOperands counts recursive directory operands in the home directory or
// another sensitive tree. An existing file counts as one path, not a tree.
// A missing path is a tree: rm -rf creates nothing, it removes a directory name.
func (in Input) treeOperands(targets []string) int {
	home := filepath.Clean(in.Home)
	n := 0
	for _, t := range targets {
		t = filepath.Clean(t)
		if t == "" || t == "/" || (home != "" && t == home) {
			continue
		}
		if !sensitiveTree(t, home) {
			continue
		}
		st, err := os.Lstat(t)
		if err == nil && !st.IsDir() {
			continue
		}
		n++
	}
	return n
}

// approvableGlob is a recursive-delete glob that must not hard-block.
// A trailing-slash star under a project directory, a data directory, and
// a dot directory are catches. /* and the home node stay on the hard-block path.
func approvableGlob(ops []string, home string) (string, bool) {
	for _, op := range ops {
		op = strings.TrimSpace(op)
		if op == "" || !strings.ContainsAny(op, "*?[") {
			continue
		}
		trimmed := strings.TrimRight(op, "/")
		switch trimmed {
		case "", "/", "*", "/*":
			continue
		}
		dir := trimmed
		if i := strings.LastIndex(trimmed, "/"); i >= 0 {
			dir = trimmed[:i]
		}
		if strings.HasSuffix(op, "/") && (homeProjectGlob(dir) || underThisHome(dir, home)) {
			return "would recursively delete a directory glob", true
		}
		if globDataOrDot(dir) {
			return "would recursively delete a data or dot directory glob", true
		}
	}
	return "", false
}

func dropGlobOperands(ops []string) []string {
	var out []string
	for _, op := range ops {
		if strings.ContainsAny(op, "*?[") && strings.TrimRight(op, "/") != "/*" && op != "/*" {
			continue
		}
		out = append(out, op)
	}
	return out
}

func underThisHome(dir, home string) bool {
	home = filepath.Clean(home)
	dir = filepath.Clean(dir)
	if home == "" || home == "/" || dir == "" || dir == home {
		return false
	}
	return strings.HasPrefix(dir, home+string(os.PathSeparator))
}

func homeProjectGlob(dir string) bool {
	if dir == "" || dir == "~" || dir == "$HOME" || dir == "${HOME}" || dir == "/root" {
		return false
	}
	if strings.HasPrefix(dir, "~/") || strings.HasPrefix(dir, "$HOME/") || strings.HasPrefix(dir, "${HOME}/") {
		return true
	}
	if strings.HasPrefix(dir, "/root/") {
		return true
	}
	if strings.HasPrefix(dir, "/home/") {
		rest := strings.TrimPrefix(dir, "/home/")
		return strings.Contains(rest, "/")
	}
	return false
}

func globDataOrDot(dir string) bool {
	for _, part := range strings.Split(dir, "/") {
		if part == "data" {
			return true
		}
		if len(part) > 1 && part[0] == '.' && part != ".." {
			return true
		}
	}
	return false
}

func sensitiveTree(path, home string) bool {
	if home != "" && home != "/" && strings.HasPrefix(path, home+string(os.PathSeparator)) {
		return true
	}
	for _, root := range []string{"/etc", "/usr", "/var", "/opt", "/boot", "/home", "/root"} {
		if path == root || strings.HasPrefix(path, root+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}
