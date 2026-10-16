// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// HomeDir is the login directory. $HOME wins. When it is unset, as with
// env -i, the passwd entry is the directory bash uses for ~.
func HomeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		return ""
	}
	return u.HomeDir
}

type protHit struct {
	Path   string
	Reason string
	Force  bool
}

// protected reports whether one resolved path is force-protected on its own
// (recursive rules and exact nodes). Sweeps are decided on the whole set.
func (in Input) protected(path string) (protHit, bool) {
	path = filepath.Clean(path)
	if in.allowed(path) {
		return protHit{}, false
	}
	for _, rule := range in.rules() {
		if rule.match(path) {
			return protHit{Path: path, Reason: rule.why, Force: true}, true
		}
	}
	if in.markerHit(path) {
		return protHit{Path: path, Reason: "directory marked .spotter-sh-protect", Force: true}, true
	}
	base := filepath.Base(path)
	if base == ".git" || strings.HasSuffix(path, string(filepath.Separator)+".git") {
		return protHit{Path: path, Reason: ".git directory", Force: true}, true
	}
	return protHit{}, false
}

type rule struct {
	prefix string
	recur  bool
	node   bool
	why    string
	glob   bool
}

func (r rule) match(path string) bool {
	path = filepath.Clean(path)
	if r.glob {
		ok, _ := filepath.Match(r.prefix, filepath.Base(path))
		if ok && filepath.Dir(path) == filepath.Dir(r.prefix) || ok && strings.HasPrefix(path, filepath.Dir(r.prefix)+string(filepath.Separator)) {
			return true
		}
		return strings.HasPrefix(path, strings.TrimSuffix(r.prefix, "*")) || path == strings.TrimSuffix(r.prefix, "*")
	}
	if r.recur {
		return path == r.prefix || strings.HasPrefix(path, r.prefix+string(filepath.Separator))
	}
	if r.node {
		return path == r.prefix
	}
	return path == r.prefix
}

func (in Input) rules() []rule {
	home := in.Home
	if home == "" {
		home = HomeDir()
	}
	var out []rule
	fhs := []string{"/", "/bin", "/sbin", "/lib", "/lib64", "/usr", "/usr/bin", "/etc", "/var", "/opt", "/srv", "/boot", "/root", "/home", "/dev", "/proc", "/sys", "/run"}
	for _, p := range fhs {
		out = append(out, rule{prefix: p, node: true, why: "filesystem directory " + p})
	}
	if home != "" {
		out = append(out, rule{prefix: filepath.Clean(home), node: true, why: "home directory"})
	}
	out = append(out, rule{prefix: "/root", node: true, why: "home directory"})
	// homes we can see
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				out = append(out, rule{prefix: filepath.Join("/home", e.Name()), node: true, why: "home directory"})
			}
		}
	}
	recur := []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".config"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".kube"),
		"/etc/sudoers.d",
		"/etc/ssh",
		"/etc/pam.d",
		"/etc/systemd",
		"/lib/systemd",
		"/boot",
	}
	for _, p := range recur {
		if p == "" || strings.HasPrefix(p, "/") && home == "" && strings.Contains(p, "home") {
			continue
		}
		out = append(out, rule{prefix: filepath.Clean(p), recur: true, why: p})
	}
	files := []string{
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".profile"),
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".ssh", "authorized_keys"),
		"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers",
		"/etc/fstab", "/etc/hosts", "/etc/resolv.conf", "/etc/crontab",
	}
	for _, p := range files {
		if p == "" {
			continue
		}
		out = append(out, rule{prefix: filepath.Clean(p), why: p})
	}
	// /etc/cron.*
	if entries, err := os.ReadDir("/etc"); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "cron.") {
				out = append(out, rule{prefix: filepath.Join("/etc", e.Name()), recur: true, why: "/etc/" + e.Name()})
			}
		}
	}
	for _, extra := range in.Config.Paths.ProtectExtra {
		out = append(out, extraRule(extra, home))
	}
	for _, extra := range extraProtect() {
		out = append(out, extraRule(extra, home))
	}
	return out
}

func extraRule(pat, home string) rule {
	pat = expandUser(pat, home)
	recur := strings.HasSuffix(pat, "/**")
	pat = strings.TrimSuffix(pat, "/**")
	pat = strings.TrimSuffix(pat, "/**")
	if strings.HasSuffix(pat, "/") && pat != "/" {
		pat = strings.TrimSuffix(pat, "/")
	}
	return rule{prefix: filepath.Clean(pat), recur: recur || strings.Contains(pat, "**"), why: "protect_extra " + pat}
}

func (in Input) allowed(path string) bool {
	home := in.Home
	for _, a := range in.Config.Paths.AllowExtra {
		a = expandUser(a, home)
		recur := strings.HasSuffix(a, "/**")
		a = strings.TrimSuffix(a, "/**")
		a = filepath.Clean(a)
		if path == a || (recur && strings.HasPrefix(path, a+string(filepath.Separator))) {
			return true
		}
	}
	return false
}

func expandUser(p, home string) string {
	if home != "" && (strings.HasPrefix(p, "~/") || p == "~") {
		return filepath.Join(home, strings.TrimPrefix(p, "~/"))
	}
	return p
}

func (in Input) markerHit(path string) bool {
	name := in.Config.Paths.MarkerFile
	if name == "" {
		name = ".spotter-sh-protect"
	}
	dir := path
	if st, err := os.Lstat(path); err != nil || !st.IsDir() {
		dir = filepath.Dir(path)
	}
	for {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return true
		}
		// a marked child makes a recursive delete of this directory a hit
		if st, err := os.Lstat(path); err == nil && st.IsDir() && dir == path {
			if entries, err := os.ReadDir(dir); err == nil {
				for _, e := range entries {
					if e.IsDir() {
						if _, err := os.Lstat(filepath.Join(dir, e.Name(), name)); err == nil {
							return true
						}
					}
				}
			}
		}
		if dir == "/" || dir == "" {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return false
}

// sweepNode reports a protected bare node whose direct children are all targeted,
// or whose node itself is a target.
func (in Input) sweepNode(targets []string) (string, bool) {
	nodes := map[string]string{}
	for _, r := range in.rules() {
		if r.node {
			nodes[r.prefix] = r.why
		}
	}
	set := map[string]struct{}{}
	for _, t := range targets {
		set[filepath.Clean(t)] = struct{}{}
	}
	for node, why := range nodes {
		if _, ok := set[node]; ok {
			return why + " (" + node + ")", true
		}
		entries, err := os.ReadDir(node)
		if err != nil || len(entries) == 0 {
			continue
		}
		cover := 0
		child := 0
		visible := 0
		visibleCover := 0
		for _, e := range entries {
			child++
			p := filepath.Join(node, e.Name())
			_, hit := set[p]
			if hit {
				cover++
			}
			if !strings.HasPrefix(e.Name(), ".") {
				visible++
				if hit {
					visibleCover++
				}
			}
		}
		if child > 0 && cover == child {
			return "sweep of " + node, true
		}
		// A shell glob omits dotfiles. Every visible child of a protected
		// node is still a sweep when more than one of them is named.
		// One visible file stays a normal delete (rm ~/notes.txt).
		if visible >= 2 && visibleCover == visible {
			return "sweep of " + node, true
		}
	}
	return "", false
}

// underSystemBin reports a file inside a system binary directory.
// /bin is often a symlink to /usr/bin, so the resolved path is what counts.
func underSystemBin(path string) bool {
	roots := []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/lib64", "/usr/lib", "/usr/lib64"}
	if underRoot(path, roots) {
		return true
	}
	// /lib and /bin are often symlinks. The resolved file is the same object.
	if real, err := filepath.EvalSymlinks(path); err == nil && underRoot(real, roots) {
		return true
	}
	return false
}

func underRoot(path string, roots []string) bool {
	path = filepath.Clean(path)
	for _, root := range roots {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func isAncestor(target, cwd string) bool {
	target = filepath.Clean(target)
	cwd = filepath.Clean(cwd)
	if target == cwd {
		return false
	}
	return cwd == target || strings.HasPrefix(cwd, target+string(filepath.Separator))
}
