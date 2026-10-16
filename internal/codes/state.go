// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package codes

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const systemStateDir = "/var/lib/spotter-sh"

// FixedDir is the install state directory for this binary.
// It never reads the environment, the working directory, or argv.
// Install writes one absolute path beside the real executable.
// A missing stamp falls back to the system directory for a root-owned
// binary, otherwise the passwd home, which is not $HOME.
func FixedDir() string {
	exe, err := os.Executable()
	if err != nil {
		return fallbackDir("", 1, passwdHome(os.Getuid()))
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil && resolved != "" {
		exe = resolved
	}
	var uid uint32 = 1
	if st, err := os.Stat(exe); err == nil {
		if s, ok := st.Sys().(*syscall.Stat_t); ok {
			uid = s.Uid
		}
	}
	return DirFrom(exe, uid, passwdHome(os.Getuid()))
}

// DirFrom applies the stamp and fallback rules to an executable path.
// exeUID is the owner of that executable. passwdHome is the passwd entry,
// never a value taken from the environment.
func DirFrom(exe string, exeUID uint32, passwdHome string) string {
	if d, ok := readStamp(exe, exeUID); ok {
		return d
	}
	return fallbackDir(exe, exeUID, passwdHome)
}

// WriteStamp records the state directory beside the real executable.
// The shim trusts the stamp only when its owner matches the executable
// and it is not group or world writable.
func WriteStamp(exe, dir string) error {
	dir, ok := safeStatePath(dir)
	if !ok {
		return errors.New("state directory")
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil && resolved != "" {
		exe = resolved
	}
	return os.WriteFile(stampPath(exe), []byte(dir+"\n"), 0o644)
}

func stampPath(exe string) string { return exe + ".state" }

func readStamp(exe string, exeUID uint32) (string, bool) {
	if exe == "" {
		return "", false
	}
	info, err := os.Lstat(stampPath(exe))
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return "", false
	}
	if info.Mode().Perm()&0o022 != 0 {
		return "", false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != exeUID {
		return "", false
	}
	buf, err := os.ReadFile(stampPath(exe))
	if err != nil {
		return "", false
	}
	return safeStatePath(string(buf))
}

func safeStatePath(p string) (string, bool) {
	p = strings.TrimSpace(p)
	if p == "" || !filepath.IsAbs(p) || strings.Contains(p, "\x00") {
		return "", false
	}
	c := filepath.Clean(p)
	for _, part := range strings.Split(c, string(os.PathSeparator)) {
		if part == ".." {
			return "", false
		}
	}
	return c, true
}

func fallbackDir(exe string, exeUID uint32, home string) string {
	if exeUID == 0 || strings.Contains(exe, "/usr/local/lib/spotter-sh/") {
		return systemStateDir
	}
	if home == "" {
		return systemStateDir
	}
	return filepath.Join(home, ".local", "state", "spotter-sh")
}

func passwdHome(uid int) string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		parts := strings.Split(s.Text(), ":")
		if len(parts) < 6 {
			continue
		}
		id, err := strconv.Atoi(parts[2])
		if err != nil || id != uid {
			continue
		}
		if parts[5] == "" || !filepath.IsAbs(parts[5]) {
			return ""
		}
		return parts[5]
	}
	return ""
}

// CallerControlsKey reports whether this process's real uid can read or
// replace the install key. An owner can chmod a mode-0000 file, so ownership
// is enough. Group access counts only for the real gid and supplementary
// groups. The setgid egid is not the caller: a system install is mode 0640
// root:spotter-sh and the agent is not in that group.
// A missing key fails closed.
func (s Store) CallerControlsKey() bool {
	info, err := os.Stat(s.keyPath())
	if err != nil {
		return true
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	groups, err := os.Getgroups()
	return controlsKey(int(st.Uid), int(st.Gid), info.Mode(), os.Getuid(), os.Getgid(), groups, err == nil)
}

// controlsKey is the permission rule without reading the filesystem.
// groupsOK is false when the group list could not be read.
func controlsKey(uid, gid int, mode os.FileMode, ruid, rgid int, groups []int, groupsOK bool) bool {
	if uid == ruid {
		return true
	}
	perm := mode.Perm()
	if perm&0o004 != 0 {
		return true
	}
	if perm&0o040 != 0 {
		if !groupsOK || gid == rgid {
			return true
		}
		for _, g := range groups {
			if g == gid {
				return true
			}
		}
	}
	return false
}
