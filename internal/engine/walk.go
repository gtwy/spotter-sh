// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type walkStat struct {
	Files   int
	Dirs    int
	Bytes   int64
	Partial int
	Timeout bool
	Cross   bool
	CrossAt string
}

// walkTree counts a directory without following symlinks.
// It stops once either ceiling is passed or the deadline hits.
func walkTree(root string, maxFiles int, maxBytes int64, deadline time.Time) walkStat {
	var st walkStat
	dev := deviceOf(root)
	var walk func(string)
	walk = func(dir string) {
		if st.Timeout || st.Files > maxFiles || (maxBytes > 0 && st.Bytes > maxBytes) {
			return
		}
		// Count the directory before the deadline check so a dir-only tree
		// that times out still reports how far the scan got.
		st.Dirs++
		if !deadline.IsZero() && time.Now().After(deadline) {
			st.Timeout = true
			st.Partial = st.Files + st.Dirs
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for i, e := range entries {
			if st.Timeout || st.Files > maxFiles || (maxBytes > 0 && st.Bytes > maxBytes) {
				return
			}
			if i&31 == 0 && !deadline.IsZero() && time.Now().After(deadline) {
				st.Timeout = true
				st.Partial = st.Files + st.Dirs
				return
			}
			p := filepath.Join(dir, e.Name())
			info, err := e.Info()
			if err != nil {
				continue
			}
			if info.Mode()&os.ModeSymlink != 0 {
				st.Files++
				continue
			}
			if info.IsDir() {
				if d := devOfInfo(info); dev != 0 && d != 0 && d != dev {
					st.Cross = true
					st.CrossAt = p
					continue
				}
				walk(p)
				continue
			}
			st.Files++
			st.Bytes += diskBytes(info)
		}
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		if err == nil && !info.IsDir() {
			st.Files = 1
			st.Bytes = diskBytes(info)
		}
		return st
	}
	walk(root)
	if st.Files > maxFiles || (maxBytes > 0 && st.Bytes > maxBytes) {
		st.Partial = st.Files
	}
	return st
}

func diskBytes(info os.FileInfo) int64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int64(st.Blocks) * 512
	}
	return info.Size()
}

func deviceOf(path string) uint64 {
	info, err := os.Lstat(path)
	if err != nil {
		return 0
	}
	return devOfInfo(info)
}

func devOfInfo(info os.FileInfo) uint64 {
	if info == nil {
		return 0
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(st.Dev)
}

func isMountRoot(path string) bool {
	path = filepath.Clean(path)
	if path == "/" {
		return true
	}
	d := deviceOf(path)
	p := deviceOf(filepath.Dir(path))
	return d != 0 && p != 0 && d != p
}
