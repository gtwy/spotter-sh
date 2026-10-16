// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package hook

import (
	"os"
	"strconv"
	"strings"
)

// ProcStat reads a process's parent pid and start time from /proc.
// start time distinguishes a pid that was reused after exit.
func ProcStat(pid int) (ppid int, start string, ok bool) {
	if pid <= 0 {
		return 0, "", false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, "", false
	}
	s := string(b)
	i := strings.LastIndex(s, ")")
	if i < 0 || i+2 >= len(s) {
		return 0, "", false
	}
	fields := strings.Fields(s[i+2:])
	// After comm: state, ppid, ..., starttime is field 20 (index 19).
	if len(fields) < 20 {
		return 0, "", false
	}
	ppid, err = strconv.Atoi(fields[1])
	if err != nil || ppid <= 0 {
		return 0, "", false
	}
	return ppid, fields[19], true
}

// InTree reports whether peer is leader or a descendant of leader, and
// leader is still the same process. A background child reparented after
// the leader exits is not in the tree. The walk is capped.
func InTree(peer, leader int, start string) bool {
	if peer <= 1 || leader <= 1 || start == "" {
		return false
	}
	if !sameProc(leader, start) {
		return false
	}
	pid := peer
	for n := 0; n < 64 && pid > 1; n++ {
		if pid == leader {
			return true
		}
		ppid, _, ok := ProcStat(pid)
		if !ok || ppid == pid {
			return false
		}
		pid = ppid
	}
	return false
}

func sameProc(pid int, start string) bool {
	_, got, ok := ProcStat(pid)
	return ok && got == start
}
