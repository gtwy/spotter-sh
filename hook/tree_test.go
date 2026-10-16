// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package hook

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestCoverFollowsLiveTreeOnly(t *testing.T) {
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill() }()
	_, start, ok := ProcStat(os.Getpid())
	if !ok || start == "" {
		t.Fatal("own start time")
	}
	if !InTree(child.Process.Pid, os.Getpid(), start) {
		t.Fatal("live child was outside the tree")
	}
	_, childStart, ok := ProcStat(child.Process.Pid)
	if !ok {
		t.Fatal("child stat")
	}
	if InTree(os.Getpid(), child.Process.Pid, childStart) {
		t.Fatal("parent counted as a descendant")
	}
	if InTree(child.Process.Pid, os.Getpid(), start+"1") {
		t.Fatal("wrong start time still covered")
	}

	// The subshell exits. sleep is reparented and must not stay covered.
	cmd := exec.Command("bash", "-c", "( sleep 30 >/dev/null 2>&1 & echo $!; echo $$ )")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(out))
	if len(lines) != 2 {
		t.Fatalf("pids %q", out)
	}
	grand, err := strconv.Atoi(lines[0])
	if err != nil {
		t.Fatal(err)
	}
	leader, err := strconv.Atoi(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exec.Command("kill", strconv.Itoa(grand)).Run() }()
	if _, _, ok := ProcStat(leader); ok {
		t.Fatal("leader still alive")
	}
	if InTree(grand, leader, "1") {
		t.Fatal("background child stayed covered after the leader exited")
	}
}
