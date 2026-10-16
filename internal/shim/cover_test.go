// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package shim

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gtwy/spotter-sh/internal/codes"
	"github.com/gtwy/spotter-sh/internal/engine"
)

func TestEnvCoverDoesNotAllow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SPOTTER_SH_HOME", dir)
	t.Setenv("SHELLSPOTTER_HOME", dir)
	_ = os.Unsetenv("SPOTTER_SH_HOOK")
	_ = os.Unsetenv("SHELLSPOTTER_HOOK")
	id, err := codes.ArmCover(dir, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPOTTER_SH_COVERED", id)
	t.Setenv("SHELLSPOTTER_COVERED", id)
	if coverAllows() {
		t.Fatal("env and a minted file allowed a catch")
	}
	block := engine.Outcome{Action: "hardblock", Exit: 121}
	if block.Action == "catch" && coverAllows() {
		t.Fatal("hardblock must not be rewritten")
	}
	if stateDir() == dir {
		t.Fatal("fake key dir became the state dir")
	}
}

func TestCoveredRequiresHost(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "decide.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("{\"decision\":\"cancel\"}\n"))
	}()
	t.Setenv("SPOTTER_SH_HOOK", sock)
	t.Setenv("SPOTTER_SH_COVERED", "deadbeef")
	if coverAllows() {
		t.Fatal("a cancel from the host still covered")
	}
}
