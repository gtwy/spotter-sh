// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gtwy/spotter-sh/internal/config"
)

func TestRound13DirectoryGlobIsApprovable(t *testing.T) {
	home := t.TempDir()
	ws := filepath.Join(home, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(ws, "rootlink")); err != nil {
		t.Fatal(err)
	}
	o := Decide(Input{
		Argv:      []string{"rm", "-rf", "--", filepath.Join(home, "ws") + "/*/"},
		Cwd:       home,
		Home:      home,
		Config:    config.Defaults(),
		StdinKind: "null",
	})
	if o.Action != "catch" || o.Exit != 120 || !o.Approve {
		t.Fatalf("dir glob %s approve %v exit %d %s", o.Action, o.Approve, o.Exit, o.Consequence)
	}
	o = Decide(Input{
		Argv:      []string{"rm", "-rf", filepath.Join(ws, "rootlink") + "/"},
		Cwd:       home,
		Home:      home,
		Config:    config.Defaults(),
		StdinKind: "null",
	})
	if o.Action != "hardblock" || o.Approve || o.Exit != 121 {
		t.Fatalf("root symlink %s approve %v exit %d %s", o.Action, o.Approve, o.Exit, o.Consequence)
	}
	o = Decide(Input{
		Argv:      []string{"rm", "-rf", filepath.Join(home, ".claude", "skills") + "/*"},
		Cwd:       home,
		Home:      home,
		Config:    config.Defaults(),
		StdinKind: "null",
	})
	if o.Action != "catch" || !o.Approve {
		t.Fatalf("dotdir glob %s approve %v %s", o.Action, o.Approve, o.Consequence)
	}
}
