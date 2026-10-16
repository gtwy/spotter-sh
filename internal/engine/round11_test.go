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

func TestRound11WeightedDirs(t *testing.T) {
	home := t.TempDir()
	work := filepath.Join(home, "ws", "big")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	var five []string
	five = append(five, "rm", "-rf")
	for i := 1; i <= 5; i++ {
		p := filepath.Join(work, "d"+itoa(i))
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		five = append(five, p)
	}
	o := Decide(Input{Argv: five, Cwd: home, Home: home, Config: config.Defaults(), StdinKind: "null"})
	if o.Action != "catch" || o.Exit != 120 {
		t.Fatalf("five dirs %s %s exit %d %s", o.Action, o.Level, o.Exit, o.Consequence)
	}
	three := []string{"rm", "-rf", five[2], five[3], five[4]}
	o = Decide(Input{Argv: three, Cwd: home, Home: home, Config: config.Defaults(), StdinKind: "null"})
	if o.Action != "allow" {
		t.Fatalf("three dirs %s %s", o.Action, o.Consequence)
	}
	four := []string{"rm", "-rf", five[2], five[3], five[4], five[5]}
	o = Decide(Input{Argv: four, Cwd: home, Home: home, Config: config.Defaults(), StdinKind: "null"})
	if o.Action != "catch" || o.Exit != 120 {
		t.Fatalf("four dirs %s %s exit %d %s", o.Action, o.Level, o.Exit, o.Consequence)
	}
	link := filepath.Join(work, "rootlink")
	if err := os.Symlink("/", link); err != nil {
		t.Fatal(err)
	}
	o = Decide(Input{
		Argv:      []string{"rm", "-rf", link + "/"},
		Cwd:       home,
		Home:      home,
		Config:    config.Defaults(),
		StdinKind: "null",
	})
	if o.Action != "hardblock" || o.Exit != 121 || o.Approve {
		t.Fatalf("root symlink %s approve %v exit %d %s", o.Action, o.Approve, o.Exit, o.Consequence)
	}
}
