// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package shim_test

import (
	"os"
	"testing"

	"github.com/gtwy/spotter-sh/hook"
	"github.com/gtwy/spotter-sh/internal/config"
	"github.com/gtwy/spotter-sh/internal/engine"
	"github.com/gtwy/spotter-sh/internal/precheck"
	"github.com/gtwy/spotter-sh/internal/shim"
)

// The corpus lives in hook so the host module, which cannot import internal
// packages, checks the same commands.

// TestLayerTiersAgree locks the text check, host PrecheckAt, the engine,
// and the shim to one tier per command. A catch on one layer and a hard
// block on another is a drift.
func TestLayerTiersAgree(t *testing.T) {
	// A temp directory keeps a relative operand out of this repository.
	// The engine treats the repo tree as protected, so `echo hi` from the
	// module root is a catch for a reason that is not the command itself.
	cwd := t.TempDir()
	back, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(back) })
	home := engine.HomeDir()
	if home == "" {
		home = cwd
	}
	cfg := config.Defaults()
	for _, c := range hook.LayerCorpus() {
		text := precheck.ScanAt(c.Text, cwd, home)
		hAction, hExit, _, hApprove := hook.PrecheckAt(c.Text, cwd, home)
		eng := engine.Decide(engine.Input{
			Argv: c.Argv, Cwd: cwd, Home: home, Config: cfg, StdinKind: "null",
		})
		got := shim.Check(c.Argv)
		tiers := []string{
			tierOf(text.Action),
			tierOf(hAction),
			tierOf(eng.Action),
			tierOf(got.Action),
		}
		for i, gotTier := range tiers {
			if gotTier != c.Tier {
				t.Errorf("%q layer %d tier %s want %s (text %s host %s engine %s shim %s)",
					c.Text, i, gotTier, c.Tier, text.Action, hAction, eng.Action, got.Action)
			}
		}
		if tiers[0] != tiers[1] || tiers[1] != tiers[2] || tiers[2] != tiers[3] {
			t.Errorf("%q tiers split text %s host %s engine %s shim %s", c.Text, tiers[0], tiers[1], tiers[2], tiers[3])
		}
		switch c.Tier {
		case "hardblock":
			if text.Approve || text.Exit != 121 || hApprove || hExit != 121 || eng.Approve || eng.Exit != 121 || got.Approve || got.Exit != 121 {
				t.Errorf("%q hardblock not sealed text %d/%v host %d/%v engine %d/%v shim %d/%v",
					c.Text, text.Exit, text.Approve, hExit, hApprove, eng.Exit, eng.Approve, got.Exit, got.Approve)
			}
		case "catch":
			if !text.Approve || text.Exit != 120 || !hApprove || hExit != 120 || eng.Exit != 120 || got.Exit != 120 {
				t.Errorf("%q catch text %d/%v host %d/%v engine %d shim %d",
					c.Text, text.Exit, text.Approve, hExit, hApprove, eng.Exit, got.Exit)
			}
		default:
			if text.Exit != 0 || hExit != 0 || eng.Exit != 0 || got.Exit != 0 {
				t.Errorf("%q pass exits text %d host %d engine %d shim %d", c.Text, text.Exit, hExit, eng.Exit, got.Exit)
			}
		}
	}
}

func tierOf(action string) string {
	switch action {
	case "hardblock":
		return "hardblock"
	case "catch":
		return "catch"
	default:
		return "pass"
	}
}
