// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package envx

import (
	"os"
	"testing"
)

func TestLegacyFallsBackWhenCurrentIsUnset(t *testing.T) {
	t.Setenv("SHELLSPOTTER_MODE", "enforce")
	os.Unsetenv("SPOTTER_SH_MODE")
	t.Cleanup(func() { os.Unsetenv("SPOTTER_SH_MODE") })
	if got := Get("MODE"); got != "enforce" {
		t.Fatalf("legacy mode %q", got)
	}
	if got := Get("SPOTTER_SH_MODE"); got != "enforce" {
		t.Fatalf("full name %q", got)
	}
}

func TestCurrentNameWins(t *testing.T) {
	t.Setenv("SPOTTER_SH_MODE", "silent")
	t.Setenv("SHELLSPOTTER_MODE", "enforce")
	if got := Get("MODE"); got != "silent" {
		t.Fatalf("current %q", got)
	}
	env := map[string]string{
		"SPOTTER_SH_HOST":   "1",
		"SHELLSPOTTER_HOST": "0",
		"SHELLSPOTTER_MODE": "enforce",
	}
	if v, ok := MapGet(env, "HOST"); !ok || v != "1" {
		t.Fatalf("host %q %v", v, ok)
	}
	if v, ok := MapGet(env, "MODE"); !ok || v != "enforce" {
		t.Fatalf("mode fallback %q %v", v, ok)
	}
}

func TestStripRemovesBothNames(t *testing.T) {
	in := []string{"PATH=/bin", "SPOTTER_SH_OK=new", "SHELLSPOTTER_OK=old", "HOME=/tmp"}
	out := Strip(in, "OK")
	if len(out) != 2 || out[0] != "PATH=/bin" || out[1] != "HOME=/tmp" {
		t.Fatalf("%q", out)
	}
}
