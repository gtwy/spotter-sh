// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package shim

import "strings"
import "testing"

func TestSealShellEnv(t *testing.T) {
	env := sealShellEnv(
		[]string{"PATH=/usr/bin:/bin", "HOME=/tmp", "SPOTTER_SH_MODE=silent"},
		"/opt/spotter/shims",
		map[string]string{
			"SPOTTER_SH_MODE":   "enforce",
			"SPOTTER_SH_HOST":   "1",
			"SHELLSPOTTER_MODE": "enforce",
			"HOME":              "/root",
			"UNRELATED":         "no",
		},
	)
	path, mode, host, legacy, home := "", "", "", "", ""
	for _, e := range env {
		switch {
		case strings.HasPrefix(e, "PATH="):
			path = strings.TrimPrefix(e, "PATH=")
		case e == "SPOTTER_SH_MODE=silent" || strings.HasPrefix(e, "SPOTTER_SH_MODE="):
			mode = e
		case strings.HasPrefix(e, "SPOTTER_SH_HOST="):
			host = e
		case strings.HasPrefix(e, "SHELLSPOTTER_MODE="):
			legacy = e
		case strings.HasPrefix(e, "HOME="):
			home = e
		case strings.HasPrefix(e, "UNRELATED="):
			t.Fatalf("non-spotter host value copied: %s", e)
		}
	}
	if !strings.HasPrefix(path, "/opt/spotter/shims:") {
		t.Fatalf("PATH %s", path)
	}
	if mode != "SPOTTER_SH_MODE=silent" {
		t.Fatalf("existing mode replaced: %s", mode)
	}
	if host != "SPOTTER_SH_HOST=1" || legacy != "SHELLSPOTTER_MODE=enforce" {
		t.Fatalf("host vars host=%s legacy=%s", host, legacy)
	}
	if home != "HOME=/tmp" {
		t.Fatalf("HOME %s", home)
	}
	again := sealShellEnv(env, "/opt/spotter/shims", nil)
	for _, e := range again {
		if strings.HasPrefix(e, "PATH=") && strings.Count(e, "/opt/spotter/shims") != 1 {
			t.Fatalf("shim dir repeated: %s", e)
		}
	}
	if childEnv("rm", []string{"PATH=/bin"})[0] != "PATH=/bin" {
		t.Fatal("rm env was rewritten")
	}
}
