// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import "testing"

func TestSpawnEnvSealsSilent(t *testing.T) {
	got := SpawnEnv("/opt/shims", "/tmp/spotter.sock", "")
	for _, line := range []string{
		"SPOTTER_SH_HOST=1\n",
		"SPOTTER_SH_MODE=silent\n",
		"SPOTTER_SH_HOOK=/tmp/spotter.sock\n",
		"PATH=/opt/shims:$PATH\n",
	} {
		if !contains(got, line) {
			t.Fatalf("missing %q in\n%s", line, got)
		}
	}
}

func TestGateCodes(t *testing.T) {
	run, _, note := classify(0, false)
	if !run || note == "" {
		t.Fatal(note)
	}
	run, exit, _ := classify(120, false)
	if run || exit != 120 {
		t.Fatalf("unapproved catch ran: %v %d", run, exit)
	}
	run, exit, note = classify(120, true)
	if !run || exit != 120 || note == "" {
		t.Fatalf("approved catch: %v %d %s", run, exit, note)
	}
	run, exit, note = classify(121, true)
	if run || exit != 121 {
		t.Fatalf("hard block ran: %v %d %s", run, exit, note)
	}
}

func classify(code int, admin bool) (bool, int, string) {
	switch code {
	case 0:
		return true, 0, "allowed, or silent mode logged it"
	case 120:
		if !admin {
			return false, 120, "approvable catch; admin did not approve"
		}
		return true, 120, "admin approved; rerun the identical command"
	case 121:
		return false, 121, "hard block; never run"
	default:
		return false, code, "spotter failure; command not run"
	}
}

func TestHookRefusesHardBlock(t *testing.T) {
	if got := HookDecision("hardblock", false, true); got != `{"decision":"cancel","reason":"hard block"}` {
		t.Fatal(got)
	}
	if got := HookDecision("danger", true, true); got != `{"decision":"proceed"}` {
		t.Fatal(got)
	}
}

func contains(s, part string) bool {
	return len(s) >= len(part) && (s == part || len(part) == 0 ||
		(len(s) > 0 && (indexOf(s, part) >= 0)))
}

func indexOf(s, part string) int {
	for i := 0; i+len(part) <= len(s); i++ {
		if s[i:i+len(part)] == part {
			return i
		}
	}
	return -1
}
