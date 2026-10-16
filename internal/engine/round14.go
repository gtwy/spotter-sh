// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import "github.com/gtwy/spotter-sh/internal/precheck"

// decideLauncher judges the command a launcher will run.
// The shim's argv is the launcher, so the payload has to be unwrapped
// before the real binary is chosen. A scheduler with no readable payload
// is a catch: the job would run later, outside this check.
func (in Input) decideLauncher(argv []string) (Outcome, bool) {
	if len(argv) == 0 {
		return Outcome{}, false
	}
	kind, rest, script := precheck.PeekLaunch(argv, string(in.StdinPeek))
	switch kind {
	case precheck.LaunchNone:
		return Outcome{}, false
	case precheck.LaunchOpaque:
		o := in.danger("F", "deferred", "a scheduler runs a command this check cannot see", "the payload is not in the command", "pass the command where it can be read", nil, "deferred")
		o.Approve = true
		return o, true
	case precheck.LaunchScript:
		r := precheck.ScanAt(script, in.Cwd, in.Home)
		if r.Action == "hardblock" || r.Action == "catch" {
			return outcomeFromPrecheck(r), true
		}
		return allow(), true
	case precheck.LaunchArgv:
		if r, ok := precheck.JudgeSystemd(argv, rest, in.Cwd, in.Home); ok {
			return outcomeFromPrecheck(r), true
		}
		if len(rest) == 0 {
			return allow(), true
		}
		in.Argv = append([]string(nil), rest...)
		return Decide(in), true
	default:
		return Outcome{}, false
	}
}
