// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"fmt"
	"strings"

	"github.com/gtwy/spotter-sh"
)

// Affected is the structured blast radius.
type Affected struct {
	Op        string
	Count     int
	Bytes     int64
	HaveBytes bool
	Top       []string
	Protected bool
	PermFrom  string
	PermTo    string
	TimedOut  bool
	Partial   int
}

// Outcome is one classification.
type Outcome struct {
	Action           string // allow, catch, hardblock, fail
	Level            string // danger, bulk, hardblock
	Case             string
	Exit             int
	Report           string
	Consequence      string
	Mistake          string
	Safer            string
	Affected         Affected
	ParseFallthrough bool
	LogNote          string
	Near             bool
	InjectSafe       bool
	Message          string // short fail/block line
	Approve          bool   // heuristic hard block an admin may approve
}

func (o Outcome) caught() bool { return o.Action == "catch" || o.Action == "hardblock" }

func allow() Outcome { return Outcome{Action: "allow", Exit: 0} }

func failClosed(why string) Outcome {
	return Outcome{
		Action:  "fail",
		Exit:    122,
		Message: "Shell Spotter failed; command not run; see log; a human can run it by hand or fix the spotter (" + why + ")",
		LogNote: "spotter_error",
	}
}

func (in Input) render(o Outcome, argv []string) Outcome {
	if o.Action == "allow" || o.Action == "fail" {
		if o.Action == "fail" && o.Message == "" {
			o.Message = "Shell Spotter failed; command not run; see log; a human can run it by hand or fix the spotter"
		}
		return o
	}
	header := "Shell Spotter: paused — large operation"
	if o.Level == "danger" {
		header = "================  Shell Spotter: DANGER — would damage protected paths  ================"
	}
	if o.Level == "hardblock" {
		header = "Shell Spotter: BLOCKED"
	}
	if o.Affected.TimedOut {
		header = "Shell Spotter: paused — check timed out"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", header)
	fmt.Fprintf(&b, "command : %s     (cwd: %s)\n", strings.Join(argv, " "), in.Cwd)
	if o.Affected.Op != "" {
		fmt.Fprintf(&b, "effect  : %s", o.Affected.Op)
		if o.Affected.Count > 0 {
			fmt.Fprintf(&b, ", %d targets", o.Affected.Count)
		}
		b.WriteByte('\n')
	}
	if o.Affected.TimedOut {
		fmt.Fprintf(&b, "check timed out. count reached so far: %d. a long scan likely means a very large target.\n", o.Affected.Partial)
	}
	if len(o.Affected.Top) > 0 {
		b.WriteString("targets :\n")
		n := len(o.Affected.Top)
		if n > 20 {
			n = 20
		}
		for _, p := range o.Affected.Top[:n] {
			fmt.Fprintf(&b, "  %s\n", p)
		}
		if o.Affected.Count > n {
			fmt.Fprintf(&b, "  + %d more\n", o.Affected.Count-n)
		}
	}
	if o.Affected.PermTo != "" {
		fmt.Fprintf(&b, "perms   : %s -> %s\n", o.Affected.PermFrom, o.Affected.PermTo)
	}
	if o.Consequence != "" {
		fmt.Fprintf(&b, "likely consequence : %s\n", o.Consequence)
	}
	if o.Mistake != "" {
		fmt.Fprintf(&b, "common mistake     : %s\n", o.Mistake)
	}
	if o.Safer != "" {
		fmt.Fprintf(&b, "safer rewrite      : %s\n", o.Safer)
	}
	fmt.Fprintf(&b, "version : %s\n", spottersh.Version)
	o.Report = b.String()
	if o.Exit == 0 {
		if o.Action == "hardblock" {
			o.Exit = 121
		} else {
			o.Exit = 120
		}
	}
	return o
}
