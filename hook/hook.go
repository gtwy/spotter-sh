// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package hook is the public approval API.
// A host runs Serve; shims block on the socket until a decision comes back.
package hook

import (
	"context"
	"time"

	"github.com/gtwy/spotter-sh/internal/engine"
)

// SchemaVersion is the catch-record version.
const SchemaVersion = "1.0"

// Catch is one pause sent to the host.
type Catch struct {
	SchemaVersion string   `json:"schema_version"`
	CatchID       string   `json:"catch_id"`
	Level         string   `json:"level"`
	Command       string   `json:"command"`
	Argv          []string `json:"argv"`
	Cwd           string   `json:"cwd"`
	Restricted    bool     `json:"restricted"`
	Report        string   `json:"report"`
	Affected      Affected `json:"affected"`
	Consequence   string   `json:"consequence,omitempty"`
	CommonMistake string   `json:"common_mistake,omitempty"`
	SaferRewrite  string   `json:"safer_rewrite,omitempty"`
	// Approve is set on a text heuristic. An admin may proceed.
	// An exact / or a disk has no approval.
	Approve bool `json:"approve,omitempty"`
	// Op is seal or covered. Those are not catches. seal binds the approval
	// to the calling process tree. covered asks whether this process is
	// still inside that tree. An empty Op is a normal catch.
	Op string `json:"op,omitempty"`
}

// TreeHandler answers a seal or a covered check. peer is the connecting
// process, from the socket credentials, not from the message.
type TreeHandler interface {
	OnSeal(peer int) bool
	OnCovered(peer int) bool
}

// Affected is the blast radius.
type Affected struct {
	Op           string   `json:"op,omitempty"`
	Count        int      `json:"count,omitempty"`
	Bytes        int64    `json:"bytes,omitempty"`
	TopPaths     []string `json:"top_paths,omitempty"`
	ProtectedHit bool     `json:"protected_hit,omitempty"`
	PermChange   *Perm    `json:"perm_change,omitempty"`
	TimedOut     bool     `json:"timed_out,omitempty"`
	PartialCount int      `json:"partial_count,omitempty"`
}

// Perm is a permission change.
type Perm struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// Decision is the host's reply. Action is proceed, cancel, or ask_human.
type Decision struct {
	CatchID string `json:"catch_id,omitempty"`
	Action  string `json:"decision"`
	Reason  string `json:"reason,omitempty"`
}

// DecisionHandler answers one catch. An error becomes cancel.
type DecisionHandler interface {
	OnCatch(ctx context.Context, c Catch) (Decision, error)
}

// HandlerFunc adapts a function to DecisionHandler.
type HandlerFunc func(ctx context.Context, c Catch) (Decision, error)

// OnCatch calls the function.
func (f HandlerFunc) OnCatch(ctx context.Context, c Catch) (Decision, error) { return f(ctx, c) }

// Option configures Serve and RunShell.
type Option func(*options)

type options struct {
	Timeout time.Duration
}

// WithDecisionTimeout bounds how long Serve waits for a handler.
// ask_human itself is not given a short timeout by the shim.
func WithDecisionTimeout(d time.Duration) Option {
	return func(o *options) { o.Timeout = d }
}

// RegisterProtected adds a recursive protected path for this process.
func RegisterProtected(pattern string) { engine.RegisterProtected(pattern) }

// RegisterPack adds an in-process rule. match returns a catch description
// or nil. The returned Catch is converted into a pause.
func RegisterPack(name string, match func(argv []string) *Catch) {
	engine.RegisterPack(func(argv []string, cwd string) *engine.Outcome {
		c := match(argv)
		if c == nil {
			return nil
		}
		o := engine.Outcome{
			Action: "catch", Level: c.Level, Exit: 120,
			Report: c.Report, Consequence: c.Consequence, Safer: c.SaferRewrite,
			Affected: engine.Affected{
				Op: c.Affected.Op, Count: c.Affected.Count, Top: c.Affected.TopPaths,
				Protected: c.Affected.ProtectedHit, TimedOut: c.Affected.TimedOut, Partial: c.Affected.PartialCount,
			},
		}
		if o.Level == "" {
			o.Level = "danger"
		}
		if o.Level == "hardblock" {
			o.Action = "hardblock"
			o.Exit = 121
		}
		return &o
	})
	_ = name
}

// ResetForTest clears in-process packs and paths.
func ResetForTest() { engine.ResetRegistry() }
