// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package hook

import (
	"context"
	"io"
	"log"
)

// Middleware wraps a handler.
type Middleware func(DecisionHandler) DecisionHandler

// Logging logs each catch and decision.
func Logging(w io.Writer) Middleware {
	lg := log.New(w, "spotter-sh ", log.LstdFlags)
	return func(next DecisionHandler) DecisionHandler {
		return HandlerFunc(func(ctx context.Context, c Catch) (Decision, error) {
			lg.Printf("catch %s level=%s cmd=%s", c.CatchID, c.Level, c.Command)
			d, err := next.OnCatch(ctx, c)
			lg.Printf("decision %s %s", c.CatchID, d.Action)
			return d, err
		})
	}
}

// Policy auto-resolves when match returns ok.
func Policy(match func(Catch) (Decision, bool)) Middleware {
	return func(next DecisionHandler) DecisionHandler {
		return HandlerFunc(func(ctx context.Context, c Catch) (Decision, error) {
			if d, ok := match(c); ok {
				return d, nil
			}
			return next.OnCatch(ctx, c)
		})
	}
}

// Chain applies middleware outermost-first.
func Chain(h DecisionHandler, mw ...Middleware) DecisionHandler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}
