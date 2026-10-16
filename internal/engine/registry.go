// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import "sync"

// PackMatch classifies an argv for a third-party pack.
// A nil outcome means the pack does not care.
type PackMatch func(argv []string, cwd string) *Outcome

var (
	regMu      sync.Mutex
	regProtect []string
	regPacks   []PackMatch
)

// RegisterProtected adds an in-process recursive protected path.
func RegisterProtected(pattern string) {
	regMu.Lock()
	regProtect = append(regProtect, pattern)
	regMu.Unlock()
}

// RegisterPack adds an in-process rule pack.
func RegisterPack(match PackMatch) {
	regMu.Lock()
	regPacks = append(regPacks, match)
	regMu.Unlock()
}

func extraProtect() []string {
	regMu.Lock()
	defer regMu.Unlock()
	return append([]string{}, regProtect...)
}

func extraPacks() []PackMatch {
	regMu.Lock()
	defer regMu.Unlock()
	return append([]PackMatch{}, regPacks...)
}

// ResetRegistry clears in-process registrations. Tests use it.
func ResetRegistry() {
	regMu.Lock()
	regProtect = nil
	regPacks = nil
	regMu.Unlock()
}
