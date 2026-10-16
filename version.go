// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package spottersh is Shell Spotter, the oops spotter for agent-driven shells.
// The command implementation lives in cmd/spotter-sh. Hosts integrate
// through the hook package.
package spottersh

import "runtime/debug"

// Version is reported in pause messages and log lines.
const Version = "0.1.0"

// Commit is the git revision baked into the binary, when the build recorded one.
func Commit() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return ""
}
