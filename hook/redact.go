// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package hook

import "github.com/gtwy/spotter-sh/internal/redact"

// Redact masks secrets in one string. Approval codes stay intact.
func Redact(s string) string {
	return redact.New(nil).Apply(s)
}

// RedactArgv masks each argument and the value after a secret flag.
func RedactArgv(argv []string) []string {
	return redact.New(nil).Argv(argv)
}

// SecretValues lists values that follow a secret flag in argv.
func SecretValues(argv []string) []string {
	return redact.New(nil).SecretValues(argv)
}

// MaskValues replaces secret values in s.
func MaskValues(s string, vals []string) string {
	return redact.New(nil).MaskValues(s, vals)
}
