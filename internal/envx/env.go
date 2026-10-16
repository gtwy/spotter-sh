// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package envx reads Shell Spotter environment variables.
// The current names are SPOTTER_SH_*. The older SHELLSPOTTER_* names still
// apply when the current name is unset.
package envx

import (
	"os"
	"strings"
)

const (
	prefix    = "SPOTTER_SH_"
	oldPrefix = "SHELLSPOTTER_"
)

// Suffix accepts a bare suffix or either full variable name.
func Suffix(name string) string {
	switch {
	case strings.HasPrefix(name, prefix):
		return strings.TrimPrefix(name, prefix)
	case strings.HasPrefix(name, oldPrefix):
		return strings.TrimPrefix(name, oldPrefix)
	default:
		return name
	}
}

// Name is the current variable, SPOTTER_SH_<suffix>.
func Name(name string) string {
	return prefix + Suffix(name)
}

// LegacyName is the older variable, SHELLSPOTTER_<suffix>.
func LegacyName(name string) string {
	return oldPrefix + Suffix(name)
}

// Get returns the current variable, or the older one when the current name is unset.
func Get(name string) string {
	v, _ := Lookup(name)
	return v
}

// Lookup reports whether either name is present. An empty current value wins.
func Lookup(name string) (string, bool) {
	if v, ok := os.LookupEnv(Name(name)); ok {
		return v, true
	}
	return os.LookupEnv(LegacyName(name))
}

// Set writes the current name. It leaves an older value in place.
func Set(name, value string) error {
	return os.Setenv(Name(name), value)
}

// Unset removes both the current name and the older name.
func Unset(name string) error {
	err1 := os.Unsetenv(Name(name))
	err2 := os.Unsetenv(LegacyName(name))
	if err1 != nil {
		return err1
	}
	return err2
}

// MapGet reads one variable from a process environment map.
// The current name wins when that key is present, including when it is empty.
func MapGet(env map[string]string, name string) (string, bool) {
	if env == nil {
		return "", false
	}
	if v, ok := env[Name(name)]; ok {
		return v, true
	}
	v, ok := env[LegacyName(name)]
	return v, ok
}

// HasPrefix reports whether an environment entry assigns either name.
func HasPrefix(entry, name string) bool {
	return strings.HasPrefix(entry, Name(name)+"=") || strings.HasPrefix(entry, LegacyName(name)+"=")
}

// Strip removes assignments of either name.
func Strip(env []string, name string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		if HasPrefix(e, name) {
			continue
		}
		out = append(out, e)
	}
	return out
}
