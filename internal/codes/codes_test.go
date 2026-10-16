// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package codes

import (
	"testing"
	"time"
)

func TestBoundAndSingleUse(t *testing.T) {
	dir := t.TempDir()
	if err := EnsureKey(dir); err != nil {
		t.Fatal(err)
	}
	s := Store{Dir: dir}
	b := Binding{Argv: []string{"rm", "-rf", "x"}, Cwd: "/tmp", Level: "danger"}
	code, err := s.Issue(b, time.Minute, "SS-")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(code, Binding{Argv: []string{"rm", "-rf", "y"}, Cwd: "/tmp", Level: "danger"}); err == nil {
		t.Fatal("different argv accepted")
	}
	if err := s.Verify(code, b); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(code, b); err == nil {
		t.Fatal("spent code accepted")
	}
}
