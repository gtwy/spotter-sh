// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package shim

import (
	"os"
	"strings"
	"testing"

	"github.com/gtwy/spotter-sh/internal/redact"
)

func TestRerunLineHidesSecrets(t *testing.T) {
	red := redact.New(nil)
	line := rerunLine("SS-ABCD12", []string{
		"mysql", "-pS3cret", "-e", "postgres://user:S3cret@db.example/app",
	}, red)
	if strings.Contains(line, "S3cret") {
		t.Fatalf("secret leaked: %s", line)
	}
	if !strings.Contains(line, "SS-ABCD12") || !strings.Contains(line, "[REDACTED]") {
		t.Fatalf("line %s", line)
	}
	quoted := rerunLine("SS-ABCD12", []string{"echo", "a b"}, red)
	if !strings.Contains(quoted, "'echo'") || !strings.Contains(quoted, "'a b'") {
		t.Fatalf("quoting dropped: %s", quoted)
	}
}

func TestStateDirIgnoresCaller(t *testing.T) {
	fake := t.TempDir()
	t.Setenv("SPOTTER_SH_HOME", fake)
	t.Setenv("SHELLSPOTTER_HOME", fake)
	t.Setenv("HOME", fake)
	got := stateDir()
	if got == fake || strings.HasPrefix(got, fake+string(os.PathSeparator)) {
		t.Fatalf("caller env chose the state dir: %s", got)
	}
}
