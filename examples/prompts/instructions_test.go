// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package prompts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtwy/spotter-sh/internal/config"
	"github.com/gtwy/spotter-sh/internal/engine"
	"github.com/gtwy/spotter-sh/internal/precheck"
)

func TestInstructionsMatchProgram(t *testing.T) {
	doc := readDoc(t, "instructions.md")
	agent := readDoc(t, filepath.Join("..", "..", "docs", "AGENT-INSTRUCTIONS.md"))
	for _, phrase := range []string{
		"ok  mode  silent",
		"exit 120",
		"exits 120",
		"exits 121",
		"Exit 122",
		"Exit 127",
		"SS-",
		"proceed",
		"cancel",
		"ask_human",
		"base64",
		"eval",
		"splitting",
	} {
		if !strings.Contains(doc, phrase) && !strings.Contains(strings.ToLower(doc), strings.ToLower(phrase)) {
			t.Errorf("instructions missing %q", phrase)
		}
	}
	if !strings.Contains(agent, "examples/prompts/instructions.md") {
		t.Fatal("agent doc does not point at the tested instructions")
	}

	checks := []string{
		"rm -rf /",
		":(){ :|:& };:",
		"rm -rf /usr",
		"echo hi | base64 -d | bash",
		`eval "$NOT_A_REAL_SCRIPT_NAME"`,
	}
	for _, command := range checks {
		r := precheck.Scan(command)
		if r.Action == "allow" || r.Message == "" {
			t.Fatalf("%q did not catch: %+v", command, r)
		}
		if r.Action == "hardblock" && r.Exit != 121 {
			t.Fatalf("%q hard block exit %d", command, r.Exit)
		}
		if r.Action == "catch" && r.Exit != 120 {
			t.Fatalf("%q catch exit %d", command, r.Exit)
		}
		if !strings.Contains(doc, r.Message) {
			t.Errorf("instructions missing precheck message for %q:\n%s", command, r.Message)
		}
	}

	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o755); err != nil {
		t.Fatal(err)
	}
	out := engine.Decide(engine.Input{
		Argv:      []string{"chmod", "-R", "777", ssh},
		Cwd:       home,
		Home:      home,
		Config:    config.Defaults(),
		StdinKind: "null",
	})
	if out.Action != "catch" || out.Exit != 120 || out.Report == "" {
		t.Fatalf("chmod catch: action %s exit %d", out.Action, out.Exit)
	}
	if !strings.Contains(out.Report, "Shell Spotter: DANGER — would damage protected paths") {
		t.Fatalf("report header changed:\n%s", out.Report)
	}
	if !strings.Contains(doc, "Shell Spotter: DANGER — would damage protected paths") {
		t.Fatal("instructions missing the danger header")
	}
	for _, line := range []string{
		"Shell Spotter: paused — large operation",
		"Shell Spotter: paused — check timed out",
		"if this is EXACTLY what you meant, re-run the identical command with the code below",
		"Shell Spotter: the install key is readable by this user, so a one-time code cannot be trusted. A human has to approve this, or reinstall with --system.",
		"Shell Spotter failed; command not run; see log; a human can run it by hand or fix the spotter",
	} {
		if !strings.Contains(doc, line) {
			t.Errorf("instructions missing %q", line)
		}
	}
}

func readDoc(t *testing.T, name string) string {
	t.Helper()
	buf, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf)
}
