// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package rollout

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	if Normalize("silent") != "silent" || Normalize("ENFORCE") != "enforce" || Normalize("standard") != "enforce" {
		t.Fatal(Normalize("silent"), Normalize("ENFORCE"), Normalize("standard"))
	}
	if Normalize("off") != "" {
		t.Fatal("unknown mode")
	}
}

func TestCaptureDefaultSilent(t *testing.T) {
	if os.Getenv("SPOTTER_SH_CAPTURE_HELPER") == "1" {
		fmt.Println(Capture(""))
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCaptureDefaultSilent$", "-test.count=1")
	cmd.Env = []string{"SPOTTER_SH_CAPTURE_HELPER=1", "PATH=" + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if !strings.Contains(string(out), "silent") {
		t.Fatalf("default %s", out)
	}
	if os.Getenv("SPOTTER_SH_HOST") == "1" && os.Getenv("SPOTTER_SH_MODE") == "silent" && os.Getenv("SPOTTER_SH_CAPTURE_HELPER") == "" {
		// The parent process must not adopt the helper's seal.
	}
}

func TestShimIgnoresOwnMode(t *testing.T) {
	if Scan().Found {
		t.Skip("an ancestor is already a sealed host")
	}
	t.Setenv("SPOTTER_SH_MODE", "silent")
	if !SilentNow("") {
		t.Fatal("operator env should select silent for the CLI")
	}
	if ShimSilent("") {
		t.Fatal("shim fell open with no host ancestor")
	}
	t.Setenv("SPOTTER_SH_MODE", "enforce")
	if SilentNow("") {
		t.Fatal("operator env should select enforce for the CLI")
	}
	if ShimSilent("") {
		t.Fatal("shim followed its own mode instead of failing closed")
	}
}

func TestLegacyModeStillSelects(t *testing.T) {
	if Scan().Found {
		t.Skip("an ancestor is already a sealed host")
	}
	os.Unsetenv("SPOTTER_SH_MODE")
	os.Unsetenv("SPOTTER_SH_HOST")
	t.Cleanup(func() {
		os.Unsetenv("SPOTTER_SH_MODE")
		os.Unsetenv("SPOTTER_SH_HOST")
	})
	t.Setenv("SHELLSPOTTER_MODE", "enforce")
	if SilentNow("") {
		t.Fatal("legacy SHELLSPOTTER_MODE was ignored")
	}
	if ShimSilent("") {
		t.Fatal("shim fell open from a legacy mode on itself")
	}
}

func TestJudgeDelayCaps(t *testing.T) {
	if d := JudgeDelay(); d != 0 && d > 5*time.Second {
		t.Fatal(d)
	}
}
