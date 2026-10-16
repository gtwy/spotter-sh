// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package shim_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtwy/spotter-sh/internal/codes"
)

func TestWrappedProgramCannotReadKey(t *testing.T) {
	if _, err := exec.LookPath("sudo"); err != nil {
		t.Skip("sudo")
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skip("sudo -n")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash")
	}
	root := moduleRoot(t)
	home := t.TempDir()
	bin := filepath.Join(home, "spotter-sh")
	build := exec.Command("go", "build", "-o", bin, "./cmd/spotter-sh")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	if err := exec.Command("sudo", "-n", "groupadd", "--system", "spotter-sh").Run(); err != nil {
		if _, lookErr := exec.Command("getent", "group", "spotter-sh").Output(); lookErr != nil {
			t.Fatal(err)
		}
	}
	state := filepath.Join(home, "state")
	if err := codes.EnsureKey(state); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(state, "key")
	sudo := func(args ...string) {
		t.Helper()
		cmd := exec.Command("sudo", append([]string{"-n"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sudo %v: %v %s", args, err, out)
		}
	}
	sudo("chown", "root:spotter-sh", key)
	sudo("chmod", "0640", key)
	sudo("chgrp", "spotter-sh", bin)
	sudo("chmod", "2755", bin)
	// The key directory is stamped beside the binary. The environment is not.
	if err := codes.WriteStamp(bin, state); err != nil {
		t.Fatal(err)
	}

	shimDir := filepath.Join(home, "shims")
	probeDir := filepath.Join(home, "probe")
	if err := os.MkdirAll(shimDir, 0o755); err != nil || os.MkdirAll(probeDir, 0o755) != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bin, filepath.Join(shimDir, "rm")); err != nil {
		t.Fatal(err)
	}
	probe := "#!/bin/sh\n" +
		"target=${1:?}\n" +
		"if [ -r \"${target}\" ]; then\n" +
		"printf '%s\\n' readable\n" +
		"exit 3\n" +
		"fi\n" +
		"printf '%s\\n' closed\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(probeDir, "rm"), []byte(probe), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(shimDir, "rm"), key)
	cmd.Env = []string{
		"HOME=" + home,
		"PATH=" + shimDir + ":" + probeDir + ":/usr/bin:/bin",
		"SPOTTER_SH_HOME=" + state,
	}
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	if code != 0 || strings.TrimSpace(string(out)) != "closed" {
		t.Fatalf("wrapped program read the key: %d %q", code, out)
	}

	// git and systemctl probes must drop the group before they start.
	fake := filepath.Join(home, "fakebin")
	if err := os.MkdirAll(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(home, "probe-result")
	script := "#!/bin/sh\n" +
		"target=${PROBE_KEY:?}\n" +
		"out=${PROBE_OUT:?}\n" +
		"if [ -e \"${out}\" ]; then\n" +
		"exit 1\n" +
		"fi\n" +
		"if [ -r \"${target}\" ]; then\n" +
		"printf '%s\\n' readable > \"${out}\"\n" +
		"else\n" +
		"printf '%s\\n' closed > \"${out}\"\n" +
		"fi\n" +
		"printf '%s\\n' inactive\n" +
		"exit 1\n"
	for _, name := range []string{"git", "systemctl"} {
		if err := os.WriteFile(filepath.Join(fake, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	probeEnv := []string{
		"HOME=" + home,
		"PATH=" + fake + ":/usr/bin:/bin",
		"SPOTTER_SH_HOME=" + state,
		"PROBE_KEY=" + key,
		"PROBE_OUT=" + result,
	}
	for _, args := range [][]string{
		{"git", "clean", "-fd"},
		{"systemctl", "stop", "spotter-sh-no-such.service"},
	} {
		if err := os.Remove(result); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, args[1:]...)
		cmd.Args = args
		cmd.Env = probeEnv
		cmd.Dir = home
		_, _ = cmd.CombinedOutput()
		buf, err := os.ReadFile(result)
		if err != nil {
			t.Fatalf("%s probe did not run: %v", args[0], err)
		}
		if strings.TrimSpace(string(buf)) != "closed" {
			t.Fatalf("%s probe could read the key: %q", args[0], buf)
		}
	}

	hook := filepath.Join(home, "hook.sh")
	if err := os.WriteFile(hook, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cfgDir := filepath.Join(home, "etccfg")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(cfgDir, "config.toml")
	body := "mode = \"enforce\"\nhook_command = " + strconvQuote(hook) + "\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	sudo("mkdir", "-p", "/etc/spotter-sh")
	sudo("cp", "--", cfgPath, "/etc/spotter-sh/config.toml")
	t.Cleanup(func() {
		_ = exec.Command("sudo", "-n", "rm", "-f", "--", "/etc/spotter-sh/config.toml").Run()
	})
	if err := os.Remove(result); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	cmd = exec.Command(bin, "-rf", "--", "/etc/passwd")
	cmd.Args = []string{"rm", "-rf", "--", "/etc/passwd"}
	cmd.Env = probeEnv
	cmd.Dir = home
	_, _ = cmd.CombinedOutput()
	buf, err := os.ReadFile(result)
	if err != nil {
		t.Fatalf("hook did not run: %v", err)
	}
	if strings.TrimSpace(string(buf)) != "closed" {
		t.Fatalf("hook could read the key: %q", buf)
	}
	if _, err := os.Stat("/etc/passwd"); err != nil {
		t.Fatal("/etc/passwd missing")
	}
}

func strconvQuote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
