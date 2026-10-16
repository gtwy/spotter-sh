// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gtwy/spotter-sh/internal/codes"
)

func TestDropTokenBindsArgv(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := os.WriteFile(filepath.Join(dir, "key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil && resolved != "" {
		exe = resolved
	}
	if err := codes.WriteStamp(exe, dir); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(exe + ".state")
	t.Setenv("SPOTTER_SH_HOME", filepath.Join(dir, "not-the-key"))
	argv := []string{"rm", "-rf", "x"}
	tok := signDrop(key, "/bin/rm", argv)
	real, ok := verifyDrop(tok, argv)
	if !ok || real != "/bin/rm" {
		t.Fatalf("verify %q %v", real, ok)
	}
	if _, ok := verifyDrop(tok, []string{"rm", "-rf", "y"}); ok {
		t.Fatal("token accepted a different argv")
	}
	if _, ok := verifyDrop("00.2f62696e2f726d", argv); ok {
		t.Fatal("garbage token accepted")
	}
	t.Setenv(DropEnv, tok)
	got, ok := TakeDrop(argv)
	if !ok || got != "/bin/rm" {
		t.Fatalf("take %q %v", got, ok)
	}
	if _, present := os.LookupEnv(DropEnv); present {
		t.Fatal("token still set")
	}
	t.Setenv(DropEnv, "not-a-token")
	if _, ok := TakeDrop(argv); ok {
		t.Fatal("user token selected drop mode")
	}
	if _, present := os.LookupEnv(DropEnv); present {
		t.Fatal("rejected token still set")
	}
	os.Unsetenv(DropEnv)
	t.Setenv("SHELLSPOTTER_DROP", tok)
	got, ok = TakeDrop(argv)
	if !ok || got != "/bin/rm" {
		t.Fatalf("legacy take %q %v", got, ok)
	}
	if _, present := os.LookupEnv("SHELLSPOTTER_DROP"); present {
		t.Fatal("legacy token still set")
	}
}
