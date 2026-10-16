// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package codes

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCoverArmAndDisarm(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SPOTTER_SH_HOME", dir)
	t.Setenv("HOME", dir)
	if got := FixedDir(); got == dir {
		t.Fatalf("env chose FixedDir: %s", got)
	}
	id, err := ArmCover(dir, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !CoverArmed(dir, id) {
		t.Fatal("fresh cover not armed")
	}
	if CoverArmed(dir, id+"nope") {
		t.Fatal("unknown id armed")
	}
	if CoverArmed(dir, "../"+id) || CoverArmed(dir, "cover/"+id) {
		t.Fatal("path escape armed")
	}
	DisarmCover(dir, id)
	if CoverArmed(dir, id) {
		t.Fatal("disarmed cover still armed")
	}
}

func TestCoverRejectsBadMacAndExpiry(t *testing.T) {
	dir := t.TempDir()
	if err := EnsureKey(dir); err != nil {
		t.Fatal(err)
	}
	id := "abcdef0123456789abcdef0123456789"
	past := "1"
	path := filepath.Join(dir, "cover", id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body := id + "\n" + past + "\n" + "00\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if CoverArmed(dir, id) {
		t.Fatal("expired cover armed")
	}
	id2, err := ArmCover(dir, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	p, err := coverPath(dir, id2)
	if err != nil {
		t.Fatal(err)
	}
	buf, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	buf[len(buf)-4] ^= 0x1
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	if CoverArmed(dir, id2) {
		t.Fatal("bad mac armed")
	}
}
