// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishSystemKeyIsReadable(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, []byte("0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := publishSystemKey(dir, ""); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSetgid == 0 || st.Mode().Perm() != 0o770 {
		t.Fatalf("dir mode %o", st.Mode())
	}
	if st.Mode().Perm()&0o007 != 0 {
		t.Fatalf("state is writable by others: %o", st.Mode())
	}
	kst, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	if kst.Mode().Perm() != 0o640 || kst.Mode().Perm()&0o007 != 0 {
		t.Fatalf("key mode %o", kst.Mode().Perm())
	}
	buf, err := os.ReadFile(key)
	if err != nil || string(buf) != "0123456789abcdef" {
		t.Fatalf("owner cannot read key: %v", err)
	}
}
