// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package silentlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRotationPermsAndSecrets(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key"), []byte("0123456789abcdef"), 0o640); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "silent.jsonl")
	opt := Options{Path: path, MaxBytes: 180, MaxAge: time.Hour}
	secret := "ghp_abcdefghijklmnopqrstuvwxyz012345"
	rec := Record{
		Raw:     "mysql -p" + "hunter2" + " PGPASSWORD=abc " + secret,
		Argv:    []string{"mysql", "-p", "hunter2", secret},
		Verdict: "pass",
		Trust:   "admin",
		Cwd:     "/tmp",
		Layer:   "engine",
	}
	if err := Write(rec, opt); err != nil {
		t.Fatal(err)
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(buf)
	if strings.Contains(text, secret) || strings.Contains(text, "hunter2") || strings.Contains(text, "PASSWORD=abc") {
		t.Fatal("secret in silent log")
	}
	if !strings.Contains(text, `"schema":1`) || !strings.Contains(text, `"verdict":"pass"`) {
		t.Fatal("record incomplete")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o007 != 0 || st.Mode().Perm() != 0o640 {
		t.Fatalf("log mode %o", st.Mode().Perm())
	}
	dst, err := os.Stat(dir)
	if err != nil || dst.Mode().Perm()&0o007 != 0 {
		t.Fatalf("dir mode %v", dst.Mode().Perm())
	}
	// Size cap rotates on the next write.
	rec.Raw = strings.Repeat("echo ok ", 40)
	rec.Argv = []string{"echo", "ok"}
	if err := Write(rec, opt); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	rotated := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "silent.jsonl.") && !strings.HasSuffix(e.Name(), ".lock") {
			rotated++
		}
	}
	if rotated == 0 {
		t.Fatal("size rotation did not move the file")
	}
	old := path + ".old"
	if err := os.WriteFile(old, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	// The rotated name must match the active file's prefix.
	aged := path + ".20000101T000000.000000000Z"
	if err := os.Rename(old, aged); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(aged, past, past); err != nil {
		t.Fatal(err)
	}
	if err := Write(Record{Raw: "echo next", Argv: []string{"echo", "next"}, Verdict: "catch", Rule: "bulk", Trust: "untrusted", Cwd: "/tmp", Layer: "engine"}, opt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(aged); !os.IsNotExist(err) {
		t.Fatal("aged rotation was kept")
	}
	recs, err := Read(path, time.Time{})
	if err != nil || len(recs) < 2 {
		t.Fatalf("read %d %v", len(recs), err)
	}
	rep := Summarize(recs)
	if rep.Verdict["pass"] == 0 || rep.Verdict["catch"] == 0 {
		t.Fatalf("verdicts %+v", rep.Verdict)
	}
	if rep.Trust["admin"] == 0 || rep.Trust["untrusted"] == 0 {
		t.Fatalf("trust %+v", rep.Trust)
	}
	if rep.Held < 1 || len(rep.Top) == 0 {
		t.Fatalf("held %d top %d", rep.Held, len(rep.Top))
	}
	text = Format(rep)
	if !strings.Contains(text, "p50_ms") || !strings.Contains(text, "p99_ms") || !strings.Contains(text, "verdict pass") {
		t.Fatal(text)
	}
	exp := filepath.Join(dir, "held.jsonl")
	if err := ExportHeld(exp, recs); err != nil {
		t.Fatal(err)
	}
	held, err := os.ReadFile(exp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(held), `"verdict":"pass"`) || !strings.Contains(string(held), `"verdict":"catch"`) {
		t.Fatal("export mixed passes into the hold file")
	}
	if st, err := os.Stat(exp); err != nil || st.Mode().Perm()&0o007 != 0 {
		t.Fatal("export is world-readable")
	}
}

func TestPercentile(t *testing.T) {
	if percentile([]int64{1, 2, 3, 4, 100}, 50) != 3 && percentile([]int64{1, 2, 3, 4, 100}, 50) != 2 {
		t.Fatal(percentile([]int64{1, 2, 3, 4, 100}, 50))
	}
	if percentile([]int64{1, 2, 3, 4, 100}, 99) != 100 {
		t.Fatal(percentile([]int64{1, 2, 3, 4, 100}, 99))
	}
}
