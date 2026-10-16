// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package redact

import "testing"

func TestMasks(t *testing.T) {
	r := New(nil)
	in := "mysql -pS3cret --password=hunter2 postgres://u:pw@h/db PGPASSWORD=abc SS-ABC123"
	out := r.Apply(in)
	if contains(out, "S3cret") || contains(out, "hunter2") || contains(out, "pw@") || contains(out, "PASSWORD=abc") {
		t.Fatal(out)
	}
	if !contains(out, "SS-ABC123") {
		t.Fatal("code stripped", out)
	}
	if contains(r.Apply("find . -print"), "[REDACTED]") {
		t.Fatal("print flag masked")
	}
	joined := r.Apply("redis-cli -a hunter2 FLUSHALL")
	if contains(joined, "hunter2") {
		t.Fatal(joined)
	}
	argv := r.Argv([]string{"redis-cli", "-a", "hunter2", "FLUSHALL"})
	if contains(argv[2], "hunter2") {
		t.Fatal(argv)
	}
	tok := r.Apply("mysql --token ghp_abcdefghijklmnopqrstuvwxyz012345 -e 'select xoxb-1234567890-abcdef'")
	if contains(tok, "ghp_") || contains(tok, "xoxb-") {
		t.Fatal(tok)
	}
	split := r.Argv([]string{"mysql", "--token", "ghp_abcdefghijklmnopqrstuvwxyz012345"})
	if contains(split[2], "ghp_") {
		t.Fatal(split)
	}
	reason := r.Apply("password hunter2")
	if contains(reason, "hunter2") {
		t.Fatal(reason)
	}
	plain := r.Argv([]string{"rm", "-p", "filename"})
	if plain[2] != "filename" {
		t.Fatalf("generic -p masked the next arg: %q", plain)
	}
	port := r.Argv([]string{"psql", "-p", "5432"})
	if port[2] != "5432" {
		t.Fatalf("psql -p masked the port: %q", port)
	}
	mysql := r.Argv([]string{"mysql", "-p", "hunter2"})
	if contains(mysql[2], "hunter2") {
		t.Fatal(mysql)
	}
	secret := "tokenvalueZZ"
	vals := r.SecretValues([]string{"rm", "--token", secret, "secret"})
	report := "command : rm --token " + secret + " secret\ntargets :\n  " + secret + "\n  /tmp/secret\n"
	masked := r.MaskValues(r.Apply(report), vals)
	if contains(masked, secret) {
		t.Fatal(masked)
	}
	if !contains(masked, "/tmp/secret") {
		t.Fatal(masked)
	}
	short := r.SecretValues([]string{"mysql", "--pass", "a", "catalog"})
	line := "mysql --pass a catalog\ntargets :\n  a\n  catalog\n"
	got := r.MaskValues(r.Apply(line), short)
	if contains(got, "\n  a\n") || !contains(got, "catalog") {
		t.Fatal(got)
	}
	path := r.MaskValues("/tmp/work/"+secret+"\n  /tmp/secret\n", []string{secret})
	if contains(path, secret) || !contains(path, "/tmp/secret") {
		t.Fatal(path)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || len(s) > 0 && (index(s, sub) >= 0)))
}

func index(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
