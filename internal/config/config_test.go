// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLowerLayerTightensOnly(t *testing.T) {
	dir := t.TempDir()
	sys := filepath.Join(dir, "system.toml")
	user := filepath.Join(dir, "user.toml")
	os.WriteFile(sys, []byte("fail = \"closed\"\n[thresholds]\nbulk_targets = 100\n"), 0o644)
	os.WriteFile(user, []byte("fail = \"open\"\n[thresholds]\nbulk_targets = 10\n[paths]\nprotect_extra = [\"/data/**\"]\n"), 0o644)
	cfg, err := Load(Locations{System: sys, User: user})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Fail != "closed" {
		t.Fatalf("fail %s", cfg.Fail)
	}
	if cfg.Thresholds.BulkTargets != 10 {
		t.Fatalf("bulk %d", cfg.Thresholds.BulkTargets)
	}
	if len(cfg.Paths.ProtectExtra) != 1 {
		t.Fatalf("extra %#v", cfg.Paths.ProtectExtra)
	}
	if cfg.Honored["fail"] {
		t.Fatal("user fail was honored")
	}
}

func TestModeStaysOnTheRootFile(t *testing.T) {
	dir := t.TempDir()
	sys := filepath.Join(dir, "system.toml")
	user := filepath.Join(dir, "user.toml")
	project := filepath.Join(dir, "project.toml")
	if err := os.WriteFile(sys, []byte("mode = \"enforce\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(user, []byte("mode = \"silent\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(project, []byte("mode = \"silent\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(Locations{System: sys, User: user, Project: project})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "enforce" {
		t.Fatalf("mode %s", cfg.Mode)
	}
	if cfg.Honored["mode"] {
		t.Fatal("a lower layer was allowed to change mode")
	}
	bare, err := Load(Locations{})
	if err != nil {
		t.Fatal(err)
	}
	if bare.Mode != "silent" {
		t.Fatalf("default %s", bare.Mode)
	}
}

func TestBadTOML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.toml")
	os.WriteFile(p, []byte("this is not toml"), 0o644)
	_, err := Load(Locations{System: p})
	if err == nil {
		t.Fatal("want error")
	}
}
