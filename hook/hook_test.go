// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package hook_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/gtwy/spotter-sh/hook"
)

func TestServeDecision(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "decide.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	asked := 0
	h := hook.HandlerFunc(func(ctx context.Context, c hook.Catch) (hook.Decision, error) {
		asked++
		if asked == 1 {
			return hook.Decision{Action: "ask_human"}, nil
		}
		if c.Level == "hardblock" {
			return hook.Decision{Action: "proceed"}, nil
		}
		return hook.Decision{Action: "cancel", Reason: "no"}, nil
	})
	go hook.Serve(ctx, sock, h)
	time.Sleep(30 * time.Millisecond)
	client := hook.Client{Path: sock}
	d, err := client.RoundTrip(context.Background(), hook.Catch{CatchID: "1", Level: "danger", SchemaVersion: hook.SchemaVersion})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != "cancel" {
		t.Fatalf("%s", d.Action)
	}
	d, err = client.RoundTrip(context.Background(), hook.Catch{CatchID: "2", Level: "hardblock"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != "cancel" {
		t.Fatalf("hardblock proceed became %s", d.Action)
	}
}

func TestAdapterDoesNotRewrite(t *testing.T) {
	cmd := "echo hello"
	res := hook.Adapt("generic", cmd)
	if res.Decision != "allow" || res.Exit != 0 {
		t.Fatalf("%+v", res)
	}
	bad := hook.Adapt("claude", "rm -rf /")
	if bad.Decision != "deny" || bad.Exit != 2 {
		t.Fatalf("%+v", bad)
	}
}
