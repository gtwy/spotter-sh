// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package hook

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// Serve listens on socketPath and answers each catch on its own connection.
// The peer's uid must match this process. A handler error becomes cancel.
func Serve(ctx context.Context, socketPath string, h DecisionHandler, opts ...Option) error {
	if h == nil {
		return errors.New("nil handler")
	}
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return err
	}
	_ = os.Chmod(filepath.Dir(socketPath), 0o700)
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	_ = os.Chmod(socketPath, 0o600)
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go serveConn(ctx, conn, h, o)
	}
}

func serveConn(ctx context.Context, conn net.Conn, h DecisionHandler, o options) {
	defer conn.Close()
	pid, peer := 0, false
	if uc, ok := conn.(*net.UnixConn); ok {
		var okPeer bool
		pid, okPeer = peerCred(uc)
		if !okPeer {
			writeDecision(conn, Decision{Action: "cancel", Reason: "peer"})
			return
		}
		peer = true
	}
	r := bufio.NewReader(conn)
	line, err := r.ReadBytes('\n')
	if err != nil {
		return
	}
	var c Catch
	if json.Unmarshal(line, &c) != nil {
		writeDecision(conn, Decision{Action: "cancel", Reason: "bad record"})
		return
	}
	if c.Op == "seal" || c.Op == "covered" {
		allow := false
		if peer {
			if th, ok := h.(TreeHandler); ok {
				if c.Op == "seal" {
					allow = th.OnSeal(pid)
				} else {
					allow = th.OnCovered(pid)
				}
			}
		}
		if allow {
			writeDecision(conn, Decision{Action: "proceed"})
			return
		}
		writeDecision(conn, Decision{Action: "cancel", Reason: "cover"})
		return
	}
	for {
		callCtx := ctx
		var cancel context.CancelFunc
		if o.Timeout > 0 {
			callCtx, cancel = context.WithTimeout(ctx, o.Timeout)
		}
		d, err := h.OnCatch(callCtx, c)
		if cancel != nil {
			cancel()
		}
		if err != nil || d.Action == "" {
			writeDecision(conn, Decision{CatchID: c.CatchID, Action: "cancel", Reason: "handler"})
			return
		}
		if d.CatchID == "" {
			d.CatchID = c.CatchID
		}
		if c.Level == "hardblock" && !c.Approve && d.Action == "proceed" {
			d.Action = "cancel"
			d.Reason = "hard block"
		}
		if c.Restricted && d.Action == "proceed" {
			d.Action = "cancel"
			d.Reason = "restricted"
		}
		writeDecision(conn, d)
		if d.Action != "ask_human" {
			return
		}
	}
}

func writeDecision(conn net.Conn, d Decision) {
	buf, _ := json.Marshal(d)
	_, _ = conn.Write(append(buf, '\n'))
}

func peerCred(uc *net.UnixConn) (pid int, ok bool) {
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	_ = raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			return
		}
		if int(cred.Uid) != os.Geteuid() || cred.Pid <= 0 {
			return
		}
		pid = int(cred.Pid)
		ok = true
	})
	return pid, ok
}

// Client talks to a Serve socket.
type Client struct {
	Path string
}

// RoundTrip sends a catch and reads until the decision is proceed or cancel.
func (c Client) RoundTrip(ctx context.Context, catch Catch) (Decision, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return Decision{}, err
	}
	defer conn.Close()
	buf, _ := json.Marshal(catch)
	if _, err := conn.Write(append(buf, '\n')); err != nil {
		return Decision{}, err
	}
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return Decision{Action: "cancel"}, err
		}
		var dec Decision
		if json.Unmarshal(line, &dec) != nil {
			return Decision{Action: "cancel"}, errors.New("bad decision")
		}
		if dec.Action != "ask_human" {
			return dec, nil
		}
	}
}
