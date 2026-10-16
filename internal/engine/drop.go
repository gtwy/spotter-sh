// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package engine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/gtwy/spotter-sh/internal/codes"
	"github.com/gtwy/spotter-sh/internal/envx"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// errDrop means a setgid spotter could not arrange for the child to shed
// the key group. The child must not start.
var errDrop = errors.New("drop group")

// DropEnv carries the setgid child's proof. It is not an argv flag: a
// user-reachable argument must not select this mode. The parent sets it,
// the child checks it once, and both sides clear it before the real program.
const DropEnv = "SPOTTER_SH_DROP"

// PrepareChild makes cmd start without the setgid key group.
// syscall.Setresgid applies to every thread in the process, so the parent
// must not call it: a later catch still has to read the HMAC key.
// The child re-execs this binary with the real argv, checks an HMAC of
// that argv, drops only its own group, then execs the real program.
// A normal user process is unchanged. A token the user typed is ignored.
func PrepareChild(cmd *exec.Cmd) error {
	if cmd == nil {
		return errDrop
	}
	if syscall.Getegid() == syscall.Getgid() {
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		return errDrop
	}
	real := cmd.Path
	if real == "" {
		return errDrop
	}
	argv := append([]string{}, cmd.Args...)
	if len(argv) == 0 {
		argv = []string{real}
	}
	key, err := readDropKey()
	if err != nil {
		return errDrop
	}
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	filtered := envx.Strip(env, "DROP")
	filtered = append(filtered, DropEnv+"="+signDrop(key, real, argv))
	cmd.Env = filtered
	cmd.Path = self
	cmd.Args = argv
	return nil
}

// TakeDrop reads and clears DropEnv. A valid token yields the real program
// path for this argv. Anything else, including a value the user set, is not
// a mode switch: the caller continues as a normal shim.
func TakeDrop(argv []string) (string, bool) {
	tok, present := envx.Lookup("DROP")
	_ = envx.Unset("DROP")
	if !present || tok == "" {
		return "", false
	}
	return verifyDrop(tok, argv)
}

func signDrop(key []byte, real string, argv []string) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte("drop"))
	_, _ = m.Write([]byte{0})
	_, _ = m.Write([]byte(real))
	for _, a := range argv {
		_, _ = m.Write([]byte{0})
		_, _ = m.Write([]byte(a))
	}
	sum := m.Sum(nil)
	return hex.EncodeToString(sum) + "." + hex.EncodeToString([]byte(real))
}

func verifyDrop(token string, argv []string) (string, bool) {
	macHex, realHex, ok := strings.Cut(token, ".")
	if !ok || macHex == "" || realHex == "" {
		return "", false
	}
	got, err := hex.DecodeString(macHex)
	if err != nil || len(got) != sha256.Size {
		return "", false
	}
	raw, err := hex.DecodeString(realHex)
	if err != nil || len(raw) == 0 {
		return "", false
	}
	real := string(raw)
	key, err := readDropKey()
	if err != nil {
		return "", false
	}
	wantHex, _, _ := strings.Cut(signDrop(key, real, argv), ".")
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		return "", false
	}
	if !hmac.Equal(got, want) {
		return "", false
	}
	return real, true
}

func readDropKey() ([]byte, error) {
	var last error = errDrop
	for _, dir := range dropKeyDirs() {
		b, err := os.ReadFile(filepath.Join(dir, "key"))
		if err != nil {
			last = err
			continue
		}
		if len(b) < 16 {
			last = errDrop
			continue
		}
		return b, nil
	}
	return nil, last
}

func dropKeyDirs() []string {
	// The same fixed directory as the shim. An environment value is not a key path.
	return []string{codes.FixedDir()}
}

// DropThread clears the setgid group on the calling thread only.
// The caller locks the OS thread first. It does not use syscall.Setresgid,
// because that helper signals every thread.
func DropThread() error {
	rgid := syscall.Getgid()
	if syscall.Getegid() == rgid {
		return nil
	}
	_, _, e := syscall.RawSyscall(syscall.SYS_SETRESGID, uintptr(rgid), uintptr(rgid), uintptr(rgid))
	if e != 0 {
		return errDrop
	}
	// Best effort. A setgid binary often cannot clear supplementary groups.
	_, _, _ = syscall.RawSyscall(syscall.SYS_SETGROUPS, 0, 0, 0)
	if syscall.Getegid() != rgid {
		return errDrop
	}
	return nil
}
