// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package codes

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ResolveDir is the install state directory. home and system are ignored:
// a caller-supplied directory, environment value, or argv must not choose
// where the key lives. Install stamps the path beside the binary.
func ResolveDir(home string, system bool) string {
	_, _ = home, system
	return FixedDir()
}

// ArmCover writes a short-lived HMAC file. The shim and the host do not
// authorize commands from it. A caller who can read the key can mint one,
// so a file cover is not an approval. The live cover is the host's record
// of the approved process tree.
func ArmCover(dir string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if err := EnsureKey(dir); err != nil {
		return "", err
	}
	key, err := os.ReadFile(filepath.Join(dir, "key"))
	if err != nil {
		return "", err
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	id := hex.EncodeToString(buf)
	exp := strconv.FormatInt(time.Now().Add(ttl).Unix(), 10)
	body := id + "\n" + exp + "\n" + coverMAC(key, id, exp) + "\n"
	path, err := coverPath(dir, id)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", err
	}
	return id, nil
}

// CoverArmed reports whether id is a live cover in dir. A missing file, a
// bad mac, or an expired id is not armed. The path is not allowed to leave dir.
func CoverArmed(dir, id string) bool {
	path, err := coverPath(dir, id)
	if err != nil {
		return false
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	lines := strings.Split(string(buf), "\n")
	if len(lines) < 3 || lines[0] != id {
		return false
	}
	expUnix, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || time.Now().Unix() > expUnix {
		return false
	}
	key, err := os.ReadFile(filepath.Join(dir, "key"))
	if err != nil || len(key) < 16 {
		return false
	}
	mac, err := hex.DecodeString(strings.TrimSpace(lines[2]))
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(coverMAC(key, id, lines[1]))
	if err != nil {
		return false
	}
	return hmac.Equal(mac, want)
}

// DisarmCover removes one cover. A bad id is ignored.
func DisarmCover(dir, id string) {
	path, err := coverPath(dir, id)
	if err != nil {
		return
	}
	_ = os.Remove(path)
}

func coverPath(dir, id string) (string, error) {
	if id == "" || id != filepath.Base(id) || strings.Contains(id, "..") || strings.ContainsAny(id, `/\`) {
		return "", os.ErrInvalid
	}
	return filepath.Join(dir, "cover", id), nil
}

func coverMAC(key []byte, id, exp string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(id))
	h.Write([]byte{0})
	h.Write([]byte(exp))
	return hex.EncodeToString(h.Sum(nil))
}
