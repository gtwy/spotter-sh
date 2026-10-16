// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package codes is the bound one-time approval fallback.
package codes

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// ErrReject is a code that does not approve this command.
var ErrReject = errors.New("code rejected")

// Binding is what a code is tied to.
type Binding struct {
	Argv    []string
	Cwd     string
	Targets []string
	Level   string
	Extra   string // hostname for power commands
}

// Store is the per-install key, pending codes, and spent nonces.
type Store struct {
	Dir string
}

var storeMu sync.Mutex

func (s Store) keyPath() string  { return filepath.Join(s.Dir, "key") }
func (s Store) pendPath() string { return filepath.Join(s.Dir, "pending.json") }
func (s Store) spentPath() string {
	return filepath.Join(s.Dir, "spent")
}

// EnsureKey creates a key if asked. The shim does not call this.
func EnsureKey(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	p := filepath.Join(dir, "key")
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	return os.WriteFile(p, buf, 0o600)
}

// KeyReadable reports whether the HMAC key can be read.
func (s Store) KeyReadable() error {
	b, err := os.ReadFile(s.keyPath())
	if err != nil {
		return err
	}
	if len(b) < 16 {
		return errors.New("key too short")
	}
	return nil
}

type pending struct {
	Code    string    `json:"code"`
	Mac     string    `json:"mac"`
	Nonce   string    `json:"nonce"`
	Expiry  time.Time `json:"expiry"`
	Level   string    `json:"level"`
	Binding string    `json:"binding"`
}

// Issue returns a new SS- code for this binding.
func (s Store) Issue(b Binding, ttl time.Duration, prefix string) (string, error) {
	key, err := os.ReadFile(s.keyPath())
	if err != nil {
		return "", err
	}
	if prefix == "" {
		prefix = "SS-"
	}
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sum := mac(key, b, hex.EncodeToString(nonce))
	code := prefix + encode(sum)
	row := pending{
		Code: code, Mac: hex.EncodeToString(sum), Nonce: hex.EncodeToString(nonce),
		Expiry: time.Now().Add(ttl), Level: b.Level, Binding: bindHash(b),
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	rows, _ := s.load()
	rows = append(rows, row)
	return code, s.save(rows)
}

// Verify checks the code against the live binding and spends it.
func (s Store) Verify(code string, b Binding) error {
	key, err := os.ReadFile(s.keyPath())
	if err != nil {
		return err
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	rows, err := s.load()
	if err != nil {
		return ErrReject
	}
	now := time.Now()
	var keep []pending
	var found *pending
	for i := range rows {
		if rows[i].Expiry.Before(now.Add(-time.Minute)) {
			continue
		}
		if rows[i].Code == code && found == nil {
			cp := rows[i]
			found = &cp
			continue
		}
		keep = append(keep, rows[i])
	}
	if found == nil {
		return ErrReject
	}
	if now.After(found.Expiry) {
		_ = s.save(keep)
		return ErrReject
	}
	if spent(s.spentPath(), found.Nonce) {
		_ = s.save(append(keep, *found))
		return ErrReject
	}
	if found.Binding != bindHash(b) || found.Level != b.Level {
		_ = s.save(append(keep, *found))
		return ErrReject
	}
	nonce, err := hex.DecodeString(found.Nonce)
	if err != nil {
		return ErrReject
	}
	sum := mac(key, b, hex.EncodeToString(nonce))
	if !hmac.Equal(sum, mustHex(found.Mac)) {
		_ = s.save(append(keep, *found))
		return ErrReject
	}
	if err := s.save(keep); err != nil {
		return err
	}
	return appendSpent(s.spentPath(), found.Nonce)
}

func mac(key []byte, b Binding, nonce string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(bindHash(b)))
	h.Write([]byte{0})
	h.Write([]byte(nonce))
	return h.Sum(nil)
}

func bindHash(b Binding) string {
	h := sha256.New()
	for _, a := range b.Argv {
		h.Write([]byte(a))
		h.Write([]byte{0})
	}
	h.Write([]byte{1})
	h.Write([]byte(b.Cwd))
	h.Write([]byte{1})
	h.Write([]byte(b.Level))
	h.Write([]byte{1})
	for _, t := range b.Targets {
		h.Write([]byte(t))
		h.Write([]byte{0})
	}
	h.Write([]byte(b.Extra))
	return hex.EncodeToString(h.Sum(nil))
}

func encode(sum []byte) string {
	// 6 chars from the digest.
	var b strings.Builder
	for i := 0; i < 6 && i < len(sum); i++ {
		b.WriteByte(alphabet[int(sum[i])%len(alphabet)])
	}
	return b.String()
}

func (s Store) load() ([]pending, error) {
	buf, err := os.ReadFile(s.pendPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(buf) == 0 {
		return nil, nil
	}
	var rows []pending
	if err := json.Unmarshal(buf, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (s Store) save(rows []pending) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	buf, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	return os.WriteFile(s.pendPath(), buf, 0o600)
}

func spent(path, nonce string) bool {
	buf, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(buf), "\n") {
		if strings.TrimSpace(line) == nonce {
			return true
		}
	}
	return false
}

func appendSpent(path, nonce string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(nonce + "\n")
	return err
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// ValidFormat reports an SS- code shape.
func ValidFormat(code, prefix string) bool {
	if prefix == "" {
		prefix = "SS-"
	}
	if !strings.HasPrefix(code, prefix) {
		return false
	}
	rest := strings.TrimPrefix(code, prefix)
	if len(rest) < 4 || len(rest) > 8 {
		return false
	}
	for _, c := range rest {
		if !strings.ContainsRune(alphabet, c) {
			return false
		}
	}
	return true
}
