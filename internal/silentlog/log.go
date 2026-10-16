// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package silentlog is the append-only JSON Lines log for silent mode.
// Records are redacted again on write. The file is not world-readable.
package silentlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gtwy/spotter-sh"
	"github.com/gtwy/spotter-sh/internal/redact"
)

// Schema is the record version.
const Schema = 1

// Record is one judged command. Fields are always present so a later
// report can tell a zero from a missing value.
type Record struct {
	Schema    int      `json:"schema"`
	TsUTC     string   `json:"ts_utc"`
	TsLocal   string   `json:"ts_local"`
	SessionID string   `json:"session_id"`
	TurnID    string   `json:"turn_id"`
	Surface   string   `json:"surface"`
	Sender    string   `json:"sender"`
	Trust     string   `json:"trust"`
	Cwd       string   `json:"cwd"`
	Raw       string   `json:"raw"`
	Argv      []string `json:"argv"`
	Layer     string   `json:"layer"`
	Verdict   string   `json:"verdict"`
	Rule      string   `json:"rule"`
	CatchID   string   `json:"catch_id"`
	Reason    string   `json:"reason"`
	Targets   []string `json:"targets"`
	Files     int      `json:"files"`
	Dirs      int      `json:"dirs"`
	Protected []string `json:"protected"`
	Symlink   bool     `json:"symlink"`
	JudgeMS   int64    `json:"judge_ms"`
	Timeout   bool     `json:"timeout"`
	Error     string   `json:"error"`
	ExitCode  *int     `json:"exit_code"`
	Version   string   `json:"version"`
	Commit    string   `json:"commit"`
}

// Options controls the active file.
type Options struct {
	Path     string
	MaxBytes int64
	MaxAge   time.Duration
}

// Prepare fills schema, clocks, and version when the caller left them empty.
func Prepare(rec Record) Record {
	now := time.Now()
	if rec.Schema == 0 {
		rec.Schema = Schema
	}
	if rec.TsUTC == "" {
		rec.TsUTC = now.UTC().Format(time.RFC3339Nano)
	}
	if rec.TsLocal == "" {
		rec.TsLocal = now.Format(time.RFC3339Nano)
	}
	if rec.Trust == "" {
		rec.Trust = "none"
	}
	if rec.Argv == nil {
		rec.Argv = []string{}
	}
	if rec.Targets == nil {
		rec.Targets = []string{}
	}
	if rec.Protected == nil {
		rec.Protected = []string{}
	}
	if rec.Version == "" {
		rec.Version = spottersh.Version
	}
	if rec.Commit == "" {
		rec.Commit = spottersh.Commit()
	}
	return redactRecord(rec)
}

func redactRecord(rec Record) Record {
	red := redact.New(nil)
	vals := red.SecretValues(rec.Argv)
	rec.Raw = red.MaskValues(red.Apply(rec.Raw), vals)
	rec.Reason = red.MaskValues(red.Apply(rec.Reason), vals)
	rec.Cwd = red.MaskValues(red.Apply(rec.Cwd), vals)
	rec.Sender = red.Apply(rec.Sender)
	rec.Surface = red.Apply(rec.Surface)
	rec.Rule = red.Apply(rec.Rule)
	rec.Error = red.MaskValues(red.Apply(rec.Error), vals)
	rec.Argv = maskSlice(red, red.Argv(rec.Argv), vals)
	rec.Targets = maskSlice(red, red.Argv(rec.Targets), vals)
	rec.Protected = maskSlice(red, red.Argv(rec.Protected), vals)
	return rec
}

func maskSlice(red redact.Text, in, vals []string) []string {
	if in == nil {
		return []string{}
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = red.MaskValues(s, vals)
	}
	return out
}

// Write appends one record. A failure is returned to the caller.
// The command path must ignore that error.
func Write(rec Record, opt Options) error {
	if opt.Path == "" {
		return os.ErrInvalid
	}
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = 32 << 20
	}
	if opt.MaxAge <= 0 {
		opt.MaxAge = 14 * 24 * time.Hour
	}
	rec = Prepare(rec)
	buf, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	buf = append(buf, '\n')
	dir := filepath.Dir(opt.Path)
	dirMode, fileMode := modes(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(dir, dirMode)
	lock, err := os.OpenFile(opt.Path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	rotateIfNeeded(opt)
	dropOld(opt)
	f, err := os.OpenFile(opt.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(fileMode); err != nil {
		return err
	}
	_, err = f.Write(buf)
	return err
}

func rotateIfNeeded(opt Options) {
	st, err := os.Stat(opt.Path)
	if err != nil || st.Size() == 0 {
		return
	}
	age := time.Since(st.ModTime())
	if st.Size() < opt.MaxBytes && age < opt.MaxAge {
		return
	}
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	dest := opt.Path + "." + stamp
	if _, err := os.Stat(dest); err == nil {
		dest = opt.Path + "." + stamp + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	_ = os.Rename(opt.Path, dest)
}

func dropOld(opt Options) {
	dir := filepath.Dir(opt.Path)
	base := filepath.Base(opt.Path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if name == base || !strings.HasPrefix(name, base+".") || strings.HasSuffix(name, ".lock") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) > opt.MaxAge {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

// modes matches the key folder when the log lives beside the key.
// Other users cannot read the file or the directory.
func modes(dir string) (os.FileMode, os.FileMode) {
	dirMode := os.FileMode(0o700)
	fileMode := os.FileMode(0o600)
	if st, err := os.Stat(dir); err == nil {
		dirMode = st.Mode() & (os.ModeSetgid | os.ModeSetuid | 0o777)
	}
	if st, err := os.Stat(filepath.Join(dir, "key")); err == nil {
		fileMode = st.Mode().Perm()
	}
	dirMode &^= 0o007
	fileMode &^= 0o007
	if dirMode.Perm()&0o700 == 0 {
		dirMode |= 0o700
	}
	if fileMode&0o600 == 0 {
		fileMode = 0o600
	}
	return dirMode, fileMode
}

// Read loads the active file and rotated siblings.
func Read(path string, since time.Time) ([]Record, error) {
	var files []string
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		files = append(files, path)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		if os.IsNotExist(err) || len(files) > 0 {
			return nil, nil
		}
		return nil, err
	}
	base := filepath.Base(path)
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, base+".") && !strings.HasSuffix(name, ".lock") {
			files = append(files, filepath.Join(filepath.Dir(path), name))
		}
	}
	var out []Record
	for _, f := range files {
		buf, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(buf), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var rec Record
			if json.Unmarshal([]byte(line), &rec) != nil {
				continue
			}
			if !since.IsZero() && rec.TsUTC != "" {
				t, err := time.Parse(time.RFC3339Nano, rec.TsUTC)
				if err != nil {
					t, err = time.Parse(time.RFC3339, rec.TsUTC)
				}
				if err == nil && t.Before(since) {
					continue
				}
			}
			out = append(out, rec)
		}
	}
	return out, nil
}

// Top is one repeated would-be hold.
type Top struct {
	Command string `json:"command"`
	Verdict string `json:"verdict"`
	Rule    string `json:"rule"`
	Count   int    `json:"count"`
}

// Report is the summary a person reads after the rollout.
type Report struct {
	Records int            `json:"records"`
	Verdict map[string]int `json:"verdict"`
	Rule    map[string]int `json:"rule"`
	Trust   map[string]int `json:"trust"`
	Top     []Top          `json:"top"`
	P50     int64          `json:"p50_ms"`
	P99     int64          `json:"p99_ms"`
	Held    int            `json:"held"`
}

// Summarize counts verdicts, rules, trust, and judge latency.
func Summarize(recs []Record) Report {
	rep := Report{
		Records: len(recs),
		Verdict: map[string]int{},
		Rule:    map[string]int{},
		Trust:   map[string]int{},
	}
	type key struct{ cmd, verdict, rule string }
	counts := map[key]int{}
	var lat []int64
	for _, rec := range recs {
		v := rec.Verdict
		if v == "" {
			v = "pass"
		}
		rep.Verdict[v]++
		if rec.Rule != "" {
			rep.Rule[rec.Rule]++
		}
		trust := rec.Trust
		if trust == "" {
			trust = "none"
		}
		rep.Trust[trust]++
		lat = append(lat, rec.JudgeMS)
		if v == "pass" {
			continue
		}
		rep.Held++
		cmd := strings.TrimSpace(rec.Raw)
		if cmd == "" {
			cmd = strings.Join(rec.Argv, " ")
		}
		counts[key{cmd, v, rec.Rule}]++
	}
	for k, n := range counts {
		rep.Top = append(rep.Top, Top{Command: k.cmd, Verdict: k.verdict, Rule: k.rule, Count: n})
	}
	sort.Slice(rep.Top, func(i, j int) bool {
		if rep.Top[i].Count != rep.Top[j].Count {
			return rep.Top[i].Count > rep.Top[j].Count
		}
		return rep.Top[i].Command < rep.Top[j].Command
	})
	if len(rep.Top) > 10 {
		rep.Top = rep.Top[:10]
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	rep.P50 = percentile(lat, 50)
	rep.P99 = percentile(lat, 99)
	return rep
}

func percentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	rank := int(p/100*float64(len(sorted))+0.999999) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

// Format renders a report for the command line.
func Format(rep Report) string {
	var b strings.Builder
	b.WriteString("records ")
	b.WriteString(strconv.Itoa(rep.Records))
	b.WriteByte('\n')
	writeMap(&b, "verdict", rep.Verdict)
	writeMap(&b, "rule", rep.Rule)
	writeMap(&b, "trust", rep.Trust)
	b.WriteString("p50_ms ")
	b.WriteString(strconv.FormatInt(rep.P50, 10))
	b.WriteByte('\n')
	b.WriteString("p99_ms ")
	b.WriteString(strconv.FormatInt(rep.P99, 10))
	b.WriteByte('\n')
	b.WriteString("held ")
	b.WriteString(strconv.Itoa(rep.Held))
	b.WriteByte('\n')
	for _, top := range rep.Top {
		b.WriteString("top ")
		b.WriteString(strconv.Itoa(top.Count))
		b.WriteByte(' ')
		b.WriteString(top.Verdict)
		b.WriteByte(' ')
		b.WriteString(top.Rule)
		b.WriteByte(' ')
		b.WriteString(top.Command)
		b.WriteByte('\n')
	}
	return b.String()
}

func writeMap(b *strings.Builder, name string, m map[string]int) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(name)
		b.WriteByte(' ')
		b.WriteString(k)
		b.WriteByte(' ')
		b.WriteString(strconv.Itoa(m[k]))
		b.WriteByte('\n')
	}
}

// ExportHeld writes catch and hard-block records for review.
func ExportHeld(path string, recs []Record) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, rec := range recs {
		if rec.Verdict != "catch" && rec.Verdict != "hardblock" {
			continue
		}
		buf, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(buf, '\n')); err != nil {
			return err
		}
	}
	return nil
}
