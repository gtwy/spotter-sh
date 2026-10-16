// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package config loads layered spotter-sh settings.
// Lower layers may only add protected paths and tighten thresholds.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config is the merged spotter configuration.
type Config struct {
	Mode         string
	Fail         string
	FailTimeout  time.Duration
	ProbeTimeout time.Duration
	WalkTimeout  time.Duration
	Thresholds   Thresholds
	Approval     Approval
	ForceRate    ForceRate
	Paths        Paths
	Commands     Commands
	DB           DB
	Limits       Limits
	RedactExtra  []string
	Log          Log
	HookCommand  string
	Sources      map[string]string
	Honored      map[string]bool
}

// Thresholds are the pause ceilings. Lower is stricter.
type Thresholds struct {
	BulkTargets        int
	TreeFiles          int
	TreeBytes          int64
	RecursivePermFiles int
	OverwriteFiles     int
}

// Approval selects hook, code, or auto.
type Approval struct {
	Mode            string
	CodeTTL         time.Duration
	CodePrefix      string
	DecisionTimeout time.Duration
}

// ForceRate is the danger-approval tripwire. It warns and does not block.
type ForceRate struct {
	Enabled bool
	Max     int
	Window  time.Duration
}

// Paths are protected and allowed path rules.
type Paths struct {
	ProtectExtra []string
	AllowExtra   []string
	MarkerFile   string
}

// Commands selects packs and exemptions.
type Commands struct {
	Disable     []string
	Packs       []string
	BuildOutput []string
}

// DB is the database gate.
type DB struct {
	InjectSafe   bool
	DryRunCounts bool
	SQLScanKB    int
}

// Limits is the opt-in cgroup backstop. Default off.
type Limits struct {
	Enabled   bool
	TasksMax  int
	MemoryMax string
}

// Log is the JSON-lines log.
type Log struct {
	Path         string
	Level        string
	MaxMB        int
	RedactHome   bool
	SilentPath   string
	SilentMaxMB  int
	SilentMaxAge time.Duration
}

// Defaults returns the built-in configuration.
func Defaults() Config {
	return Config{
		Mode:         "silent",
		Fail:         "closed",
		FailTimeout:  2 * time.Second,
		ProbeTimeout: 1500 * time.Millisecond,
		WalkTimeout:  1500 * time.Millisecond,
		Thresholds: Thresholds{
			BulkTargets:        100,
			TreeFiles:          2000,
			TreeBytes:          1 << 30,
			RecursivePermFiles: 500,
			OverwriteFiles:     100,
		},
		Approval: Approval{
			Mode:            "auto",
			CodeTTL:         120 * time.Second,
			CodePrefix:      "SS-",
			DecisionTimeout: 300 * time.Second,
		},
		ForceRate: ForceRate{Enabled: true, Max: 5, Window: 10 * time.Minute},
		Paths: Paths{
			MarkerFile: ".spotter-sh-protect",
		},
		Commands: Commands{
			Packs:       []string{"files", "git", "db", "infra", "power"},
			BuildOutput: []string{"node_modules", "dist", "build", "target", ".next", ".cache", "__pycache__", "vendor"},
		},
		DB: DB{InjectSafe: true, DryRunCounts: true, SQLScanKB: 256},
		Log: Log{
			Path:         "~/.local/state/spotter-sh/spotter.log",
			Level:        "catch",
			MaxMB:        50,
			SilentPath:   "~/.local/state/spotter-sh/silent.jsonl",
			SilentMaxMB:  32,
			SilentMaxAge: 14 * 24 * time.Hour,
		},
		Sources: map[string]string{},
		Honored: map[string]bool{},
	}
}

// Locations are the files Load reads.
type Locations struct {
	System  string
	User    string
	Project string
	Home    string
}

// DefaultLocations uses the spec paths. Project is discovered from cwd.
func DefaultLocations(cwd string) Locations {
	home, _ := os.UserHomeDir()
	return Locations{
		System:  "/etc/spotter-sh/config.toml",
		User:    filepath.Join(home, ".config", "spotter-sh", "config.toml"),
		Project: FindProjectFile(cwd),
		Home:    home,
	}
}

// FindProjectFile returns the nearest .spotter-sh.toml inside a project root.
func FindProjectFile(cwd string) string {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	dir := cwd
	for {
		cand := filepath.Join(dir, ".spotter-sh.toml")
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// Load merges defaults, the root-owned file, then tightening lower layers.
// A missing file is not an error. Invalid TOML is an error (fail closed).
func Load(loc Locations) (Config, error) {
	cfg := Defaults()
	note := func(key, src string, honored bool) {
		cfg.Sources[key] = src
		cfg.Honored[key] = honored
	}
	for _, k := range []string{"mode", "fail", "thresholds", "approval", "paths", "commands", "db", "log"} {
		note(k, "default", true)
	}
	if loc.System != "" {
		raw, err := readFile(loc.System)
		if err != nil {
			return Config{}, err
		}
		if raw != nil {
			if err := applySystem(&cfg, raw); err != nil {
				return Config{}, fmt.Errorf("%s: %w", loc.System, err)
			}
			for _, k := range []string{"mode", "fail", "thresholds", "approval", "paths", "commands", "db", "limits", "log", "hook_command", "force_rate", "redact"} {
				if raw.has(k) {
					note(k, loc.System, true)
				}
			}
		}
	}
	for _, layer := range []string{loc.User, loc.Project} {
		if layer == "" {
			continue
		}
		raw, err := readFile(layer)
		if err != nil {
			return Config{}, err
		}
		if raw == nil {
			continue
		}
		if err := applyLower(&cfg, raw, layer); err != nil {
			return Config{}, fmt.Errorf("%s: %w", layer, err)
		}
	}
	cfg.Log.Path = expandHome(cfg.Log.Path, loc.Home)
	cfg.Log.SilentPath = expandHome(cfg.Log.SilentPath, loc.Home)
	return cfg, nil
}

func expandHome(p, home string) string {
	if strings.HasPrefix(p, "~/") && home != "" {
		return filepath.Join(home, p[2:])
	}
	return p
}

type rawDoc struct {
	keys map[string]rawVal
}

func (d rawDoc) has(k string) bool {
	if d.keys == nil {
		return false
	}
	_, ok := d.keys[k]
	return ok
}

type rawVal struct {
	kind string // string, int, bool, list, table
	s    string
	n    int64
	b    bool
	list []string
	tab  map[string]rawVal
}

func readFile(path string) (*rawDoc, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	doc, err := parseTOML(string(b))
	if err != nil {
		return nil, err
	}
	return doc, nil
}

func applySystem(cfg *Config, doc *rawDoc) error {
	if v, ok := doc.lookup("mode"); ok {
		cfg.Mode = v.s
	}
	if v, ok := doc.lookup("fail"); ok {
		if v.s != "closed" && v.s != "open" {
			return fmt.Errorf("fail must be closed or open")
		}
		cfg.Fail = v.s
	}
	if v, ok := doc.lookup("fail_timeout_ms"); ok {
		cfg.FailTimeout = time.Duration(v.n) * time.Millisecond
	}
	if v, ok := doc.lookup("probe_timeout_ms"); ok {
		cfg.ProbeTimeout = time.Duration(v.n) * time.Millisecond
	}
	if v, ok := doc.lookup("walk_timeout_ms"); ok {
		cfg.WalkTimeout = time.Duration(v.n) * time.Millisecond
	}
	if v, ok := doc.lookup("hook_command"); ok {
		cfg.HookCommand = v.s
	}
	applyThresholds(&cfg.Thresholds, doc, false)
	if v, ok := doc.lookup("approval.mode"); ok {
		cfg.Approval.Mode = v.s
	}
	if v, ok := doc.lookup("approval.code_ttl_sec"); ok {
		cfg.Approval.CodeTTL = time.Duration(v.n) * time.Second
	}
	if v, ok := doc.lookup("approval.code_prefix"); ok {
		cfg.Approval.CodePrefix = v.s
	}
	if v, ok := doc.lookup("approval.decision_timeout_sec"); ok {
		cfg.Approval.DecisionTimeout = time.Duration(v.n) * time.Second
	}
	if v, ok := doc.lookup("force_rate.enabled"); ok {
		cfg.ForceRate.Enabled = v.b
	}
	if v, ok := doc.lookup("force_rate.max"); ok {
		cfg.ForceRate.Max = int(v.n)
	}
	if v, ok := doc.lookup("force_rate.window_min"); ok {
		cfg.ForceRate.Window = time.Duration(v.n) * time.Minute
	}
	if v, ok := doc.lookup("paths.protect_extra"); ok {
		cfg.Paths.ProtectExtra = append([]string{}, v.list...)
	}
	if v, ok := doc.lookup("paths.allow_extra"); ok {
		cfg.Paths.AllowExtra = append([]string{}, v.list...)
	}
	if v, ok := doc.lookup("paths.marker_file"); ok {
		cfg.Paths.MarkerFile = v.s
	}
	if v, ok := doc.lookup("commands.disable"); ok {
		cfg.Commands.Disable = append([]string{}, v.list...)
	}
	if v, ok := doc.lookup("commands.packs"); ok {
		cfg.Commands.Packs = append([]string{}, v.list...)
	}
	if v, ok := doc.lookup("commands.build_output.names"); ok {
		cfg.Commands.BuildOutput = append([]string{}, v.list...)
	}
	if v, ok := doc.lookup("db.inject_safe_mode_interactive"); ok {
		cfg.DB.InjectSafe = v.b
	}
	if v, ok := doc.lookup("db.dry_run_counts"); ok {
		cfg.DB.DryRunCounts = v.b
	}
	if v, ok := doc.lookup("db.sql_scan_kb"); ok {
		cfg.DB.SQLScanKB = int(v.n)
	}
	if v, ok := doc.lookup("limits.enabled"); ok {
		cfg.Limits.Enabled = v.b
	}
	if v, ok := doc.lookup("limits.tasks_max"); ok {
		cfg.Limits.TasksMax = int(v.n)
	}
	if v, ok := doc.lookup("limits.memory_max"); ok {
		cfg.Limits.MemoryMax = v.s
	}
	if v, ok := doc.lookup("redact.extra_patterns"); ok {
		cfg.RedactExtra = append([]string{}, v.list...)
	}
	if v, ok := doc.lookup("log.path"); ok {
		cfg.Log.Path = v.s
	}
	if v, ok := doc.lookup("log.level"); ok {
		cfg.Log.Level = v.s
	}
	if v, ok := doc.lookup("log.log_max_mb"); ok {
		cfg.Log.MaxMB = int(v.n)
	}
	if v, ok := doc.lookup("log.redact_home"); ok {
		cfg.Log.RedactHome = v.b
	}
	if v, ok := doc.lookup("log.silent_path"); ok {
		cfg.Log.SilentPath = v.s
	}
	if v, ok := doc.lookup("log.silent_max_mb"); ok && v.n > 0 {
		cfg.Log.SilentMaxMB = int(v.n)
	}
	if v, ok := doc.lookup("log.silent_max_age_hours"); ok && v.n > 0 {
		cfg.Log.SilentMaxAge = time.Duration(v.n) * time.Hour
	}
	return nil
}

func applyLower(cfg *Config, doc *rawDoc, src string) error {
	// Only protect_extra (add) and lowered thresholds are honored.
	if v, ok := doc.lookup("paths.protect_extra"); ok {
		cfg.Paths.ProtectExtra = append(cfg.Paths.ProtectExtra, v.list...)
		cfg.Sources["paths.protect_extra"] = src
		cfg.Honored["paths.protect_extra"] = true
	}
	before := cfg.Thresholds
	applyThresholds(&cfg.Thresholds, doc, true)
	if cfg.Thresholds != before {
		cfg.Sources["thresholds"] = src
		cfg.Honored["thresholds"] = true
	}
	for _, k := range []string{"fail", "mode", "commands.disable", "commands.packs", "commands.build_output.names", "approval.mode", "force_rate.enabled", "paths.allow_extra", "log.level", "log.silent_path", "log.silent_max_mb", "log.silent_max_age_hours", "hook_command"} {
		if _, ok := doc.lookup(k); ok {
			cfg.Sources[k] = src
			cfg.Honored[k] = false
		}
	}
	return nil
}

func applyThresholds(th *Thresholds, doc *rawDoc, lowerOnly bool) {
	setInt := func(key string, dst *int) {
		v, ok := doc.lookup(key)
		if !ok {
			return
		}
		n := int(v.n)
		if lowerOnly && n >= *dst {
			return
		}
		*dst = n
	}
	setInt("thresholds.bulk_targets", &th.BulkTargets)
	setInt("thresholds.tree_files", &th.TreeFiles)
	setInt("thresholds.recursive_perm_files", &th.RecursivePermFiles)
	setInt("thresholds.overwrite_files", &th.OverwriteFiles)
	if v, ok := doc.lookup("thresholds.tree_bytes"); ok {
		n, err := ParseBytes(v.s)
		if err == nil && (!lowerOnly || n < th.TreeBytes) {
			th.TreeBytes = n
		}
	}
}

func (d *rawDoc) lookup(path string) (rawVal, bool) {
	if d == nil {
		return rawVal{}, false
	}
	cur := d.keys
	parts := strings.Split(path, ".")
	for i, p := range parts {
		v, ok := cur[p]
		if !ok {
			return rawVal{}, false
		}
		if i == len(parts)-1 {
			return v, true
		}
		if v.kind != "table" {
			return rawVal{}, false
		}
		cur = v.tab
	}
	return rawVal{}, false
}

// ParseBytes parses 1GB, 1MB, 1KB, or a plain integer.
func ParseBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"`)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	up := strings.ToUpper(s)
	switch {
	case strings.HasSuffix(up, "GB"):
		mult = 1 << 30
		s = s[:len(s)-2]
	case strings.HasSuffix(up, "MB"):
		mult = 1 << 20
		s = s[:len(s)-2]
	case strings.HasSuffix(up, "KB"):
		mult = 1 << 10
		s = s[:len(s)-2]
	case strings.HasSuffix(up, "G"):
		mult = 1 << 30
		s = s[:len(s)-1]
	case strings.HasSuffix(up, "M"):
		mult = 1 << 20
		s = s[:len(s)-1]
	case strings.HasSuffix(up, "K"):
		mult = 1 << 10
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, err
	}
	return n * mult, nil
}

// PackEnabled reports whether a pack is on and the command is not disabled.
func (c Config) PackEnabled(pack, command string) bool {
	for _, d := range c.Commands.Disable {
		if d == command {
			return false
		}
	}
	if pack == "" {
		return true
	}
	for _, p := range c.Commands.Packs {
		if p == pack {
			return true
		}
	}
	return false
}

// Explain returns a human-readable merged config.
func (c Config) Explain() string {
	var b strings.Builder
	fmt.Fprintf(&b, "mode = %s\nfail = %s\n", c.Mode, c.Fail)
	fmt.Fprintf(&b, "log.silent_path = %s\n", c.Log.SilentPath)
	fmt.Fprintf(&b, "log.silent_max_mb = %d\n", c.Log.SilentMaxMB)
	fmt.Fprintf(&b, "log.silent_max_age_hours = %d\n", int(c.Log.SilentMaxAge.Hours()))
	fmt.Fprintf(&b, "fail_timeout_ms = %d\nprobe_timeout_ms = %d\nwalk_timeout_ms = %d\n",
		c.FailTimeout.Milliseconds(), c.ProbeTimeout.Milliseconds(), c.WalkTimeout.Milliseconds())
	fmt.Fprintf(&b, "thresholds.bulk_targets = %d\n", c.Thresholds.BulkTargets)
	fmt.Fprintf(&b, "thresholds.tree_files = %d\n", c.Thresholds.TreeFiles)
	fmt.Fprintf(&b, "thresholds.tree_bytes = %d\n", c.Thresholds.TreeBytes)
	fmt.Fprintf(&b, "thresholds.recursive_perm_files = %d\n", c.Thresholds.RecursivePermFiles)
	fmt.Fprintf(&b, "thresholds.overwrite_files = %d\n", c.Thresholds.OverwriteFiles)
	fmt.Fprintf(&b, "approval.mode = %s\n", c.Approval.Mode)
	fmt.Fprintf(&b, "paths.protect_extra = %s\n", strings.Join(c.Paths.ProtectExtra, ", "))
	fmt.Fprintf(&b, "commands.packs = %s\n", strings.Join(c.Commands.Packs, ", "))
	fmt.Fprintf(&b, "commands.disable = %s\n", strings.Join(c.Commands.Disable, ", "))
	var keys []string
	for k := range c.Sources {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		hon := "honored"
		if !c.Honored[k] {
			hon = "ignored"
		}
		fmt.Fprintf(&b, "source %s = %s (%s)\n", k, c.Sources[k], hon)
	}
	return b.String()
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j] < s[j-1] {
			s[j], s[j-1] = s[j-1], s[j]
			j--
		}
	}
}
