// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package redact masks secrets before text leaves the spotter.
// It cannot be disabled. SS- approval codes are left intact.
package redact

import (
	"regexp"
	"strings"
)

const mask = "[REDACTED]"

var (
	codeRE     = regexp.MustCompile(`SS-[A-Z0-9]{4,8}`)
	uriRE      = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^\s:/@]+:)([^\s@/]+)(@)`)
	envRE      = regexp.MustCompile(`(?i)\b([A-Za-z_][A-Za-z0-9_]*(?:PASSWORD|TOKEN|SECRET|KEY))\s*=\s*([^\s]+)`)
	pwFlagRE   = regexp.MustCompile(`(?i)(--(?:password|pass)(?:=|\s+))(\S+)`)
	secretFlag = regexp.MustCompile(`(?i)(--(?:secret|token)(?:=|\s+))(\S+)`)
	redisARE   = regexp.MustCompile(`(?i)(\bredis-cli\b(?:\s+\S+){0,8}\s+-a\s+)(\S+)`)
	dashPRE    = regexp.MustCompile(`(^|[\s=])(-p)(\S+)`)
	authRE     = regexp.MustCompile(`(?i)(authorization:\s*bearer\s+)(\S+)`)
	bearerRE   = regexp.MustCompile(`(?i)(bearer\s+)([A-Za-z0-9._~+/-]{8,})`)
	sqlPW      = regexp.MustCompile(`(?is)((?:identified\s+by|password)\s*\(?\s*')([^']*)(')`)
	sqlPW2     = regexp.MustCompile(`(?is)((?:identified\s+by|password)\s+)("[^"]*"|[^\s;]+)`)
	plainPW    = regexp.MustCompile(`(?i)(\b(?:password|passwd|pwd)\s+)(\S+)`)
	githubRE   = regexp.MustCompile(`\b(?:ghp_|gho_|ghs_|github_pat_)[A-Za-z0-9_]{16,}\b`)
	slackRE    = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)
)

// Text masks secrets in s. Approval codes keep their SS- form.
type Text struct {
	Extra []*regexp.Regexp
}

// New builds a redactor. Invalid extra patterns are skipped.
func New(extra []string) Text {
	var rs []*regexp.Regexp
	for _, p := range extra {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		rs = append(rs, re)
	}
	return Text{Extra: rs}
}

// Apply masks one string.
func (t Text) Apply(s string) string {
	if s == "" {
		return s
	}
	codes := codeRE.FindAllString(s, -1)
	holders := make([]string, len(codes))
	for i, c := range codes {
		holders[i] = "\x00SSCODE" + strconvI(i) + "\x00"
		s = strings.Replace(s, c, holders[i], 1)
	}
	s = uriRE.ReplaceAllString(s, "${1}"+mask+"${3}")
	s = envRE.ReplaceAllString(s, "${1}="+mask)
	s = pwFlagRE.ReplaceAllString(s, "${1}"+mask)
	s = secretFlag.ReplaceAllString(s, "${1}"+mask)
	s = redisARE.ReplaceAllString(s, "${1}"+mask)
	s = dashPRE.ReplaceAllStringFunc(s, maskDashP)
	s = githubRE.ReplaceAllString(s, mask)
	s = slackRE.ReplaceAllString(s, mask)
	s = plainPW.ReplaceAllString(s, "${1}"+mask)
	s = authRE.ReplaceAllString(s, "${1}"+mask)
	s = bearerRE.ReplaceAllString(s, "${1}"+mask)
	s = sqlPW.ReplaceAllString(s, "${1}"+mask+"${3}")
	s = sqlPW2.ReplaceAllString(s, "${1}"+mask)
	for _, re := range t.Extra {
		s = re.ReplaceAllString(s, mask)
	}
	for i, c := range codes {
		s = strings.Replace(s, holders[i], c, 1)
	}
	return s
}

// Argv masks each element. A secret flag also masks the following element,
// which Apply cannot see when the flag and the value are separate words.
// The environment is never passed here.
func (t Text) Argv(argv []string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		out[i] = t.Apply(a)
	}
	cmd := ""
	if len(argv) > 0 {
		cmd = strings.ToLower(baseName(argv[0]))
	}
	for i := 0; i < len(argv); i++ {
		if !secretFlagWord(cmd, argv[i]) || i+1 >= len(out) {
			continue
		}
		if strings.HasPrefix(argv[i+1], "-") && argv[i+1] != "-" {
			continue
		}
		out[i+1] = mask
	}
	return out
}

func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func secretFlagWord(cmd, flag string) bool {
	switch strings.ToLower(flag) {
	case "--password", "--pass", "--token", "--secret":
		return true
	case "-p":
		// mysql -p takes a password. Everywhere else -p is a normal flag
		// (mkdir -p, psql -p port) and must not hide the next argument.
		return cmd == "mysql" || cmd == "mariadb"
	case "-a":
		return cmd == "redis-cli" || cmd == "redis"
	default:
		return false
	}
}

// SecretValues lists argument values that follow a secret flag.
func (t Text) SecretValues(argv []string) []string {
	cmd := ""
	if len(argv) > 0 {
		cmd = strings.ToLower(baseName(argv[0]))
	}
	var out []string
	for i := 0; i < len(argv); i++ {
		flag := argv[i]
		if eq := strings.IndexByte(flag, '='); eq > 0 && secretFlagWord(cmd, flag[:eq]) {
			if v := flag[eq+1:]; v != "" {
				out = append(out, v)
			}
			continue
		}
		if !secretFlagWord(cmd, flag) || i+1 >= len(argv) {
			continue
		}
		next := argv[i+1]
		if next == "" || next == "-" || strings.HasPrefix(next, "-") {
			continue
		}
		out = append(out, next)
		i++
	}
	return out
}

// MaskValues masks a secret only when it is a whole field. A short value
// such as "a" must not blot out every letter a in the report.
func (t Text) MaskValues(s string, vals []string) string {
	if s == "" || len(vals) == 0 {
		return s
	}
	set := map[string]struct{}{}
	for _, v := range vals {
		if v != "" {
			set[v] = struct{}{}
		}
	}
	if len(set) == 0 {
		return s
	}
	var b strings.Builder
	i := 0
	for i < len(s) {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			b.WriteByte(c)
			i++
			continue
		}
		j := i
		for j < len(s) {
			d := s[j]
			if d == ' ' || d == '\t' || d == '\n' || d == '\r' {
				break
			}
			j++
		}
		field := s[i:j]
		b.WriteString(maskField(field, set))
		i = j
	}
	return b.String()
}

// maskField hides a secret argument. A resolved path is masked only in its
// final component, so a one-letter secret does not blot out other words.
func maskField(field string, secrets map[string]struct{}) string {
	if _, ok := secrets[field]; ok {
		return mask
	}
	for secret := range secrets {
		if secret == "" || secret == "." || strings.Contains(secret, "/") {
			continue
		}
		if strings.HasSuffix(field, "/"+secret) {
			return strings.TrimSuffix(field, secret) + mask
		}
	}
	return field
}

// Join renders argv as a command line after redaction.
func (t Text) Join(argv []string) string {
	return strings.Join(t.Argv(argv), " ")
}

func maskDashP(m string) string {
	i := strings.LastIndex(m, "-p")
	if i < 0 {
		return m
	}
	attached := m[i+2:]
	if attached == "" || knownPFlag[attached] || knownPFlag["p"+attached] {
		return m
	}
	return m[:i] + "-p" + mask
}

var knownPFlag = map[string]bool{
	"print": true, "print0": true, "path": true, "parent": true, "prune": true,
	"perm": true, "printf": true, "pid": true, "port": true, "prompt": true,
	"preserve": true, "pretty": true,
}

func strconvI(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
