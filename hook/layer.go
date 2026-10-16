// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package hook

import "strings"

// LayerCase is one command the text check, host PrecheckAt, the engine,
// and the shim must place in the same tier. Tier is hardblock, catch, or pass.
type LayerCase struct {
	Text string
	Argv []string
	Tier string
}

// LayerCorpus is the shared set those layers are checked against.
// A single system directory stays a catch. The canonical top-level set is a
// hard block, the same call the engine makes.
func LayerCorpus() []LayerCase {
	top := "rm -rf /bin /etc /usr /home /var /lib /sbin /opt /root /boot"
	return []LayerCase{
		{Text: "rm -rf /", Argv: []string{"rm", "-rf", "/"}, Tier: "hardblock"},
		{Text: "rm -rf /*", Argv: []string{"rm", "-rf", "/*"}, Tier: "hardblock"},
		{Text: "rm -rf /bin", Argv: []string{"rm", "-rf", "/bin"}, Tier: "catch"},
		{Text: "rm -rf /usr", Argv: []string{"rm", "-rf", "/usr"}, Tier: "catch"},
		{Text: "rm -rf /etc /usr", Argv: []string{"rm", "-rf", "/etc", "/usr"}, Tier: "catch"},
		{Text: top, Argv: strings.Fields(top), Tier: "hardblock"},
		{Text: "{ :|:& }", Argv: []string{"bash", "-c", "{ :|:& }"}, Tier: "hardblock"},
		{Text: "f(){ :|:& }", Argv: []string{"bash", "-c", "f(){ :|:& }"}, Tier: "pass"},
		{Text: "runuser -u root -- rm -rf /", Argv: []string{"runuser", "-u", "root", "--", "rm", "-rf", "/"}, Tier: "hardblock"},
		{Text: "at --help", Argv: []string{"at", "--help"}, Tier: "pass"},
		{Text: "at --version", Argv: []string{"at", "--version"}, Tier: "pass"},
		{Text: "systemd-run --user --help", Argv: []string{"systemd-run", "--user", "--help"}, Tier: "pass"},
		{Text: "systemd-run --version", Argv: []string{"systemd-run", "--version"}, Tier: "pass"},
		{Text: "systemd-run --user sleep 1", Argv: []string{"systemd-run", "--user", "sleep", "1"}, Tier: "pass"},
		{Text: "echo hi", Argv: []string{"echo", "hi"}, Tier: "pass"},
		{Text: "systemd-run --user rm -rf ~/.ssh", Argv: []string{"systemd-run", "--user", "rm", "-rf", "~/.ssh"}, Tier: "catch"},
		{Text: "systemd-run --user --scope rm -rf ~/.appdata", Argv: []string{"systemd-run", "--user", "--scope", "rm", "-rf", "~/.appdata"}, Tier: "catch"},
		{Text: "systemd-run --user --on-active=1min rm -rf ~/notes", Argv: []string{"systemd-run", "--user", "--on-active=1min", "rm", "-rf", "~/notes"}, Tier: "catch"},
		{Text: "systemd-run --scope rm -rf ~/.ssh", Argv: []string{"systemd-run", "--scope", "rm", "-rf", "~/.ssh"}, Tier: "catch"},
		{Text: "systemd-run --user rm -rf /", Argv: []string{"systemd-run", "--user", "rm", "-rf", "/"}, Tier: "hardblock"},
		{Text: "systemd-run --scope rm -rf /", Argv: []string{"systemd-run", "--scope", "rm", "-rf", "/"}, Tier: "hardblock"},
		{Text: "systemd-run --user --on-active=1min rm -rf /", Argv: []string{"systemd-run", "--user", "--on-active=1min", "rm", "-rf", "/"}, Tier: "hardblock"},
		{Text: "systemd-run --user --scope make", Argv: []string{"systemd-run", "--user", "--scope", "make"}, Tier: "pass"},
		{Text: "systemd-run --scope go build", Argv: []string{"systemd-run", "--scope", "go", "build"}, Tier: "pass"},
		{Text: "if true; then :|:& fi", Argv: []string{"bash", "-c", "if true; then :|:& fi"}, Tier: "hardblock"},
		{Text: "if :; then :|:& fi", Argv: []string{"bash", "-c", "if :; then :|:& fi"}, Tier: "hardblock"},
		{Text: "if true; then :|:&; fi", Argv: []string{"bash", "-c", "if true; then :|:&; fi"}, Tier: "hardblock"},
		{Text: "if :; then :|:&; fi", Argv: []string{"bash", "-c", "if :; then :|:&; fi"}, Tier: "hardblock"},
		{Text: "if false; then :; else :|:&; fi", Argv: []string{"bash", "-c", "if false; then :; else :|:&; fi"}, Tier: "hardblock"},
		{Text: "while false; do :|:& done", Argv: []string{"bash", "-c", "while false; do :|:& done"}, Tier: "pass"},
		{Text: "f(){ :|:& }; f", Argv: []string{"bash", "-c", "f(){ :|:& }; f"}, Tier: "hardblock"},
	}
}
