# Shell Spotter — Integration Guide

Everything a host needs to run `spotter-sh` that lives **outside the codebase**: the
filesystem surfaces it owns on a machine, how `install` creates them and `doctor` checks
them, and how an agent runtime wires the approval hook and instructs its agent. See
[SPEC.md](./SPEC.md) for the full design.

---

## 1. Host filesystem surfaces

`spotter-sh` is a single static binary plus a small set of host-owned paths. Nothing here
is secret except the HMAC key; never print or commit the key.

| Surface | Default path | Owner / mode | What it is |
|---|---|---|---|
| **Binary** | `/usr/local/bin/spotter-sh` | root | Static Go binary (CGO off). The shims dispatch to it by `argv[0]`. |
| **Shim dir** | system: `/usr/local/lib/spotter-sh/shims`<br>user: `~/.local/lib/spotter-sh/shims` | install owner | One symlink per wrapped command that exists on the machine (`rm`, `chmod`, `mv`, `git`, `psql`, `docker`, …) → the binary. This dir is **prepended to PATH in the agent spawn env only** — not into system login shells. |
| **Root-owned config** | `/etc/spotter-sh/config.toml` | **root** | The authority. `fail`, `mode`, packs, redaction, limits and `allow_extra` are honored **only** from here. Lower layers (`~/.config/spotter-sh/config.toml`, project `.spotter-sh.toml`) may only *tighten* (add protected paths, lower thresholds). |
| **Key / state dir** (`$SPOTTER_SH_HOME`) | system: `/var/lib/spotter-sh`<br>user: `~/.local/state/spotter-sh` | dedicated `spotter-sh` user or root (system); the user (per-user) | Holds the per-install **HMAC key** (`key`, mode `600`) used to bind one-time codes, the **spent-nonce store** (append-only, single-use enforcement, GC'd past `code_ttl_sec`), and the **force-rate counter**. A system install owns this as a separate uid so the agent's uid cannot read the key (that is what makes a code unforgeable); a per-user install is readable by that user (the honest limit). |
| **Log** | `~/.local/state/spotter-sh/spotter.log` | install owner | JSON Lines. Records catches, approvals and near-threshold passes. argv is always redacted; env is never logged; command bodies (`-c`/`-e`/here-docs) are never stored. |
| **Per-session socket dir** | `/run/spotter-sh/<session>/decide.sock` | **host**, dir mode `0700` | The host binds and listens on this unix-domain socket for the interactive hook (§2). The path is unguessable per session and passed to the agent env as `SPOTTER_SH_HOOK`. The host owns the listening endpoint (it decides); the shim connects as the agent's uid. Auth: `0700` per-session dir + `SO_PEERCRED` check + `catch_id` match. |
| **Optional sudoers drop-in** | `/etc/sudoers.d/spotter-sh` | root | **Off by default.** Written only when installing with `--sudoers`; `visudo -c`-validated. Lets code-mode re-approval survive a `sudo` boundary via an `env_keep`'d one-shot. With it off, `sudo` is a documented coverage limit. |

### `spotter-sh install` creates them; `doctor` checks them
`spotter-sh install [--system|--user] [--shell bash,zsh] [--packs ...] [--refresh] [--sudoers]`:
1. places the static binary;
2. generates the per-install HMAC key at `$SPOTTER_SH_HOME/key` (mode `600`);
3. creates the shim dir and **one symlink per wrapped command present on the machine** (all packs on by default);
4. configures Layer-1 as a **host pre-check** and prepends the shim dir to PATH **in the agent spawn env only** — it does **not** set `BASH_ENV` and installs no DEBUG trap;
5. **only with `--sudoers`**, writes the opt-in, validated sudoers drop-in (default off);
6. runs `doctor`.

`--refresh` re-scans which wrapped tools are present (e.g. a newly installed `docker`) and
adds/removes shims. `install` is idempotent; `uninstall` reverses every step (shims, PATH
edit, key, nonce store, any sudoers drop-in) and leaves nothing on PATH.

`spotter-sh doctor` verifies: shims are on PATH in the real spawn env; the HMAC key is
present and readable; the hook fires; `sudo` coverage matches config; present-tool shims
match what is installed (hints `--refresh`); and a liveness probe (a canned allow + a canned
catch) passes, so a fail-closed spotter is not silently blocking everything. It prints
green/red per check. Per the standing no-automation rule, **nothing runs `doctor` on a
timer** — the host runs it at session spawn, at deploy, and on demand, and surfaces a red
result to the operator.

---

## 2. The interactive approval hook (preferred)

When a command is caught, the preferred resolution is the interactive hook: the shim
**blocks in place** on the host-owned socket and the host answers with a decision. There is
no re-run of the command and no token for the agent to hold.

- The host **binds and listens** on `/run/spotter-sh/<session>/decide.sock` and passes the
  path to the agent's shell env as `SPOTTER_SH_HOOK`.
- On a catch the shim connects, sends one newline-delimited **catch record** (JSON with
  `schema_version`, `catch_id`, `level`, redacted `command`/`argv`, `cwd`, `report`,
  `affected`, `consequence`, `common_mistake`, `safer_rewrite`), and waits on the same
  connection.
- The host presents the agent **three worded choices — never Y/N**, and replies with one
  decision frame `{"catch_id":"…","decision":"proceed|cancel|ask_human","reason":"…"}`:
  1. **PROCEED** — the shim `execve`s the real binary in place.
  2. **CANCEL & REWRITE** — the shim refuses (exit `120`); the agent composes a corrected command.
  3. **UNSURE, ASK MY HUMAN** — the command stays blocked; the host relays the report + the
     agent's reason to the human and answers with their proceed/cancel. `ask_human` has **no
     short timeout**.
- **Default = cancel** on an unclear/unparseable answer, a dropped connection, or any host
  error. Hard blocks offer only CANCEL or ASK MY HUMAN. Restricted (non-owner) turns cannot
  PROCEED.

If `SPOTTER_SH_HOOK` is unset or the connect fails, the shim falls back to **code mode**: it
prints the report plus a bound one-time `SS-` code and refuses the run (exit `120`); the agent
re-runs the identical command with `SPOTTER_SH_OK=<code>`.

**Stability:** the catch-record and decision-frame JSON are a versioned contract
(`schema_version`, currently `"1.0"`). New fields are only ever added within a major version;
consumers must ignore unknown fields.

### Example: wiring the hook from a Go agent runtime

The host runs a decision server on the socket, and spawns the agent's shell with the shim dir
on PATH and `SPOTTER_SH_HOOK` set. No PII, no secrets.

```go
package main

import (
	"context"
	"log"
	"os"
	"path/filepath"

	"spotter-sh/hook" // the public Go library
)

// decide maps a catch to one of the three choices. Return ask_human to hold the
// command and route to a person; a returned error defaults to cancel.
type decide struct{}

func (decide) OnCatch(ctx context.Context, c hook.Catch) (hook.Decision, error) {
	switch c.Level {
	case "hardblock":
		// Hard blocks can never proceed.
		return hook.Decision{Action: "cancel", Reason: "hard-blocked command"}, nil
	case "danger":
		// Surface c.Report to the agent and collect its choice. When the agent is
		// unsure, hand off to a human (the library keeps the connection open).
		choice := presentToAgent(c.Report) // "proceed" | "cancel" | "ask_human"
		return hook.Decision{Action: choice, Reason: "agent decision"}, nil
	default: // "bulk"
		return hook.Decision{Action: presentToAgent(c.Report), Reason: "bulk"}, nil
	}
}

func main() {
	session := os.Getenv("SESSION_ID")
	sockDir := filepath.Join("/run/spotter-sh", session)
	_ = os.MkdirAll(sockDir, 0o700)
	sock := filepath.Join(sockDir, "decide.sock")

	// 1) Prepend the shim dir to PATH and point the shell at the socket, in the
	//    environment the agent's shell is spawned with (NOT system-wide).
	shimDir := "/usr/local/lib/spotter-sh/shims"
	os.Setenv("PATH", shimDir+":"+os.Getenv("PATH"))
	os.Setenv("SPOTTER_SH_HOOK", sock)

	// 2) Serve decisions on the socket for the lifetime of the session.
	ctx := context.Background()
	if err := hook.Serve(ctx, sock, decide{}); err != nil {
		log.Fatal(err)
	}
}

func presentToAgent(report string) string { /* host UI */ return "cancel" }
```

For a non-Go host, set `hook_command = "/path/to/handler"` in config: the spotter execs it
with the catch-record JSON on stdin and reads a decision JSON on stdout. Built-in
`--adapter claude|cursor|codex|generic` adapters translate the catch record into those
frameworks' existing pre-tool-hook shapes.

---

## 3. Protected paths for the runtime's own data

An agent runtime should register its **own data directory and working repo** as protected,
so a wrong-cwd `rm -rf` inside them pauses. In the root-owned config:

```toml
[paths]
# add the runtime's state dir and source tree (recursive rows match at any depth)
protect_extra = ["~/.myagent/**", "~/src/myrepo/**"]
```

These are additive and may also be set from a lower (tightening) config layer.

---

## 4. Agent-side wiring (text that lives in the agent, not the codebase)

### 4.1 Shell tool-description line (one line, always present)
> Shell Spotter may pause unusually risky deletes, permission changes, database drops, or
> opening a DB session, and give you three choices — proceed, cancel & rewrite, or ask your
> human; its message explains the exact effect and a safer rewrite.

### 4.2 On-catch instruction note (load only when the spotter fires)
> Shell Spotter stopped a command and is asking you to choose. Read its report: it shows
> exactly what would be hit and a safer rewrite. In most cases a stop means you ran the
> command wrong (bad glob, empty variable, wrong folder, missing WHERE) — so prefer CANCEL &
> REWRITE: drop it, fix the command, and re-run the correct version, without interrupting
> your human to report a mistake you fixed. Choose PROCEED only when the listed targets are
> EXACTLY what you meant. Choose UNSURE, ASK MY HUMAN only when you are genuinely unsure it's
> right, when there's no safe alternative, or when the spotter warns you've proceeded on
> several dangerous commands recently — that routes to your human and you can wait or do
> other work. A hard BLOCK offers no proceed. If the spotter itself errors, the command
> won't run — don't work around it; fix the spotter or ask your human to run it. (If this
> shell ever falls back to code mode, the same judgment applies: re-run the identical command
> with the one-time code only when the effect is exactly intended.)

### 4.3 Generic agent-instructions block (paste into any agent's system prompt / tool description)

```
Shell safety spotter
This environment runs Shell Spotter (`spotter-sh`), an accident spotter in front of destructive
shell and database commands (rm, chmod/chown, mv/cp, dd, find -delete, git
reset/clean/push --force, DROP/TRUNCATE/DELETE-without-WHERE, docker/kubectl/
terraform deletes, and similar). It checks what a command would ACTUALLY affect
after the shell expands it, so it sees the real files, counts, and targets.

Most commands run normally and you will never notice it. It only stops a command
when the real effect looks dangerous or far larger than usual. It is a spotter
against mistakes, NOT a permission wall — anything it stops, you can approve.

It also stops before OPENING an interactive database session (psql/mysql with
no -c, redis-cli with no command, mongosh with no --eval), because it cannot
check statements you type live; back up first and prefer one-shot -c/-e/-f forms.

When it stops a command it shows what would be affected (counts, top paths,
system/protected paths, before→after permissions, estimated DB rows), the likely
consequence in plain words, the common mistake, and a safer rewrite. How you
approve depends on how this host is wired:

HOOK MODE (preferred). The tool call pauses and you are offered three choices:
  1. PROCEED — "I've read the report; these exact effects are what I intend."
  2. CANCEL & REWRITE — "This isn't what I meant; drop it, I'll fix the command."
  3. UNSURE, ASK MY HUMAN — the command is HELD (not run) and your human is sent
     the report and your reason; they decide proceed or cancel.
You never see or type a code; the decision returns over the host socket by catch_id.

CODE MODE (fallback, plain shells). The stop prints a one-time code like SS-7F3K.
To proceed, re-run the IDENTICAL command with it:
       SPOTTER_SH_OK=SS-7F3K <command>
The code lasts ~2 min, works once, and is tied to that exact command, directory
and target set. There is no on/off switch and no reusable token: do not try to
set SPOTTER_SH_OK=force or export it; it is ignored.

In BOTH modes:
1. PROCEED / use the code only when the listed effect is EXACTLY what you intended.
2. USUALLY a stop means your command was wrong — a glob matched too much, a
   variable was empty, you were in the wrong directory, or a WHERE clause was
   missing. Then CANCEL & REWRITE (or just don't use the code): fix the command
   and run the correct version. You don't need to tell the user about a mistake
   you caught and fixed yourself; just run it right.
3. Ask your human only when you are genuinely unsure the effect is correct, when
   there is no safe way to do it, or when the spotter warns you've proceeded on
   several dangerous commands recently.
4. A hard BLOCK (e.g. `rm -rf /`, a fork bomb) offers no proceed; cancel, or ask
   a human to run it by hand.

Each decision covers one command only and never disables the spotter. If the spotter
itself errors, the command is refused (not run) — fix the spotter or have a human
run it by hand.
```
