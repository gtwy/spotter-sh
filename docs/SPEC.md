# shellspotter — Design Specification

| | |
|---|---|
| Status | Design specification. |
| Working name | `shellspotter` (binary `shellspotter`, env prefix `SHELLSPOTTER_`) |
| Audience | Implementers and open-source users. |

---

## 0. One-paragraph summary

`shellspotter` is an **oops spotter** for shells driven by AI agents. It sits in front of
destructive commands (file deletes/moves, permission/ownership changes, raw disk
writes, database drops) and checks the **real, already-expanded arguments** at the
moment they run. Normal work passes silently in under 5 ms. A small number of
commands that are never legitimate (e.g. `rm -rf /`, fork bombs) are **hard-blocked**.
Everything else it catches is **paused** with a message that says exactly what would have
happened. The **preferred** way to resolve a pause is an **interactive approval hook**: the
host holds the tool call and offers the agent three worded choices — proceed, cancel &
rewrite, or ask the human — and the shim **blocks in place** on a host-owned socket until the
decision returns, so there is no re-run and no token for the agent to handle (§10.1). Where no
hook exists (plain shells), the fallback is a **bound
one-time code** (`SHELLSPOTTER_OK=<code>`), HMAC-bound to the exact argv, cwd and resolved
targets, single-use, ~2 min expiry. On a pass the spotter adds nothing and `execve`s the real
binary with byte-identical argv (§3.7). The agent decides —
and in most cases the right move is to fix the command, not force it. It is not a
security boundary and makes no attempt to stop a determined actor.

---

## 1. Purpose and goals

1.1 **Purpose.** Prevent accidental, high-blast-radius damage caused by AI agents
running shell commands: the `chmod -R 600 .*` in `/root` incident (`.*` matched `..`
and recursed into `/`), empty-variable `rm -rf "$D"/*`, a `DROP TABLE` on the wrong
database, a fork bomb that freezes the host.

1.2 **Success criteria.**
1. Catches real accidents (every repro in §19.2 is caught).
2. Almost never interrupts normal work (zero false positives on the must-pass list, §19.3; target < 1 pause per 500 wrapped commands in the tuning week).
3. When it pauses, the agent can decide correctly from the message alone.
4. Overhead < 5 ms p95 per wrapped command; zero for unwrapped commands.
5. Ships standalone (no host dependency), documented well enough to open-source.

1.3 **Design principles.**
1. **Check effects, not text.** Inspect the final argv, real cwd, and the filesystem at exec time. Text matching is only used for the tiny pre-check list (§6) and for SQL (§11), where there is no other option.
2. **Quiet by default.** Pass-through emits nothing and changes nothing (same argv, env, exit code, stdin/stdout/stderr, signals).
3. **Every pause is approvable** except the hard-block list.
4. **Unclassifiable target ⇒ allow; a check that times out ⇒ catch; spotter failure ⇒ fail closed.** When the spotter can *run* but can't classify a target at all (unreadable path, unparsed SQL, piped stdin, remote operand, unknown flag), it lets the command run unless the case is a listed danger case — an oops spotter that breaks ordinary commands gets uninstalled. **But when a *check* runs too long (a walk or probe timeout, §9.5/§11.5/§12.3), that is a **catch** (§25 #4): the command does NOT run — it pauses with the normal choices (hook: PROCEED / CANCEL & REWRITE / UNSURE-ASK-HUMAN; code mode refuses with an `SS-` code), and the report says the check timed out, the count reached so far, and that a long scan likely means a very large target (§25 #4) — not an allow, not a 122.** If the spotter itself *fails* (crash, unreadable/invalid config, missing/unreadable key), the command does **not** run with exit 122 (§1.3.6, §14).
5. **Explain like a colleague.** Every message says what, why it's dangerous, the probable mistake, a safer rewrite, and how to approve.
6. **Fail closed.** If the spotter crashes, times out, or cannot read/parse its config, the command is **not** executed: it exits with a dedicated error code (§14) and a clear message — `shellspotter failed; command not run; see log; a human can run it by hand or fix the spotter` — and logs `spotter_error`. A spotter that cannot vouch for a command must not wave it through.
7. **Standalone and portable.** Single static binary + optional config. Linux first, macOS/BSD supported best-effort.

---

## 2. Threat model and non-goals

2.1 **In scope (accidents):**
- Glob surprises (`.*` → `..`, `*` in the wrong cwd, brace expansion blow-ups).
- Empty/unset variables (`rm -rf "$DIR"/`, `chmod -R 755 $X/`).
- Wrong cwd (`cd` failed silently, then `rm -rf *`).
- Wrong target scope (deleting `~` instead of `~/tmp`, recursive permission changes on system trees).
- Breaking permission-sensitive files (`~/.ssh`, `/etc/sudoers`, `/tmp`, setuid binaries).
- Database: dropping a whole DB/table, unscoped DELETE/UPDATE, FLUSHALL.
- Resource exhaustion: fork bombs, runaway process/memory growth.

2.2 **Non-goals (explicitly out of scope):**
- Stopping a malicious or determined actor. Anyone can call `/bin/rm`, `python -c 'shutil.rmtree(...)'`, `env -i`, or `unset BASH_ENV` to step outside the shims. The one-time codes raise the bar on casual reflex-approval, but they are not a security boundary and are not meant to be one. That is fine.
- Sandboxing, privilege separation, network policy, secrets protection.
- Guarding destruction done inside other programs (python, perl, node, make recipes calling absolute paths, ORMs, migrations), binaries called by absolute path (`/bin/rm`, `/usr/bin/find -delete`), `command -p`/`hash -p`/`PATH=…` resets, busybox by absolute path, and static binaries.
- **`sudo` when the `--sudoers` opt-in is off (default):** covered only by the agent-side sudo shim's inner-argv scan; there is no inner root shim, so code-mode re-approval across the sudo boundary is unavailable (§3.4 NB4). With `--sudoers` on, an `env_keep`'d one-shot restores it.
- **Per-file loops / batched invocations are a documented limit, not a catch (C7).** `for f in *; do rm -rf "$f"; done`, `find … -exec rm {} \;`, and `xargs rm` call the real command once per item, so each shim invocation sees **one** target and is only caught if that single target is itself protected or a large tree. The spotter does **not** aggregate across sibling invocations. This is honest: the design catches the *big single command*, not a hand-rolled loop. (`find -delete` and `find … -exec rm … +` batched form ARE seen as one op; the per-`{}`-`\;` form is the limit.)
- Guarding shell builtins and redirects in general (`> file`, `: > file`, `exec 3>f`, `tee`, `cp /dev/null x`): these are **out of scope** as a class. The narrow exceptions handled are the raw-disk redirect in the §6 pre-check and the `>`-onto-an-existing-**protected** file overwrite-class catch (§12.2) — resolving §2.2-vs-§12.2 (C5): ordinary redirects pass; only a redirect whose target is a protected path is flagged, and only via the pre-check's text view.
- Undo/backup (may be a later feature: §22).

2.3 **Honest-limits statement** (ships verbatim in README): "shellspotter catches the common ways an agent accidentally destroys things through the shell. It is not a sandbox. If you need a security boundary, use containers, users, and permissions — and run shellspotter inside them too."

---

## 3. Architecture

### 3.1 Components

| Component | What it is |
|---|---|
| `shellspotter` binary | **Implementation language: Go.** Single static binary (CGO off), so it drops in with no runtime deps. Subcommands: `exec` (shim mode), `precheck`, `check`, `explain`, `test`, `install`, `uninstall`, `doctor`, `log`. |
| Shim directory | `$SHELLSPOTTER_HOME/shims/` (default `/usr/local/lib/shellspotter/shims` system-wide, `~/.local/lib/shellspotter/shims` per user). One symlink per wrapped command → `shellspotter`. Binary dispatches on `argv[0]`. |
| Shell init snippet | `shellspotter init bash\|zsh\|sh\|fish` prints a snippet for **plain interactive shells**: prepend the shim dir to PATH and set `SHELLSPOTTER_ACTIVE=1`. The optional text-only pre-check hook is opt-in and is **not** used for the agent (no `BASH_ENV`/DEBUG trap, M6; host pre-check instead). Resource limits are **host-managed / opt-in**, never applied by this snippet (B6). |
| Config | `/etc/shellspotter/config.toml`, `~/.config/shellspotter/config.toml`, project `.shellspotter.toml` (§13). |
| Log | JSON Lines, default `~/.local/state/shellspotter/spotter.log` (§15). |
| Host adapter (optional) | Library/CLI contract for agent hosts that want to run pre-check themselves and map `confirm` params to tokens (§10.5). |

### 3.2 Layers

**Layer 1 — Pre-check (command text, before the shell runs it).**
Runs on the whole command string. Scope is deliberately tiny: hard blocks (§6) and the
bare-`.*` warning. Implemented two ways, either suffices:
- Host-side: agent host calls `shellspotter precheck -- "<command string>"` before sending to the shell (preferred; an example host does this).
- Shell-side: bash `extdebug` + `DEBUG` trap / zsh `preexec` calls the same check (fallback for interactive/other hosts).
No attempt to understand bash. False negatives here are acceptable because Layer 2 catches the same targets after expansion (as force catches rather than hard blocks).

**Layer 2 — Shims (real argv, after expansion).**
Wrapped commands resolve to the shim. By then bash has resolved variables, `~`, globs,
brace expansion, `cd`/`pushd`, loops, functions, subshells, `eval`, here-strings, and
wrappers like `sudo/nice/timeout/xargs/env/setsid/flock/watch`. The shim:
1. Identifies the real binary: next match on PATH after the shim dir (cached per PATH hash), never itself.
2. Parses argv with a per-command flag table (§8).
3. Resolves targets against real cwd (`getcwd`), `lstat`s them, classifies (§7), counts (§9).
4. Decision: `allow` → `execve(real, argv, env)` (process replaced; zero wrapper process remains). `pause`/`block` → message on stderr, exit code (§14).

### 3.3 Wrapped commands


| Group | Commands wrapped | Guarded action |
|---|---|---|
| Delete | rm, rmdir, unlink, shred, trash-put (if present) | remove / recursive remove |
| Perms/owner | chmod, chown, chgrp, setfacl | change (recursive = higher weight) |
| Move/copy/link | mv, cp, ln, install, rsync, dd | move-away, overwrite, `rsync --delete*`, `dd of=` |
| Internal-delete tools | find (`-delete`/`-exec rm`), rsync (`--delete*`), tar (`--overwrite`/`--recursive-unlink`), unzip (`-o`), sed (`-i`), perl (`-pi`), truncate | treated as delete/overwrite with real target counts |
| Multicall | busybox, toybox, coreutils | dispatch on argv[1]; re-enter the matching group (prior art P0.5) |
| VCS | git (subcommand table, §12) | `clean -fd[x]`, `reset --hard`, `checkout/restore -- .`, `stash drop/clear`, `branch -D`, `push --force` (no `--force-with-lease`), `filter-repo` |
| Disk | mkfs.*, wipefs, blkdiscard, fdisk, sgdisk, parted | raw-device writes (mostly hard-block, §6) |
| Database | mysql, mariadb, psql, sqlite3, mongosh, redis-cli, clickhouse-client (opt), cockroach (opt) | §11 |
| Infra (on by default) | docker, kubectl, helm, terraform, aws, gcloud, gsutil, crontab, systemctl | §12.3 — a wrapper is installed only for tools that exist on the system |
| Power (on by default) | reboot, shutdown, halt, poweroff, systemctl poweroff/reboot | molly-guard-style hostname confirm (§12.3) |

Each shim is the same binary dispatching on `argv[0]`/`argv[1]`. All groups — including
the DB, Infra and Power packs — are **on by default**. A wrapper is created only for a
command that is actually present on the system (resolved at install time and re-resolved by
`shellspotter install --refresh` and `doctor`), so a box without docker simply has no docker
shim. Any group or individual command can still be turned off in config. The rules
themselves are tiny config (§12.3), so an unused pack costs nothing: the overhead is one
extra PATH entry and, for present tools, the same sub-5 ms argv check (§16). Checks that
need live state — e.g. listing docker volumes, counting a tree, estimating DB rows — run
only for a tool that exists and only on a catch, never on the common allow path.

### 3.4 sudo, doas and PATH resets

`sudo` applies `secure_path` (compiled default, e.g. `/usr/sbin:/usr/bin:/sbin:/bin`),
which **drops the shim dir from PATH**, so `sudo rm -rf /etc` would bypass Layer 2
(prior art P0.2). Three defenses, applied in order:

1. **Wrap `sudo` and `doas` themselves.** The shim parses off sudo's own flags
   (`-u`, `-g`, `-E`, `-i`, `-s`, `--`), finds the inner command, and runs the normal
   classification on the *inner* argv against the target user's resolved home/cwd. On
   `allow` it `execve`s the real `sudo`. This catches `sudo rm`, `sudo find -delete`, etc.
   *User lookup with CGO off (U4):* the sudo shim resolves the target user's home/shell by
   reading `/etc/passwd` directly (and `getent` if present) — it does **not** rely on NSS/LDAP,
   so a pure-Go static binary works. `sudoedit`/`sudo -e`, `-s`, `-i` are handled explicitly
   (login/edit forms); an unparseable sudo form falls through with `parse_fallthrough`.
   *Approving an inner (root) catch (NB4 — the earlier "root-owned marker" is dropped; the
   sudo shim runs as the agent and cannot write a root file):* when `--sudoers` is on, the
   installed drop-in adds a single **`Defaults env_keep += "SHELLSPOTTER_SUDO_OK"`** entry so
   that **one** variable survives `env_reset`. The agent-side sudo shim, once its own catch is
   approved, sets `SHELLSPOTTER_SUDO_OK=<HMAC one-shot bound to the inner argv+nonce>`; the
   inner root shim verifies the HMAC against root's key, consumes the nonce, and runs without
   re-prompting. The same `env_keep` lets `SHELLSPOTTER_HOOK` (socket path) survive if the
   host prefers hook mode under sudo. **When `--sudoers` is OFF (the default), sudo is
   a documented limit:** there is no inner root shim, so `sudo` is covered only by the
   agent-side sudo shim's inner-argv scan (defense #1), and code-mode re-approval across the
   sudo boundary is not available. This is called out in §2.2 and §25.
2. **Optionally put the shim dir in `secure_path` — OPT-IN, and OFF on the host by default
   (B7).** Because this makes a bad config break the operator's *own* `sudo` and deploy scripts, the
   edit is **not** applied automatically. `install --sudoers` writes a commented, reversible
   `/etc/sudoers.d/shellspotter` **validated with `visudo -c`** before install; without that
   flag, `sudo` coverage is limited to defense #1. Default for the host: **no**.
3. **`doctor` verifies coverage** (at spawn / deploy / on demand, never on a timer, §16 C9):
   it reports whether `sudo command -v rm` resolves through the spotter and warns if not.

**Shim PATH is scoped to agent spawn envs (B7).** The shim dir is prepended to PATH **only
in the environments the host spawns agents in**, not system-wide login shells — so the operator's
own interactive/`sudo`/deploy sessions are untouched unless he opts in. `su -`, `env -i`,
`login`, `systemd-run`, cron and `docker exec` reset PATH; `doctor` lists each context it can
and cannot cover, and the README names them as known gaps (not silently "safe").

### 3.5 Shells, non-interactive agents and containers

- **bash (primary).** Layer 2 is PATH shims. Layer 1 (the tiny §6 text pre-check) runs
  **host-side** via the agent hook (§3.6), **not** via a bash `DEBUG`/`extdebug` trap. For
  this agent runtime specifically, **do NOT set `BASH_ENV` and do NOT install a DEBUG trap** (M6): a trap
  spawns `shellspotter precheck` for *every* simple command, so a loop costs thousands of
  forks, and `extdebug` changes bash semantics (function-return on trap, `BASH_ARGV`). Host
  pre-check once per tool call is enough.
- **Non-interactive `bash -c` agents**: coverage is (a) the shim dir on the inherited PATH
  (set in the agent spawn env, §3.4) and (b) the host pre-check (§3.6). No `BASH_ENV`.
- **Sticky-shell PATH resets (M7).** the agent can reset PATH mid-session
  (`export PATH=/usr/local/go/bin:/usr/bin:/bin`), which would drop the shims for the rest of
  the session. The host (`ShellTool`) therefore **re-asserts the shim-dir prefix and runs
  `hash -r` before each command**, and `doctor`/the host can check `command -v rm` per call.
- **zsh**: `preexec` cannot abort, so Layer 1 uses a `zle accept-line` widget override
  (prior art). **sh/dash**: no preexec; rely on shims + host hook. **fish**:
  `fish_preexec` event + shims. `shellspotter init <shell>` prints the right snippet.
- **Containers**: the static binary + shim dir bind-mount (or copy) into the image; one
  `RUN shellspotter install --system` layer. Works the same inside Docker/k8s as on the host.
- **Honest limit**: if a shell starts without the shim dir on PATH *and* without the hook,
  the spotter is simply not present. `doctor` is the way to confirm it is wired in a given
  spawn path. This is an oops spotter, not a sandbox (§2.3).

### 3.6 Agent pre-tool-hook adapter (prior art P0.3)

Most agent frameworks already expose a **pre-tool/command hook** that receives the full
command string and can return allow / ask / deny. `shellspotter precheck` speaks these so
Layer 1 works even where no shell init is sourced:

- Reads the command (argv `--` or stdin JSON), runs the pre-check (§6) **and** a recursive
  scan of inline-script strings (`bash -c`, `sh -c`, `python -c`, `perl -e`, `node -e`,
  `ssh host CMD`, `mongosh --eval`, heredocs — prior art P1.7).
- Emits the host's expected shape; adapters ship for: Claude Code PreToolUse
  (`{"permissionDecision":"deny|ask|allow","reason":...}`, exit 2 = block), Cursor
  `beforeShellExecution` (allow/deny/ask JSON), OpenAI Codex approval hook, and a
  **generic** mode (our exit codes §14: 0 allow / 120 catch / 121 hard block / 123 ask, with
  the catch record on stderr) for other agent frameworks.
- `shellspotter doctor` includes a hook check: it prints the exact config snippet for the
  detected host and verifies, in the agent's **real spawn env**, that `command -v rm`
  resolves to a shim and that the hook fires. "Installed" is only true when doctor is green.

### 3.7 Transparent passthrough guarantee

shellspotter is a **bystander on the allow path**. It must be impossible to tell, from a
command's behavior, whether the spotter was present — unless the spotter actually caught
something.

**The wrapper never re-parses, re-quotes, or rebuilds a command string.** It receives
`argv` exactly as the shell produced it (after bash did all expansion) and, on a pass,
calls `execve` on the real binary with the **byte-identical `argv` array**. Specifically,
on allow:
- `argv` is passed through unchanged, element for element, byte for byte — no re-quoting,
  no normalization, no splitting or joining, no string reconstruction.
- **`argv[0]` is preserved** so tools that branch on their invocation name (busybox/toybox
  applets, `bash` as `sh`, `vim` as `vi`) behave identically. (The shim resolves the real
  binary via PATH but execs it with the original `argv[0]`.)
- The **environment is passed through** untouched except that the one-shot
  `SHELLSPOTTER_OK` code (if present) is consumed and removed. **`SHELLSPOTTER_HOOK` is NOT
  stripped (N2):** descendants of a wrapped command (a git hook calling `rm`, `find -exec rm`,
  a `make`/`sed` child) must keep hook mode, and the socket model needs the path inherited.
  Leaking it is harmless — it is only a socket path, and the socket is auth-checked (§10.1).
- **stdin/stdout/stderr** file descriptors are inherited unchanged (no buffering,
  tee-ing, or line-wrapping); streaming and interactivity are unaffected.
- The child's **exit code and signal disposition** are returned verbatim: because the shim
  `execve`s (replacing its own process) rather than forking, the kernel delivers signals and
  the exit status directly, with no wrapper process left in between.
- On a pass the spotter writes **no output** to any stream and adds no measurable change
  beyond the <5 ms check (§16).

**One documented exception (B5).** Opening an *interactive* DB REPL that the
agent approved injects a server-side safe mode (`mysql --safe-updates`; append to
`PGOPTIONS`) — a deliberate behavior change, confined to interactive sessions, never applied
to one-shot `-c/-e/-f` runs, and never touching `sql_select_limit`/`max_join_size` (§11.4).
It is the only place shellspotter alters a command's arguments/env. **This exception is deliberate and documented** (§11.4, §25 #2b).

**stdin is never consumed or relayed (NB2).** For a regular-file stdin the shim `pread`s a
prefix then `lseek`s back to 0 before `execve`, so the client re-reads every byte. For a
pipe stdin (`pg_dump | psql`) the shim reads nothing and scans nothing — it never forks or
relays, so stdin, exit code and signals pass through untouched (§11.1).

**The pre-check (Layer 1) only reads text.** It never edits, re-quotes, or rewrites the
command; it either lets it through unchanged or raises a hard block / pause. The
**agent-hook adapter (§3.6) forwards the command unchanged** — it decides, it does not
transform.

**Why the earlier text-parsing approach was dropped.** That design tried to read
the command string and *predict* what bash would do, which meant effectively re-implementing
a shell parser — and bash has endless ways to hide a command's real effect (variables,
`eval`, nested shells, quoting tricks), so the parser both missed cases (the N1–N6 bypasses)
and risked altering intent. **bash is the parser.** shellspotter never second-guesses or
rewrites what bash produced: Layer 1 only *reads* the text for a tiny fixed danger list, and
Layer 2 inspects the already-expanded `argv` and execs it verbatim. The spotter's correctness
rests on *not* reconstructing commands.


---

## 4. Thresholds

Thresholds answer the sizing question. The v2 single-number idea (50 targets / 1,000
files) is replaced by **scaling by target type**, because the blast radius of deleting
files, recursively re-permissioning a tree, and touching a protected path are not
comparable. Recommended defaults:

| Trigger | Default | Rationale |
|---|---|---|
| Bulk delete (count of resolved targets) | pause above **100** targets | A human-meant delete is usually a handful or a single glob; 100+ distinct resolved paths is where "I didn't realize `*` matched that" lives. Below 100 is almost always intended. |
| Recursive delete of a tree | pause above **2,000 files OR 1 GB** (either) | Default is **OR** so a small-but-precious tree is still guarded (NB1): `rm -rf ~/.myagent/state` (many small files, far under 1 GB) and `rm -rf ~/src/myrepo` (a source tree under 1 GB) **do** pause — wrong-cwd-inside-a-repo is the most common accident. The **only** exemption is a **known build-output directory** (`node_modules`, `dist`, `build`, `target`, `.next`, `.cache`, `__pycache__`, `vendor` — configurable) **that itself sits inside a project root** (nearest `.git`/`.shellspotter-root`). The exemption applies to that build dir only, never to the repo root or its source/data; and **`/`, `/etc`, any `$HOME`, and any mount root are never treated as a project root** even if a `.git` lives there (etckeeper, a dotfiles repo). |
| Recursive chmod/chown/chgrp | pause above **500 files** | Permission sweeps are rarer and more dangerous than deletes (they can break a whole tree's executability or ownership) and are almost never meant to span 500+ files, so the bar is lower than for delete. |
| Any destructive op touching a **protected path** (§5) | **always** catch, independent of count | One file is enough: `chmod 0 ~/.ssh/authorized_keys` is a single-file disaster. |
| Overwrite class (`cp/mv/install -f`, `>` onto existing, `tar --overwrite`, `sed -i`) over many files | pause above **100** existing files overwritten | Same reasoning as bulk delete, applied to clobbering. |

4.1 **Count vs. size.** Counts are of **resolved, lstat'd targets** after glob/brace
expansion. The recursive-tree rule trips when **either** the file count OR the byte total is
over threshold (NB1). Size/count is a bounded walk (§9) that short-circuits as soon as either
bound is crossed, so cost is O(threshold), not O(tree). The build-output exemption (a known
build-dir name *inside* a project root, with `/`, `/etc`, `$HOME` and mount roots excluded as
project roots) is checked first and, when it applies, skips the walk for that one directory.

4.2 **Everything configurable** (§13): every number above is a key, settable globally,
per-user, and **per-project** via `.shellspotter.toml` at the project root. A project that
legitimately deletes huge trees raises its own ceiling without weakening others.

4.3 **Tuning plan (the spotter-log week).** Defaults are a starting guess, not doctrine.
During the first week every catch, approval and pass-near-threshold is logged (§15) with the
count/size that triggered (or came within 20% of) a threshold — **catches/approvals only, no
full command bodies** (N4). At week's end:
1. Build a histogram of real target counts/sizes per command.
2. Any threshold that fired on something the agent then simply `OK`'d without changing the
   command is probably too low → raise to the 95th percentile of observed safe operations.
3. Any real accident that passed under a threshold → lower it.
4. Record each change with its evidence in the log/README changelog. The goal from §1.2 is
   **< 1 pause per 500 wrapped commands** while still catching every §19.2 repro.

---

## 5. Protected paths and classification

Protected paths are flagged for **any** destructive action regardless of count (§4), at
**force** level (§10). This section is the precise classification required.

### 5.1 Protected-path table

| Class | Members | Guarded against | Level |
|---|---|---|---|
| Filesystem root & FHS dirs (NODE + direct-children sweep only, **not** prefix) | `/`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/usr`, `/etc`, `/var`, `/opt`, `/srv`, `/boot`, `/root`, `/home`, `/dev`, `/proc`, `/sys`, `/run` | delete/move-away/recursive-perms of **the dir itself** or a sweep of **all its direct children** (`rm -rf /var`, `rm -rf /var/*`, `chmod -R /opt`). A path *under* one of these (`/var/tmp/x`, `/opt/app/build`, `/srv/site/old.html`, `~/notes.txt`) is **NOT** force-protected by this row (B3). | force |
| Any home directory itself | `/home/<user>`, `/root`, `$HOME` — the directory node itself or sweeping all of its contents | delete, move-away, recursive perms | force |
| Dotfiles & agent config in a home | `~/.ssh/**`, `~/.gnupg/**`, `~/.config/**`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `~/.ssh/authorized_keys`, `~/.aws/**`, `~/.kube/**` | delete, overwrite, perms change | force |
| Key `/etc` files | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/sudoers`, `/etc/sudoers.d/**`, `/etc/ssh/**`, `/etc/fstab`, `/etc/hosts`, `/etc/resolv.conf`, `/etc/crontab`, `/etc/cron.*`, `/etc/pam.d/**`, `/etc/systemd/**`, `/lib/systemd/**` | delete, overwrite, perms change | force |
| Boot / devices / mount roots | `/boot/**`, `/dev/sd*`, `/dev/nvme*`, `/dev/mapper/*`, any detected mount point root | delete, raw write, perms | force (raw-disk writes → hard-block, §6) |
| Permission-sensitive files (perms-break) | ssh private keys / `authorized_keys` (must stay `600`), `/tmp` and other `*+t` sticky dirs (must stay `1777`), setuid/setgid binaries, `/etc/sudoers*` (must stay `440`) | **any chmod/chown that changes the required mode** | force |
| VCS metadata | `.git/` directory itself | delete, overwrite | force (prior art P1.9) |
| Marker-protected (opt-in) | any directory containing a `.shellspotter-protect` file (and that dir's parents, as a sweep) | delete, move-away, recursive perms | force (prior art P1.9) |

**Matching rule (B3).** Only the explicit `/**` rows (dotfiles, key `/etc`, `/boot/**`,
`~/.ssh/**` …) match **recursively by prefix**. Every bare directory entry (the FHS dirs,
home-dir node) matches **only the node itself and a sweep of its direct children** — never
arbitrary descendants. This is what keeps `rm ~/notes.txt`, `rm ~/*.log`, `rm /var/tmp/x`
and `rm /srv/site/old.html` from becoming force catches (§5.3, §19.3).

### 5.2 Perms-sensitive rule detail

A chmod/chown is a **perms-break** catch when it would move a sensitive file *away from*
its required mode/owner:
- ssh key or `authorized_keys` → anything other than `600`/`400` (and owner must stay the
  user) → catch.
- `/tmp` or any sticky world-writable dir → removing the sticky bit or `1777` → catch.
- a setuid/setgid binary → clearing the `s` bit is allowed (that is *safer*); **adding**
  setuid to a non-system file, or `chmod -R 777` over a tree containing setuid files, →
  catch.
- `/etc/sudoers*` → anything other than `440` → catch (a bad mode makes sudo refuse to run).

### 5.3 Explicitly NOT flagged (intent: don't nag)

| Operation | Why it passes |
|---|---|
| Deleting website/app content, e.g. `rm public/old.html`, `rm -rf dist/` | ordinary project output, not a protected path, under threshold |
| The bot's own scratch/text files, `rm ~/notes.txt`, `rm /tmp/scratch/*` | ordinary files, under threshold, not protected |
| Build output, `rm -rf node_modules build target .next` | under the tree thresholds (count+size), common and intended |
| `rm ~/*.log`, `rm /tmp/*.png` | under threshold, home dotfiles not matched by `*.log` |
| Normal perms, `chmod +x script.sh`, `chmod -R 755 ./site`, `chmod 644 index.html` | under 500 files, not a sensitive/protected target |
| Copy/move into `.` or `~`: `cp report.pdf ~`, `mv ../a .`, `rsync -a src/ dest/` | destination is cwd/home, not a protected *target*; this was a v2-era false positive and must pass |
| `d=$(mktemp -d); rm -rf "$d"` | resolved target is a temp dir, under threshold |

### 5.4 Classification algorithm (per resolved target)

1. `lstat` the target (no symlink follow). Record real path via `realpath` of the parent +
   the final component (so a symlink *to* a protected path is also caught; §18).
2. Match against §5.1 using its **matching rule (B3)**: a `/**` row matches by prefix; a bare
   FHS/home-node row matches only the **node itself** or a target set that is a **sweep of
   that node's direct children** (the operand set, after expansion, equals or covers all of
   its immediate entries). → **protected ⇒ force**. A path merely *under* a bare node is not
   protected here and falls through.
3. Else, danger ⇒ force (§7 A/D), detected **purely from resolved targets** (U2 — there is no
   text channel from Layer 1 to the shim):
   - the target's realpath **is the parent of cwd** or any `..`-reached ancestor of cwd
     (this is how post-expansion `.*`/`rm -rf ..` and `rm -rf $empty/` → `/` are caught; it
     does not depend on seeing the literal `.*`, so bash ≥5.2 `globskipdots` makes no
     difference, M12);
   - the resolved set is exactly `/` or every direct child of `/` (empty-variable sweep, §7 D).
   - **Sweeping the cwd itself** (`rm -rf *` resolving to all of cwd's children) is a **bulk**
     candidate (step 4), **not** an automatic force, unless cwd is a protected node — a plain
     `rm -rf *` in a build dir must not be a force catch (M12).
4. Else count/size against §4 (with the build-output/in-project exemption) → **bulk** if over.
5. Else → **allow**.
If classification cannot complete within the walk/probe budget → a **catch** (§25 #4): the command does NOT run — it pauses with the normal choices (hook: PROCEED / CANCEL & REWRITE / UNSURE-ASK-HUMAN; code mode refuses with an `SS-` code), and the report says the check timed out, the count reached so far, and that a long scan likely means a very large target; never a silent allow and never a 122. Highest level across all targets wins.

---

## 6. Hard blocks (never run, no approval)

Layer 1, on the command text, after normalizing whitespace and flag order
(`-rf`/`-fr`/`-r -f`/`--recursive --force`), with or without `sudo`/`doas`. The list is
deliberately tiny — only patterns that are certain to be a mistake and that no real command
needs. Anything uncertain goes to §7 (approvable) instead, never here.

**Match only at command position; ignore quoted text (fixes M5).** The pre-check tokenizes
the line and tests a pattern **only where a command would start** (start of line, after
`;`/`&&`/`||`/`|`/newline, inside `$( )`). It never matches inside a single/double-quoted
string, a here-doc body, or a `-m`/`-e`-style argument. So `git commit -m "guard rm -rf ~
case"`, `grep -r 'rm -rf /' docs/`, and `echo "rm -rf /"` are **not** hard-blocked — only an
actual `rm -rf /` at command position is. (This matters because a hard block offers no
PROCEED, so a false match on a doc or commit message would be unrecoverable.)

- `rm -rf /`, `rm -rf /*`, `rm -rf --no-preserve-root /`
- `rm -rf ~`, `rm -rf ~/`, `rm -rf $HOME`, `rm -rf "$HOME"` (the home node itself)
- `rm -rf .*`, `rm -rf ./.*`
- `chmod -R`/`chown -R`/`chgrp -R` whose target is `/`, `/*`, or `.*`
- `chmod -R 777 /`, `chmod -R 000 /`
- `mkfs.*` / `dd of=` / `wipefs` / `blkdiscard` aimed at a mounted system disk; `>`-style
  writes to a raw system device (`/dev/sda`, `/dev/nvme0n1`)
- **Fork bombs**: a function whose body pipes or backgrounds a call to its own name —
  `:(){ :|:& };:` and renamed variants (`bomb(){ bomb|bomb& };bomb`). Detected by the
  self-recursive-pipe/background pattern, not a literal string.

6.1 **Resource backstop (fixes B6) — cgroup, not per-UID rlimits.** For a fork bomb the
pattern misses, the containment is a **per-shell cgroup**, not `ulimit`. `ulimit -u`
(RLIMIT_NPROC) is **per UID**, so it would count *all* of the agent's user's processes (agent
children, `go build`, the browser, the host runtime itself) and make forks start failing across the
whole bot — unacceptable. And an address-space cap (RLIMIT_AS / a hard `MemoryMax` as
vmem) **kills Go, Node and Chrome**, which reserve huge virtual address space, so `go build`
and `npm` would die. Instead, when a host opts in, each agent shell runs in its own scope —
`systemd-run --scope -p TasksMax=<n> -p MemoryMax=<n>` (or an equivalent cgroup v2 slice) —
which bounds a bomb to that scope without touching sibling processes or vmem reservations.
**Default: OFF.** On the host it is left to the host; shellspotter sets no rlimits by
default. The fork-bomb *pattern* hard block (§6) stays on regardless.

6.2 **Message**: `shellspotter: BLOCKED — <reason>. This command is never allowed. If you
truly mean it, a human must run it by hand (/bin/<cmd>).` Logged as `block`.

6.3 Hard blocks are a Layer-1 convenience, not the safety line: the same catastrophic
targets are caught at **force** level by Layer 2 after expansion even when the text form
dodges §6 (e.g. built from a variable). Hard block = "obvious literal typo"; Layer 2 =
"the real effect."

---

## 7. Catch classification (approvable danger cases)

After expansion, Layer 2 raises one of:

- **A. Catastrophic target** — delete, move-away, or recursive chmod/chown/chgrp aimed at
  (or sweeping everything inside) a §5.1 protected path, a mount root, or a `..`-reached
  parent. Level: **force**.
- **B. Bare `.*`** in a wrapped command. Level: **force**. Message suggests `.[!.]*`.
- **C. Bulk surprise** — over a §4 threshold. Level: **OK**.
- **D. Empty-variable sweep** — a target that **resolved** to `/`, a bare mount root, or a
  direct-child sweep of one (e.g. an empty `$X` turning `"$X"/` into `/`). Level: **force**.
  Detected **purely from the resolved operands** the shim receives after bash expansion
  (§5.4.3, U2) — the shim never re-reads the raw `$X` text and does not depend on the
  pre-check.
- **E. Protected-path / perms-break** (§5.1, §5.2). Level: **force**.
- **F. git / overwrite / infra / DB** danger (§11, §12). Level per that section.

There are two catch **levels**: **bulk** (case C) and **danger** (cases A, B, D, E, and
the force-level entries of F). Both are resolved the same way — via the interactive hook
(preferred, §10.1) or, with no hook, a bound one-time code
(§10) — but a danger report is louder (DANGER header, consequences, protected/system paths
called out). The level only changes the message and the force-rate monitor (§10.4), not the
mechanism.

---

## 8. argv parsing

8.1 Each wrapped command has a small flag table (which flags take values, which set
recursion, which set force like `rm -f`, which are destructive subcommands). The shim does
**not** shell out to the real tool to parse; it reproduces GNU/BSD getopt behavior,
including `--`, clustered short flags (`-rf`), `--long=value`, and `--` end-of-options.

8.2 Targets are the non-flag operands. For `cp/mv/install/ln/rsync`, the **last** operand
is the destination (checked for overwrite/protected), the rest are sources. For
`find`, the leading paths are roots and `-delete`/`-exec rm`/`-exec sh -c` are the
destructive actions. For `dd`, `of=` is the target. Multicall binaries (busybox/toybox):
`argv[1]` selects the applet, then re-enter the matching table.

8.3 **Unknown flag ⇒ allow** (principle 4). The spotter never refuses because it failed to
parse; it logs `parse_fallthrough` and runs the command. The only exception is when the
*already-resolved operands* independently hit §5/§7 (those are checked regardless of flag
confusion).

8.4 **argv[0] dispatch fallback (M13).** The shim normally dispatches on `basename(argv[0])`.
`exec -a weird rm …` (or a renamed symlink) hands it an unrecognized `argv[0]`. The shim does
**not** fail-closed on this: it resolves the real target binary by PATH as usual, and if the
name is unrecognized it passes through with `parse_fallthrough` (the resolved operands are
still checked against §5/§7). `/proc/self/exe` is not used to recover the intended name (the
symlink name is already lost).

8.5 **Flag tables are variant-aware (U6).** Each wrapped command ships a tiny table covering
the **GNU, BSD/macOS and busybox/toybox** spellings of the flags that matter
(recursion/force/destructive-subcommand); unlisted flags are ignored for classification
(§8.3). The complete per-command list of which invocations are intercepted — and the note
that `sed`/`perl`/`tar`/`unzip`/`git` are only intercepted for their destructive forms — is a
documented table in the man page (so maintainers can see exactly what pays the shim cost).

8.6 **Built-in secret redactor (MANDATORY — fixes B8).** Before any argv or command text
leaves the process — to the log (§15), to a catch record / socket (§10.1), or to an
ask_human message (see INTEGRATION.md) — it passes through a built-in redactor that **cannot be disabled**.
It masks: password flags (`-p<pw>`, `--password=`, `mysql -pX`); a **generic
`scheme://user:pw@host` URI-credential pattern** covering any git/DB/HTTP URL with inline
credentials or a token (`postgres://u:pw@h/db`, `mongodb+srv://…`, `https://x-access-token:…@`);
secret-bearing env assignments in argv (`PGPASSWORD=…`, `*_TOKEN=`, `*_SECRET=`, `*_KEY=`,
`AWS_SECRET_ACCESS_KEY=`); `Authorization:`/bearer headers in a scanned `-c` string;
high-entropy `--secret`/`--token` values; and **SQL password literals** —
`ALTER USER … PASSWORD '…'`, `CREATE USER … PASSWORD '…'`, `IDENTIFIED BY '…'`,
`PASSWORD('…')` — in any `-c/-e/--eval` body. **Environment is never logged at all.** Hosts
add patterns via `[redact] extra_patterns`; for the host runtime the catch record is **also** run
through the host's existing secret redactor before it reaches the agent or the operator (defense in depth,
B8). The code format (`SS-…`) is on the allow-list so it is never masked (M9).

---

## 9. Counting and bounded walk

9.1 Non-recursive op: targets = resolved operands; count directly.

9.2 Recursive op (`-r`/`-R`, `find`, `rsync --delete`): walk each root with a **bounded**
traversal that stops the instant it exceeds the larger of the relevant count/size
thresholds, reporting "> N". It does not stat the whole tree. One `--one-file-system`-style
check marks when a walk crosses into a different device (mount) — crossing a mount root is
itself a §7A catch (§18).

9.3 Symlinks are not followed during the walk (matches `rm -r` / `chown -R` default). A
command-line operand that *is* a symlink to a protected path is still caught via §5.4.1.

9.4 Size is summed from `st_blocks` (actual on-disk), short-circuited at the byte ceiling.
The tree rule trips on **either** count OR bytes over threshold (§4 NB1); only a known
build-output dir inside a project root is exempt (and `/`, `/etc`, `$HOME`, mount roots are
never project roots).

9.5 The walk has a `walk_timeout_ms` budget (slow NFS / cold disk). On expiry the result is
a **catch** (§25 #4): the command does NOT run — it pauses with the normal choices (hook: PROCEED / CANCEL & REWRITE / UNSURE-ASK-HUMAN; code mode refuses with an `SS-` code), and the report says the check timed out, the count reached so far, and that a long scan likely means a very large target (§25 #4), **never** an allow and **never** a fail-closed 122. The report
gives the partial count reached before the deadline; a scan this slow usually means a very
large target, which is exactly when a pause is wanted.

---

## 10. Approval: interactive hook (preferred) and one-time codes (fallback)

shellspotter has **two approval modes**. The **interactive approval hook (§10.1)** is the
preferred integration: the host pauses the tool call and presents the agent a structured,
three-option choice; the agent never sees or types a code. **Bound one-time codes
(§10.2)** are the fallback for plain shells and hosts without a hook. Both share the same
binding (argv + cwd + resolved targets + level + nonce + ~2 min expiry), single-use
tokens, hard-block rules, logging and force-rate monitor.

### 10.1 Interactive approval hook (preferred) — block in place over a socket

**Why block-in-place, not exit-and-resume (fixes B1/B2).** A shim is a grandchild of bash
running deep inside a command string. If it *exited* to ask for a decision, bash would carry
on: `a; rm -rf x; b` would run `b`, `rm … || echo ok` would swallow the signal, a pipeline
without `pipefail` would lose it, and `set -e` would abort the script — and the host would
only ever see the exit status of the whole string. "Re-running the identical command" would
then either re-execute side effects that already happened (`mv data data.old; rm -rf
data.old/*`) or exec argv outside the agent's sticky shell, losing its cwd, exported env and
functions. So the shim does **not** exit to ask. **It blocks in place**: it opens the
host-owned decision socket, sends the catch record, waits for the decision on that same
connection, and then — in the *same* process, with the real cwd/env/stdin intact — either
`execve`s the real binary or refuses with a non-zero exit. Nothing is ever re-run. There is
**no exit-11 resume and no fd 3** (writing catch JSON to a bare fd 3 would corrupt a user's
`exec 3>file`, breaking §3.7).

**The decision socket (auth — N3).** The host **binds and listens** on a unix-domain socket
and passes its path in `SHELLSPOTTER_HOOK=/run/shellspotter/<session>/decide.sock`. The
**host owns the listening endpoint** (it decides); the shim, running as the agent's uid,
**connects** to it — so the socket is **host-bound, agent-connectable** (the earlier "not
writable by the agent" wording was wrong, N3). Authority stays with the host because only the
host *answers*; a connect does not grant the agent any decision power. Auth, concretely:
- the socket lives in a **per-session directory mode `0700` owned by the host**, so only the
  host (and the agent uid it chose to share with) can reach the path, and the path is
  unguessable per session;
- the host does a **`SO_PEERCRED` check** on each connection and accepts only the expected
  agent uid/pid lineage;
- the decision frame is matched to the connection's `catch_id`; a frame on the wrong
  connection is ignored.
On a catch the shim connects, sends the catch record, and reads back one decision frame. If
`SHELLSPOTTER_HOOK` is unset or the connect fails, the shim falls back to **code mode**
(§10.2): it prints the report + a bound code and refuses this run (exit 120, §14), so the
agent re-runs with the code. The decision wait and the ask_human wait are **excluded from
`fail_timeout_ms`** (§7/§14): thinking is not a spotter failure.

**Concurrency.** Many shims can wait at once (e.g. `find … | xargs -P8 rm`, or two catches
in one pipeline). Each connection carries a unique `catch_id`; the host serializes
presentation (a queue) and answers each `catch_id` independently. The host decides its UI for
multiple open catches — an example host presents them one at a time in arrival order and may
offer "cancel all remaining". A shim whose peer closes the socket defaults to **cancel**.

Catch record (JSON, sent on the socket):
```json
{
  "schema_version": "1.0",
  "catch_id": "c7f2…",                // unique per waiting shim
  "level": "danger",                  // "danger" | "bulk" | "hardblock"
  "command": "chmod -R 600 .[REDACTED]",   // redacted argv string (§8.x redactor)
  "argv": ["chmod","-R","600",".*"],  // redacted element-wise
  "cwd": "/root",
  "restricted": false,                // host-set: is this a restricted (non-owner) turn?
  "report": "…full human-readable report text (same as §10.6, already redacted)…",
  "affected": {
    "op": "chmod-recursive",
    "count": 3891,
    "bytes": null,
    "top_paths": ["/root/.ssh/authorized_keys","/etc/passwd","/usr/bin/sudo"],
    "protected_hit": true,
    "perm_change": {"from":"varies","to":"0600"}
  },
  "consequence": "sshd will refuse logins; sudo will stop working; may not boot.",
  "common_mistake": "'.*' matches '..' so -R walks the whole filesystem.",
  "safer_rewrite": "chmod 600 .[!.]*"
}
```
No `approval_token` travels to the agent: the host answers the open connection directly, so
there is nothing for the agent to hold or type (fixes the M1 "agent can mint codes" concern
for hook mode).

**The three options the host presents the agent** (structured choice, never Y/N):
1. **PROCEED** — "I've read the report; these exact effects are what I intend." The host
   sends `{"decision":"proceed","catch_id":…}` on the connection; the shim `execve`s the real
   binary in place.
2. **CANCEL & REWRITE** — "This isn't what I meant; drop it and I'll fix the command." The
   shim refuses (exit code §14); the agent composes a corrected command.
3. **UNSURE, ASK MY HUMAN** — the command stays **blocked** (the shim keeps waiting; nothing
   runs). The host messages the human with the already-redacted `report` and the agent's
   stated reason, and answers the still-open connection with the human's proceed/cancel. No
   re-resolution or token re-check is needed because the process never left the catch.

**Rules.**
- A decision is accepted **only on that open connection** (`catch_id`). There is no
  pre-approval, no token minted ahead of time, and no carry-over to a later command.
- **Default = CANCEL** on an unclear/unparseable answer, a dropped connection, or any host
  error. **A plain decision timeout is NOT applied to ASK MY HUMAN** (§10 C3): once routed to
  the human the shim waits (bounded only by the host's own session lifetime), so "ask the
  human" does not silently cancel after a few minutes.
- **Restricted (non-owner) turns cannot PROCEED.** When the host marks the turn `restricted`,
  the only options are CANCEL or ASK MY HUMAN (fixes M8).
- **Hard blocks (§6)** present with `level:"hardblock"` and offer **only** CANCEL or ASK MY
  HUMAN — never PROCEED. (A human still runs a true hard block by hand.)
- **Bulk** catches use the same options with lighter wording (option 1: "Yes, do all N —
  intended"; option 2: "No, let me narrow it").
- **Power/molly-guard (§12.3):** a hostname-confirm catch is a danger catch whose PROCEED the
  host gates behind the human typing the hostname; it occupies the normal PROCEED slot, the
  host just requires the extra confirmation before sending `proceed` (fixes M15).

### 10.2 Bound one-time codes (fallback)

Used when there is no host hook (a plain interactive shell, a bare `bash -c`, or a host
that hasn't implemented §10.1). There is no sticky `SHELLSPOTTER_OK=1`/`force` and no "disarm
for the session." When the spotter catches a
command it prints a short code, e.g. `SS-7F3K`. The code is an **HMAC** over:
normalized argv + real cwd + a hash of the resolved target set + the catch level (bulk or
danger) + a random nonce, with a **~2-minute expiry**. The HMAC key is generated per
install. **Honest limit on the key (M1):** for a *per-user* install the shim runs as the
agent's own uid, so the key (and the spent-nonce / force-rate state) are readable and
writable by that user — a determined agent could mint its own code. That is acceptable for an
oops spotter (it is not a security boundary, §2.2), and it is why the **preferred** hook mode
(§10.1) keeps the decision authority off the agent's uid entirely (host-owned socket, or a
separate spotter uid / root-owned helper). Where a host wants codes to be unforgeable too, it
installs with a dedicated spotter user or a small setuid helper that owns the key and the
nonce store (§10.8, U3). In the common case the code still prevents *accidental* reuse and
reflex approval, which is the point: **the code exists only after the report is shown**, is
bound, single-use and expiring.

**To approve in fallback mode**, re-run the *identical* command with the code:

```
SHELLSPOTTER_OK=SS-7F3K rm -rf /srv/data/old
```

The spotter recomputes the HMAC from the live argv, cwd and freshly resolved targets and
compares. It is rejected — and a fresh report with a new code is shown — if the argv, cwd or
resolved target set changed, the code expired (> ~2 min), it was already used (single-use;
spent nonces recorded), or the HMAC/level doesn't match. The code format is fixed as
`SS-[A-Z0-9]{4,8}`; a host redactor that masks high-entropy strings in agent-visible output
must **allow-list this format** so code mode keeps working (M9), while hook-mode tokens never
appear in agent-visible output at all.

Both **bulk** and **danger** catches use codes; the danger report is louder (§10.5). A hard
block (§6) has no code and is never approvable this way. A **catch always refuses this run**
with a distinct exit code (§14, not a tool's own 2/3) so the host can tell a spotter pause
from the command's own failure.

*Compound-command caveat (N6):* in code mode the shim can only refuse **its own** invocation
by exiting non-zero, so in `a; rm …(refused); b` the shell still runs `b` (and in
`rm …(refused) && b`, `b` does not). This is acceptable for the fallback path and is
documented here and in the agent-instructions (§20.1); the preferred **hook** mode has no
such gap because the shim blocks in place before anything after it runs.

10.3 **No env-var disable.** `SHELLSPOTTER_OK` carries a one-time **code** for *this* catch
only; it approves nothing on its own and cannot disable anything. There is no
`SHELLSPOTTER_OFF` and no "paranoid off" env var. The spotter's presence, packs, thresholds,
`fail` mode and `mode` are controlled **only by root-owned config** (§13): the system file
`/etc/shellspotter/config.toml` and the lower layers may only *tighten*, and **there is no
`SHELLSPOTTER_CONFIG` env override** (dropped per C2 — it would let the agent point at a
`packs=[]` / `fail="open"` / `allow_extra=["/**"]` file). An agent running as its own uid
therefore cannot weaken the spotter through the environment.

*Honest note (M2):* a command-prefix assignment and an exported var are indistinguishable in
`envp`, so the spotter does not try to tell them apart; it simply treats any `SHELLSPOTTER_OK`
as a candidate code and rejects it unless it is a valid, unused, bound code for the live
catch. Because `sudo`'s `env_reset` strips both `SHELLSPOTTER_OK` and `SHELLSPOTTER_HOOK`,
crossing the sudo boundary in code mode works only when the opt-in `--sudoers` drop-in
`env_keep`s a single `SHELLSPOTTER_SUDO_OK` HMAC one-shot (§3.4 NB4). With `--sudoers` off
(default) there is no inner root shim and sudo is a documented limit, not a
re-prompt — the earlier root-owned-marker idea is dropped as unbuildable (the sudo shim runs
as the agent).

10.4 **Force-rate monitor.** The spotter counts **PROCEED decisions on danger catches**
(hook mode) and **danger-level code approvals** (fallback) in one sliding window (default
**5 in 10 minutes**, configurable). Once the count is exceeded, the next catch's report —
and, in hook mode, the option-3 wording — gains a prominent line: `shellspotter: you have
proceeded on N dangerous commands in M minutes — STOP and check with your human before
continuing`, and logs a `force_rate_alert`. It does **not** block (still an oops spotter, not
a lock); it is a tripwire against an agent reflexively proceeding. A human PROCEED (option 3
resolved by the human) does not count against the agent. Threshold and window are config
keys; the monitor can be disabled in config only.

10.5 **Host integration surfaces.** Preferred: the interactive hook (§10.1) — the host
pauses the tool call while the shim blocks in place on the host-owned socket (§10.1) and
exposes the three-option decision as a tool/parameter; the decision returns over the socket
by `catch_id` — no token, no re-run. Fallback for hosts that pass a parameter but don't
implement the full hook: a
`confirm: "<code>"` tool parameter that the host maps to `SHELLSPOTTER_OK=<code>` on the
re-run (agent sees the code). The §3.6 agent-hook adapter maps a pause to the host's `ask`
decision, carrying the structured catch record (§10.1) or, in fallback, the message with
its code.

10.6 **Pause message format** (goal: make the danger unmistakable):

```
================  shellspotter: DANGER — would damage protected paths  ================
command : chmod -R 600 .*     (cwd: /root)
effect  : recursive permission change, 3,891 files
targets : .* expands to  . ..   ->  this RECURSES INTO /  via ..
          top paths:
            /root/.ssh/authorized_keys   0700 -> 0600
            /etc/passwd                  0644 -> 0600   <-- SYSTEM FILE
            /usr/bin/sudo                4755 -> 0600   <-- SYSTEM FILE (setuid)
          + 3,888 more under /
likely consequence : sshd will refuse logins (key/auth perms), sudo will stop
                     working, the system may not boot cleanly.
common mistake     : ".*" matches "." AND ".." — ".." is the parent, so -R walks
                     the whole filesystem.
safer rewrite      : chmod 600 .[!.]*        (dotfiles in THIS dir only, no ..)
--------------------------------------------------------------------------------------
if this is EXACTLY what you meant, re-run the identical command with the code below
(valid ~2 min, single use, bound to this command + directory + targets):
    SHELLSPOTTER_OK=SS-7F3K <command>
or just re-run the safer rewrite above.
======================================================================================
```

A **bulk** (C) catch uses a calmer header (`shellspotter: paused — large operation`), the
count/size, the first 20 paths, and the same `SHELLSPOTTER_OK=<code>` line. For **permission**
changes the message always shows **before -> after** modes; for **deletes/moves** it shows
counts + top paths + any system/protected paths called out explicitly; for **DB** it shows
the statement, the target DB/table, and the estimated row count (§11). When the force-rate
monitor (§10.4) has tripped, the "STOP and check with your human" line is prepended.

10.7 **Who approves — the agent decides** (binding design intent). A
danger catch does **not** automatically go to a human. In hook mode the three options map
directly to this judgment; in fallback mode the same judgment governs whether to re-run with
the code:

1. **PROCEED** — only when the affected list is exactly what was intended.
2. **CANCEL & REWRITE** — the usual case: the catch means the command was wrong (bad glob,
   empty var, wrong cwd, missing WHERE). The agent drops it and runs the corrected command.
   This must not interrupt the user — there is no point stopping to say "I meant to do X but
   it would break everything," when the right move is to work out what was meant and run it
   properly.
3. **UNSURE, ASK MY HUMAN** — only when genuinely unsure, when there is no safe alternative,
   or when the force-rate monitor (§10.4) warns.
4. **Hard blocks (§6)**: no PROCEED; cancel, or ask the human to run it by hand.

The spotter's job is to make the consequence unmistakable (clear DANGER header, counts, top
paths, system paths flagged, before→after perms, plain-words consequence, the common
mistake, a safer rewrite) so that this judgment is usually obvious. When it isn't, kicking
to the human is the safety valve, not the default.


### 10.8 Public, pluggable approval-hook API

The approval hook is a **public integration contract**, not a host-specific feature. Any
host — in any language — can drive shellspotter decisions through it, and anyone can register
custom handlers, middleware and rule packs. An example host integration is just the reference consumer.

**10.8.1 Stable versioned contract.**
- **Transport**: a **host-owned unix-domain socket** whose path is in `SHELLSPOTTER_HOOK`.
  The shim connects, sends one catch record, and **waits on the same connection** for one
  decision frame, then execs or refuses in place (§10.1). Newline-delimited JSON both ways.
  Never a bare fd number (B2). If the socket is absent/unreachable the shim uses code mode.
- **Catch-record JSON** carries `schema_version` (string, semver, current `"1.0"`), a
  `catch_id`, and the §10.1 fields (`level`, `command`, `argv`, `cwd`, `restricted`,
  `report`, `affected`, `consequence`, `common_mistake`, `safer_rewrite`). **No approval
  token is sent to the agent** — the host answers the open connection directly. All
  text/argv fields are redacted (§8.6) before they leave the process. New fields are only
  ever **added** within a major `schema_version`; a field is never removed or repurposed
  without a major bump; unknown fields must be ignored by consumers.
- **Decision frame**: `{"catch_id":"…","decision":"proceed|cancel|ask_human","reason":"…"}`.
  `ask_human` keeps the connection open and is later resolved by the host into a terminal
  `proceed`|`cancel` (no short timeout, §10 C3). Any other value, a closed connection, or an
  unparseable frame = **cancel**.
- **Exit codes** (host also keys on the record, not the code — M4; §14): `0` ran/allowed,
  `120` catch refused, `121` hard block, `122` spotter failure (fail-closed), `123` pre-check
  "ask", `127` real binary missing. In hook mode the shim blocks and does not exit to ask.
- **Code-mode token channels** (only when there is no socket): the agent re-runs with
  `SHELLSPOTTER_OK=<code>` (env prefix); a host that brokers it may instead pass the code on
  **stdin** JSON or a **`--resume-token`** flag. Codes are bound (argv+cwd+targets+level+
  nonce), single-use, re-verified regardless of channel, and format-allowlistable (`SS-…`,
  M9).

**10.8.2 Integration points.**
- **(a) Go library — `shellspotter/hook`.** The host runs a **decision server** on the
  socket; it does not re-exec commands. (B1: the agent sends a shell *string*, not argv — the shims
  live inside its sticky shell, so the library never needs the argv or a resume call.)
  ```go
  type Catch struct { SchemaVersion, CatchID, Level, Command, Cwd, Report string
                      Argv []string; Restricted bool; Affected Affected; SaferRewrite string }
  type Decision struct { Action string /* proceed|cancel|ask_human */; Reason string }
  type DecisionHandler interface { OnCatch(ctx context.Context, c Catch) (Decision, error) }
  // helpers:
  func Serve(ctx context.Context, socketPath string, h DecisionHandler, opts ...Option) error
  func RunShell(ctx context.Context, script string, h DecisionHandler, opts ...Option) (ExitStatus, error) // spawn a guarded shell that runs `script`; shims call back to Serve
  ```
  `Serve` answers each `catch_id` on its open connection; `RunShell` is a convenience that
  starts a shim-equipped shell and a `Serve` loop together. A handler returning an error, or
  a non-terminal `ask_human` the host never resolves, **defaults to cancel** (§10.1). The
  wait inside `OnCatch` is not charged to `fail_timeout_ms`.
- **(b) Language-neutral — CLI / JSON-over-stdio, or exec-a-handler.** Config
  `hook_command = "/path/to/handler"`: on a catch the spotter execs it with the catch-record
  JSON on stdin and reads a decision JSON on stdout (`{"decision":"proceed"}` etc.), or a
  long-lived host speaks the same newline-JSON over the `SHELLSPOTTER_HOOK` socket. This lets
  Python/Node/Ruby bots plug in with no Go. Parse failure or a dropped connection → cancel.
- **(c) Agent pre-tool-hook adapters.** Built-in `--adapter claude|cursor|codex|generic`
  translate the catch record to each framework's PreToolUse/beforeShellExecution shape
  (deny/ask/allow + reason) and map their reply back to a decision, so shellspotter drops into
  those agents' existing hook slots.

**10.8.3 Custom handlers, middleware and packs.** Handlers compose:
- **Middleware** wrap a `DecisionHandler`: structured logging, metrics, redaction, and
  **routing for `ask_human`** to Slack / chat / email / a ticket, awaiting the human's
  reply.
- **Policy auto-decisions**: a handler may auto-resolve by rule — e.g. auto-`cancel` every
  danger catch in CI (`SHELLSPOTTER_ENV=ci`), or auto-`proceed` a specific known-safe bulk
  pattern — always within the open catch, never as pre-approval.
- **Custom rule packs and protected paths** are registered either via config
  (`[paths] protect_extra`, `[commands] packs`, a `packs_dir`) or, for Go hosts, through the
  API (`hook.RegisterPack(...)`, `hook.RegisterProtected(...)`). Third-party packs ship as
  data (tiny rule tables, §12.3), so adding coverage needs no fork.


## 11. Database gate

CLI DB clients are wrapped so that **structure-destroying or unscoped** statements, and
**starting an unspotted interactive session**, require approval (hook decision or code), while ordinary
reads and scoped writes pass untouched. This is an oops gate, not a lock: the agent can
always approve what it meant.

### 11.1 Wrapped clients and input forms

| Client | Inline | stdin / here-doc | file | interactive |
|---|---|---|---|---|
| mysql / mariadb | `-e "…"` | piped SQL / `<<EOF` | `mysql db < f.sql`, `source` | REPL |
| psql | `-c "…"` | piped / `<<EOF` | `-f f.sql`, `\i` | REPL |
| sqlite3 | `sqlite3 db "…"` | piped | `.read f.sql` | REPL |
| mongosh | `--eval "…"` | piped js | script.js | REPL |
| redis-cli | `redis-cli CMD` | piped / `--pipe` | `--eval x.lua` | REPL |
| clickhouse-client (opt) | `-q "…"` | piped | `--queries-file` | REPL |
| cockroach sql (opt) | `-e "…"` | piped | `-f f.sql` | REPL |

**How a session is detected (U5).** the agent's shell has no tty, so `isatty` is unreliable. The
shim decides from argv + redirection, not a tty: a client with **no** statement-bearing flag
(`-c/-e/-q/--eval`), **no** `-f`/`--queries-file`/script path, and **no** SQL arriving on
stdin (stdin is a tty, `/dev/null`, or a closed/empty pipe) is an **interactive session**.
`psql db < f.sql` and `echo q | psql` have stdin SQL → treated as the stdin form, not a
session.

**Parsing (M11): a real SQL lexer, not regex.** The shim tokenizes with a small lexer that
understands string literals, `'…'`/`"…"` quoting, `--`/`/* */`/`/*! */` comments,
PostgreSQL dollar-quoting (`$tag$ … $tag$`), statement separators, CTEs
(`WITH d AS (DELETE … RETURNING …)`), psql `\i`/`:vars` and `\set`, and `source`/`.read`
includes (followed one level, up to the read cap). It flags the §11.2 set on the tokenized
statements, including degenerate always-true predicates (`WHERE 1`, `WHERE 1=1`,
`WHERE true`, `WHERE id IS NOT NULL`). **Input the lexer cannot parse → ALLOW + log
`sql_unparsed` (N5), not a pause** — consistent with principle 4 and avoiding false positives
on PL/pgSQL function bodies, `DELIMITER` blocks, and psql meta-commands (`\gexec`, `\i`,
`:vars`) common in migrations. A bulk pause is raised **only** when the statement *does* lex
but is genuinely ambiguous about whether a §11.2 destructive keyword applies.

**Handling per form:**
- **Inline (`-e/-c/-q/--eval`)**: lex the argument; gate per §11.2. Passes through
  byte-identically on allow (no server-mode injection, §11.4).
- **`-f`/`.read`/`\i`/`source`/script.js**: read the file (one include level) up to the scan
  cap and lex it.
- **stdin — regular file (`psql < f.sql`) (NB2)**: `pread` the first `sql_scan_kb`
  (default 256 KB), lex it, then **`lseek(fd,0,SEEK_SET)` back to 0** and `execve` the real
  client, which re-reads from the start. The bytes are not consumed, so passthrough stays
  byte-identical (§3.7). A destructive statement past the cap is a documented limit; the
  common `psql < drop.sql` is within it.
- **stdin — a PIPE (`pg_dump | psql`) (NB2)**: a pipe is not seekable, so the shim **does
  NOT scan it** — reading even one byte to peek would corrupt the restore. Piped SQL is
  treated as **target unknown → allow, with a `sql_unscanned` log line** (never a bulk
  pause that would need the bytes). This is stated here and in §3.7: shellspotter never
  forks/relays a client's stdin, so `pg_dump | psql` is never altered. "Empty pipe"
  detection is likewise dropped (it would need a read).
- **Interactive REPL / unspotted session**: never permanently prevented, but **starting one
  is itself a DANGER catch** — the shim cannot see statements typed live. The message says
  plainly there is **NO per-statement protection inside the session**, to **BACK UP FIRST**,
  and suggests the gated one-shot `-c`/`-e`/`-f` forms. The agent approves (hook or code) and
  the session opens, with the §11.4 interactive-only safe mode injected.

### 11.2 Destructive set (needs approval)

- `DROP DATABASE`, `DROP SCHEMA`, `DROP TABLE`, `DROP COLLECTION`
- `TRUNCATE`
- `DELETE` / `UPDATE` with **no WHERE**, or `WHERE 1=1` / `WHERE true`
- `ALTER TABLE … DROP [COLUMN|CONSTRAINT]`
- Mass-destructive: `FLUSHALL`, `FLUSHDB`, `db.dropDatabase()`, `drop()`,
  `deleteMany({})`, `remove({})`, `KEYS *` + `DEL` pipelines, `CONFIG RESETSTAT`,
  `SHUTDOWN [NOSAVE]`
- clickhouse: `DROP`/`TRUNCATE`/`ALTER … DROP PARTITION`; cockroach: same SQL set.

### 11.3 Not gated (passes)
Normal reads (`SELECT`, `SHOW`, `EXPLAIN`, `\dt`, `find()`), scoped writes (`INSERT`,
`UPDATE … WHERE id=…`, `DELETE … WHERE …`, `CREATE`, scoped `ALTER`), migrations that are
scoped. The gate is about *unbounded* destruction, not writing.

### 11.4 Server-side injection — interactive sessions only (prior art P0.4; fixes B5)
Server-side safe modes **change behavior**, so they are **not** applied to one-shot
`-c/-e/-f` runs (which are already gated by the §11.2 scan and must pass through
byte-identically, §3.7). They are injected **only when opening an interactive REPL** (§11.1),
where there is no per-statement gate and the session was already a danger catch the agent
approved. Even then, strictly:
- **mysql/mariadb**: inject **`--safe-updates` only**. **Never** set `sql_select_limit` or
  `max_join_size` (B5 — those silently truncate legitimate SELECTs). Note the known
  over-refusal: safe-updates also rejects an UPDATE whose WHERE is on a non-key column
  (`UPDATE t SET x=1 WHERE status='a'`); this is accepted *inside an approved REPL* only, and
  documented.
- **psql**: **append** `-c session_preload_libraries=safeupdate` to any existing `PGOPTIONS`
  (never overwrite it, B5), and only when the `pg-safeupdate` extension is present.
- **redis-cli**: no injected mode; the shim catches `FLUSHALL/FLUSHDB/SHUTDOWN/CONFIG`; docs
  recommend ACL `-@dangerous` / `rename-command` server-side.
- **mongosh**: no native safe mode; rely on the §11.2 scan + a role without `dropDatabase`.

Because this is a deliberate, documented deviation from byte-identical passthrough, it is
listed as the **one explicit exception** in §3.7 and in §25 #2b (a documented exception). It never
applies to non-interactive invocations.

### 11.5 Optional dry-run count
Where safe, the pause message includes an estimated blast radius without executing. **The
probe has its own time budget (`probe_timeout_ms`, default 1500 ms), separate from
`fail_timeout_ms`. A probe that **errors** (cannot connect) yields "row count unknown" and the
statement is still judged on its §11.2 shape. A probe that **times out** is a **catch** (§25 #4): the command does NOT run — it pauses with the normal choices (hook: PROCEED / CANCEL & REWRITE / UNSURE-ASK-HUMAN; code mode refuses with an `SS-` code), and the report says the check timed out, the count reached so far, and that a long scan likely means a very large target
(§25 #4) — never a silent allow, never a 122.** A probe makes a DB connection — this is the one place the
spotter touches the network, called out as the explicit exception to §16's "no network on
the hot path" (C4), and only on a candidate catch, never on the allow path.
- SQL `DELETE/UPDATE`: run `EXPLAIN` (preferred, no row touch) or `SELECT count(*)` with the
  same WHERE inside `BEGIN; … ; ROLLBACK` when a probe connection is allowed; else
  "row count unknown."
- Never probe for `DROP`/`TRUNCATE`: show the table name and, if cheap, catalog-stat rows.

### 11.6 Message
Same style and one-time code as §10. Example:
```
shellspotter: DANGER — unscoped DELETE on production
command : psql -c "DELETE FROM orders"
target  : database "shop" table "orders"  (~1,240,000 rows, EXPLAIN)
effect  : deletes EVERY row (no WHERE clause)
mistake : missing WHERE — did you mean  DELETE FROM orders WHERE status='cancelled' ?
approve : SHELLSPOTTER_OK=SS-9QX2 <command>   (valid ~2 min, single use, bound to this command)
```
Interactive-session catch example:
```
shellspotter: DANGER — opening an UNGUARDED psql session
effect  : inside this session shell-spotter CANNOT check individual statements.
          There is NO per-statement protection once you are in the REPL.
advice  : BACK UP FIRST. Prefer one-shot, gated forms:
            psql -c "…"      or   psql -f script.sql
server  : safe-updates mode is still injected (WHERE-less UPDATE/DELETE refused).
approve : SHELLSPOTTER_OK=SS-4KD8 psql <args>   (valid ~2 min, single use)
```

---

## 12. git, overwrite and infra coverage

### 12.1 git (prior art P0.1 — top real-world agent accident), keyed on effects
Wrap `git` with a subcommand table. Catches are **keyed on uncommitted / unpushed state at
exec time** (effects-based, not text):
- `git reset --hard`, `git checkout -- <paths>` / `git restore <paths>`, `git clean -fd[x]`:
  catch **only if** `git status --porcelain` shows uncommitted changes that the op would
  discard; show the count/list of files that would be lost. Clean working tree ⇒ allow
  silently. The `git status` probe runs under `probe_timeout_ms` (not `fail_timeout_ms`); on
  a slow/huge repo that **times out** it becomes a **catch** (§25 #4): the command does NOT run — it pauses with the normal choices (hook: PROCEED / CANCEL & REWRITE / UNSURE-ASK-HUMAN; code mode refuses with an `SS-` code), and the report says the check timed out, the count reached so far, and that a long scan likely means a very large target (§25 #4), never a 122.
- `git stash drop` / `git stash clear`: catch if it drops stashes (show how many).
- `git push --force` **without** `--force-with-lease`: catch; suggest `--force-with-lease`.
  With lease ⇒ allow.
- `git branch -D`, `git filter-repo`, `git push :branch` / `--mirror`: catch (force).
- `.git/` directory as a delete/overwrite target ⇒ protected (§5.1).
All approvable; none hard-blocked. Clean, routine git (commit, pull, merge, normal push,
checkout of a branch) passes untouched.

### 12.2 Overwrite class (prior art P1.8)
`cp/mv/install` onto an existing destination (with **or** without `-f` — `mv a b` silently
replaces `b`), `ln -sf`, `>`/`>|` onto an existing file (pre-check, redirect form only),
`tar --overwrite`/`--recursive-unlink`, `unzip -o`, `sed -i`, `perl -pi`, `truncate -s0`,
`shred`: treated as writes that destroy existing content. Catch when the destination is a
**protected path** (§5.1, force) or when **> 100 existing files** would be clobbered (bulk).
Overwriting non-protected files under threshold passes.
**Remote/un-lstat'able targets (M14):** an `rsync`/`scp` **remote** target (`host:/path`,
`rsync://`) or any operand the shim cannot `lstat` is treated as *target unknown*: a
`--delete` to a remote is a **bulk pause** (it can't be counted), a plain remote copy passes.
This is documented, not silently allowed-as-safe.

### 12.3 Infra pack (ON by default; prior art P1.10)
On by default everywhere; a wrapper is installed **only for a tool that exists on the
system** (resolved at install and re-checked by `shellspotter install --refresh` / `doctor`),
so a box without, say, terraform simply has no terraform shim and pays nothing. The rules
are a tiny config table. Checks that need live state (listing docker volumes, reading a
terraform plan's deletions, naming the kube namespace) run only where the tool is present,
only on a candidate catch, never on the allow path, and **under `probe_timeout_ms` (N9)** — a
timeout is a **catch** (§25 #4): the command does NOT run — it pauses with the normal choices (hook: PROCEED / CANCEL & REWRITE / UNSURE-ASK-HUMAN; code mode refuses with an `SS-` code), and the report says the check timed out, the count reached so far, and that a long scan likely means a very large target (§25 #4), never a silent allow and never a 122. Catches (danger level), with the
affected resource named:
- `docker rm -v`, `docker volume rm`, `docker system prune -a --volumes`,
  `docker compose down -v`
- `kubectl delete` with `--all`/`-A`/namespace scope, `helm uninstall`
- `terraform destroy`, `terraform apply -destroy`, `apply -auto-approve` (on a plan with
  deletions)
- `aws s3 rm --recursive`, `gsutil rm -r`, `gcloud … delete`
- `crontab -r` (easy fat-finger for `-e`), `systemctl stop/disable` of a running unit,
  `iptables -F`, `userdel -r`
- Power commands (`reboot`/`shutdown`/`halt`/`poweroff`/`systemctl poweroff`): molly-guard
  style — over an SSH session the report names the host and, in hook mode, PROCEED is gated
  on the agent echoing the **hostname** back in its decision `reason`; in code-mode fallback
  the hostname is folded into the code's HMAC binding (so the code is host-specific), not a
  bare code.

---

## 13. Config format

TOML, layered: built-in defaults → **root-owned** `/etc/shellspotter/config.toml` → user
`~/.config/shellspotter/config.toml` → nearest `.shellspotter.toml` up to the project root
(`.git`/`.shellspotter-root`). **There is NO `SHELLSPOTTER_CONFIG` env override** (dropped per
C2). The system file is the authority. Lower (agent-writable) layers are governed by an
**explicit allow-list, not a deny-list (N1)**: a user `~/.config` or project
`.shellspotter.toml` may set **only** these keys, and only in the tightening direction —
- `[paths] protect_extra` (add protected paths; cannot remove any),
- `[thresholds] *` **lowered only** (a lower layer may make thresholds stricter, never raise
  them — raising is a system-file-only change, closing the §4.2 "raise to infinity" hole).

**Every other key is ignored from lower layers** and honored only from the root-owned
`/etc/shellspotter/config.toml`: `fail`, `mode`, `[commands] disable`/`packs`,
`[commands.build_output]` (names / exemption), `[approval] mode`, `[force_rate]`, `[limits]`,
`[redact]`, `[log]`, and `allow_extra`. So an agent-writable file cannot
`disable=["rm"]`, add `build_output.names=["src","data"]`, switch to forgeable `mode="code"`,
turn off logging or the force-rate monitor, or widen `allow_extra`. `shellspotter config
--explain` prints the merged config and, per key, its source and **whether it was honored**.

```toml
# /etc/shellspotter/config.toml  (all keys optional; shown with defaults)
mode = "standard"              # standard | strict | paranoid (prior art P2.12). NOTE: there
                               # is no "off" mode and no env var that disables the spotter;
                               # the spotter can only be turned off/reconfigured HERE, in a
                               # config file the agent cannot write (§10.3).
fail = "closed"                # closed | open (honored only from the root-owned file).
                               # DEFAULT closed: a CRASH, a BAD/UNREADABLE CONFIG, or a
                               # MISSING/UNREADABLE KEY => command NOT run (§14 code 122).
                               # A check TIMEOUT is NOT a 122 failure: per §25 #4 it
                               # is a CATCH -> pause w/ choices; code mode SS- code; never allow.
fail_timeout_ms = 2000         # classification self-budget. On expiry: CATCH (§25 #4), NOT a
                               # fail. EXCLUDES the hook decision wait and ask_human wait.
probe_timeout_ms = 1500        # §11.5 DB probe budget; expiry => CATCH (§25 #4), not "unknown"
walk_timeout_ms  = 1500        # §9 recursive walk budget; expiry => CATCH (§25 #4)

[thresholds]
bulk_targets        = 100
tree_files          = 2000
tree_bytes          = "1GB"
recursive_perm_files = 500
overwrite_files     = 100

[approval]
mode           = "hook"         # "hook" (preferred, §10.1) | "code" (fallback, §10.2) |
                                # "auto" (hook if SHELLSPOTTER_HOOK socket present, else code)
code_ttl_sec   = 120            # one-time code expiry (~2 min); applies to code mode
code_prefix    = "SS-"          # redactor allow-list format (M9)
decision_timeout_sec = 300      # code-mode / unclear-answer default CANCEL. Does NOT apply to
                                # ask_human, which waits for the human (C3), nor to the hook
                                # block itself (that is the host's session lifetime).
# HMAC key for code mode is generated per-install at $SHELLSPOTTER_HOME/key (mode 600). For
# an unforgeable key, install with a dedicated spotter user / setuid helper (§10.2 M1, U3).

[force_rate]                    # danger-approval tripwire (§10.4); warns, never blocks
enabled   = true
max       = 5
window_min = 10

[paths]
protect_extra   = ["/data/prod/**", "/srv/zeldafiles/**",
                   "~/.myagent/**", "~/src/myrepo/**"]   # NB1: the runtime registers its
                   #   live data dir and repo at install so a wrong-cwd rm pauses
allow_extra     = ["/scratch/**"]       # never flag these
marker_file     = ".shellspotter-protect"

[commands]
disable = []                    # e.g. ["dd"] to stop wrapping a command
packs   = ["files", "git", "db", "infra", "power"]   # ALL on by default; a shim is created
                                # only for a command that exists on the box (§3.3, §12.3)

[commands.build_output]        # §4 NB1 tree-delete exemption: ONLY these dir names, and
                               # ONLY when they sit inside a project root (nearest
                               # .git/.shellspotter-root). It never exempts the repo root,
                               # source, or data. /, /etc, any $HOME and mount roots are
                               # NEVER project roots. Everything else uses files OR bytes.
names = ["node_modules","dist","build","target",".next",".cache","__pycache__","vendor"]

[db]
inject_safe_mode_interactive = true  # §11.4: safe-updates in REPLs ONLY; never on -c/-e/-f;
                                     # never sql_select_limit/max_join_size; PGOPTIONS appended
dry_run_counts = true
sql_scan_kb    = 256                 # §11.1 NB2: scan first N KB of a REGULAR-FILE stdin
                                     # then lseek back; PIPED stdin is never scanned (allow+log)

[limits]                        # §6.1 B6: cgroup scope, NOT per-UID rlimits. Default OFF.
enabled    = false              # on the host left to the host; shellspotter sets nothing
tasks_max  = 0                  # 0 = unset. When enabled: systemd-run --scope -p TasksMax=
memory_max = ""                 #            and -p MemoryMax= (cgroup, not RLIMIT_AS)

[redact]                        # §8.6 built-in secret redactor; MANDATORY, cannot be disabled
                                # covers pw flags, scheme://user:pw@ URIs, *_TOKEN/_SECRET/_KEY
                                # env, auth headers, and SQL password literals (N4)
extra_patterns = []             # host adds more; the host also runs its own redactor (B8)

[log]
path  = "~/.local/state/shellspotter/spotter.log"
level = "catch"                 # catch | all | off. argv ALWAYS redacted (§8.6); env NEVER
                                # logged; at "all", SQL/-c/-e/here-doc BODIES are never logged,
                                # only statement shape (N4). "all" rotates (log_max_mb, keep 5)
log_max_mb = 50
```

A **per-project** `.shellspotter.toml` typically only tunes `[thresholds]` and adds
`[paths] protect_extra`. Because loosening keys are honored only from the root-owned system
file (and there is no env override), an agent running as its own user cannot weaken the
spotter.

---

## 14. Exit codes

Shellspotter uses **high, distinct exit codes (120–125)** so a host never confuses a spotter
outcome with a wrapped tool's own exit status (M4: `psql`/`ls`/`diff`/`grep` legitimately
exit 2 or 3). **A host must key on the catch record / socket message, not on the exit code
alone.** In **hook mode (§10.1) the shim blocks and then `execve`s or refuses in place — it
does not exit to ask**, so there is no "awaiting decision" exit code; the former code 11 is
removed.

| Code | Meaning |
|---|---|
| (passthrough) | On allow, the shim `execve`s the real command, so the command's own exit code is returned unchanged. |
| 120 | **Catch refused** (hook CANCEL, or code-mode catch awaiting re-run with a code). Not executed. The report/record carries the detail. **A walk/probe-timeout catch (§25 #4) refuses here too** — code mode prints an `SS-` code; it never allows the command through. |
| 121 | **Hard block (§6).** Never executed; no PROCEED. |
| 122 | **Spotter failure under `fail = "closed"` (default): command NOT run.** Covers only a spotter **crash**, an **unreadable/invalid config**, or a **missing/unreadable key** — a bounded, operator-fixable set (B7). A **classification/walk/probe timeout is NOT a 122 failure** (it is a crash/config/key-only set): per §25 #4 a check that runs too long is instead a **catch** — the command pauses with the normal choices (code mode refuses with an `SS-` code), never a silent allow. Message: `shellspotter failed; command not run; see log; a human can run it by hand (/bin/<cmd>) or fix the spotter`. With the non-default `fail = "open"` the command instead runs and returns its own code. |
| 123 | Pre-check "ask" result in generic adapter mode (host should prompt). |
| 127 | Real binary not found behind the shim (same as a normal shell). |

The pause/block/failure message always goes to **stderr**; stdout is untouched so pipelines
aren't corrupted. Note code **122 is a safe stop, not an allow** (§1.3.4, §1.3.6). The
decision wait in hook mode and the human-wait of ASK MY HUMAN are **not** counted against
`fail_timeout_ms` and never produce a 122.

---

## 15. Logging format

JSON Lines, one object per event, default `~/.local/state/shellspotter/spotter.log`.
**Every `argv`/`cmd` field is redacted by §8.6 before it is written; the environment is NEVER
logged** (B8). No file contents or SQL *values* are logged, only the statement shape. Home
paths may be further masked with `log.redact_home = true`. The log can rotate by size
(`log_max_mb`, keep 5) which matters under `level = "all"` (U7). **Under `level = "all"` the
log records each wrapped command's name + redacted flags/targets only — it NEVER stores a
`-c`/`-e`/`--eval` SQL body or a here-doc body (statement *shape* only), so a password
literal or token inside a query body cannot land in the log (N4).**

```json
{"ts":"2026-10-14T14:40:12-04:00","event":"decision","level":"danger","cmd":"chmod",
 "argv":["chmod","-R","600",".*"],"cwd":"/root","case":"A",
 "reason":"target realpath is parent of cwd (recurses into /)","targets":3891,
 "top":["/root/.ssh/authorized_keys","/etc/passwd"],"decision":"cancel",
 "mode":"hook","decided_by":"agent","host":"example-host","agent":"example-agent","v":"3.0.0"}
```

Every resolved catch records the **decision** (`proceed`|`cancel`, incl. one reached via
`ask_human`) and **who made it** (`decided_by`: `agent` | `human` | `default` for
unclear/dropped→cancel). Events: `allow_near` (within 20% of a threshold, tuning), `catch`,
`block`, `decision` (with `mode`, decision, `decided_by`, option chosen), `code_rejected`
(expired/reused/mismatch), `inherited_ok` (an ignored `SHELLSPOTTER_OK` that wasn't a valid
code), `ask_human` (routed to the human), `force_rate_alert`, `parse_fallthrough`,
`spotter_error` (a fail-closed stop, with the reason). `shellspotter log --since 7d --summary`
prints the §4.3 tuning histogram.

---

## 16. Performance

- Pass-through target **< 5 ms p95**, **< 1 ms** typical for non-recursive ops (one PATH
  resolve cached by PATH-hash, argv parse, a handful of `lstat`s, then `execve`). Zero
  cost for unwrapped commands (they never touch the shim).
- Recursive walks are bounded (§9): cost O(threshold), independent of tree size.
- **No network on the hot path, no fork for the real command** (uses `execve`, replacing the
  process). The spotter's *only* outbound calls are **live-state checks, all under the shared
  `probe_timeout_ms` budget (N9)**: the §11.5 DB row-count probe **and** every §12.3 infra
  live-state lookup (docker volume listing, `terraform plan` deletions, kube namespace
  resolution, `git status`). They run **only on a candidate catch**, never on the allow path,
  and a timeout is a catch (§25 #4), never a 122. This is the
  explicit exception to "no network on the hot path" (C4).
- PATH-resolution and config are memoized; config is read once per process.
- `shellspotter test --bench` reports measured overhead and fails CI if p95 > 5 ms.
- **Fail-closed health check (no timers — C9).** Because a spotter failure stops the command
  (§14), a broken spotter would halt wrapped commands. `doctor` runs a liveness probe (a
  canned allow + a canned catch) and reports red/green. Per the operator's standing no-automation
  rule, **nothing runs `doctor` on a timer**: the host runs it **at session spawn, at deploy,
  and on demand**, and surfaces a red result to the operator. The classification self-budget
  (`fail_timeout_ms`) bounds any single hang; per §25 #4 a check that times out becomes a **catch** (pause with choices; code mode refuses with an `SS-` code), never a silent allow and never a 122.

---

## 17. Install / uninstall / CLI

### 17.1 Install
`shellspotter install [--system|--user] [--shell bash,zsh] [--packs ...] [--refresh]
[--sudoers]`:
1. places the static Go binary (CGO off); 2. generates the per-install HMAC key
(`$SHELLSPOTTER_HOME/key`, mode 600 — see U3 below for who owns it); 3. creates the shim dir
and **one symlink per wrapped command that exists on the box** — all packs on by default
(§3.3, §12.3); 4. configures Layer 1 as a **host pre-check** and prepends the shim dir to
PATH **in the agent spawn env only** — **it does NOT set `BASH_ENV` and installs no DEBUG
trap** (M6, §3.5); 5. **only with `--sudoers`**, writes the opt-in, `visudo -c`-validated
`/etc/sudoers.d/shellspotter` secure_path edit (default off, §3.4 B7); 6. runs
`doctor`.
`--refresh` re-scans which wrapped tools are present (e.g. docker installed later) and
adds/removes shims. Idempotent. `uninstall` reverses every step (shims, PATH edit, key,
nonce store, and any sudoers drop-in); nothing is left on PATH.

**Key, nonce store and force-rate state (U3).** `$SHELLSPOTTER_HOME` defaults to
`/var/lib/shellspotter` for a system install (owned by a dedicated `shellspotter` user or
root, so the agent's uid cannot read the key — the unforgeable-code path, §10.2 M1) and to
`~/.local/state/shellspotter` for a per-user install (readable by that user — the honest
limit). It holds the HMAC key, the **spent-nonce store** (an append-only file with its own
lock, GC'd by dropping entries past `code_ttl_sec`), and the force-rate counter. When root
and a normal user both run the spotter, each uses its **own** `$SHELLSPOTTER_HOME`/key/config;
a sudo→root transition therefore reads root's config, which must exist (else §14 122) — the
install sets up both.

### 17.2 CLI
| Command | Purpose |
|---|---|
| `shellspotter check -- <cmd...>` | Classify a command and print the decision/message **without running it** (exit 0 allow / 120 catch / 121 hard block). For agents and CI. |
| `shellspotter explain <case>` | Expand a catch case into the full reasoning + safer rewrite. (Codes themselves are opaque one-time HMACs and are not "explained".) |
| `shellspotter test [--bench]` | Run the bundled test suite (§19): bypass repros, must-pass list, look-alikes, fork-bomb containment, perf. |
| `shellspotter precheck` | Hook mode (§3.6); host adapters. |
| `shellspotter doctor` | Verify shims are on PATH in the real spawn env, the HMAC key is present/readable, hook fires, sudo covered, limits set, **present-tool shims match what's installed (`--refresh` hint)**, and a liveness probe (allow+catch) passes so a fail-closed spotter isn't silently blocking (§16). Green/red per check. |
| `shellspotter scan <dir>` | CI mode: scan scripts in a repo for would-be catches (prior art P2.14). |
| `shellspotter log` / `config --explain` / `init <shell>` | as described above. |

---

## 18. Edge cases

| Case | Handling |
|---|---|
| Symlinks | Walk does not follow (matches `rm -r`); a command-line operand that *is* a symlink to a protected path is resolved and caught (§5.4.1). Flag `chmod/chown -R` with `-L/-H` (follows symlinks) as higher risk. |
| Bind mounts / crossing devices | Detect device change during the walk; crossing a mount root is a §7A catch; suggest `--one-file-system`. |
| NFS / network FS | Treated as normal paths; the bounded walk still applies (and matters more — slow stat). Size short-circuit avoids walking huge NFS trees. |
| Case-insensitive FS (macOS/APFS, Windows) | Protected-path matching is case-folded on such volumes so `/ETC` matches `/etc`. |
| Unicode / zero-width / `$'\x72m'` tricks | Layer 1 normalizes NFC and strips zero-width before matching; Layer 2 is immune (it sees the resolved argv regardless of how the name was spelled, as long as PATH lookup was used). |
| Very long arg lists / `ARG_MAX` | Count/classify by streaming operands; never materialize the whole list in memory beyond the threshold needed to decide. |
| Hardlinks | Counted as the files they are; note in docs that deleting one hardlink doesn't free data. |
| Absolute-path calls (`/bin/rm`) | Layer 2 blind spot; Layer 1 text pre-check flags `/bin/rm -rf` forms; documented non-goal otherwise. |
| Interpreters (`python -c`, `perl -e`) | Layer 1 recursive inline-script scan (§3.6) flags obvious `rmtree`/`unlink`; otherwise documented non-goal (§2.2). |

---

## 19. Test plan

All tests run against **real bash** (and zsh/sh in a matrix), not mocked, in a disposable
container with tripwire files, so a bypass that would actually delete is proven caught.

### 19.1 Harness
`shellspotter test` builds a throwaway rootfs fixture (fake `/etc/passwd`, `~/.ssh/`,
setuid binary, `/tmp` sticky dir, a 3,000-file tree, a git repo with uncommitted changes,
sqlite/postgres fixtures) and asserts the spotter's decision for each case **and** that the
real filesystem is untouched when a catch fires.

### 19.2 Must-CATCH — known bypass repros
Each caught after expansion (danger level unless noted). The point: because bash expands
first and the PATH lookup then reaches the shim, the *verb-hiding* tricks are irrelevant —
the shim sees the real target either way.
- Compound/hidden verb: `(rm -rf ~)`, `{ rm -rf ~; }`, `if true; then rm -rf ~; fi`,
  `! rm -rf ~`
- cd gaps: `pushd / && rm -rf *`, `command cd / && rm -rf *`, `(cd / && rm -rf *)`,
  `{ cd ~; rm -rf ./*; }`
- Piped/nested shells where the inner verb resolves via PATH to the shim (bash itself is NOT
  wrapped — the inner `rm` is): `env X=1 bash -c 'rm -rf ~'` (PATH inherited into the child),
  `echo 'rm -rf ~' | sh`
- Wrappers: `timeout 5 rm -rf ~`, `doas rm -rf /etc`, `setsid rm -rf ~`,
  `nice -n 10 rm -rf ~`, `ionice -c 3 rm -rf ~`, `sudo xargs rm` (via sudo shim)
- Variable-built: `c='rm -rf'; $c ~`, `c='rm -rf ~'; eval "$c"`,
  `x=a; rm -rf ${x/a/$HOME}`, `${x#..}`, `f(){ rm -rf "$1"; }; f ~`
- Empty var: `d=$(mktemp -d); rm -rf "$D"/*` (unset `$D` → `/*`), caught by the
  realpath/`/`-sweep rule (§5.4.3), independent of `globskipdots`
- The incident: `chmod -R 600 .*` in `/root` — caught by target-realpath = parent-of-cwd
  (§5.4.3), **not** by seeing the literal `.*` (so it holds on bash ≥5.2, U8)
- sudo direct verb (via the sudo shim's inner-argv scan, or the opt-in secure_path edit):
  `sudo rm -rf /etc`
- find/rsync internal (single op): `find / -name '*.conf' -delete`,
  `find / -name '*.o' -exec rm {} +`, `rsync -a --delete empty/ /etc/`
- git: `git reset --hard` with dirty tree, `git clean -fdx` with untracked files,
  `git push --force` (no lease)
- DB: `psql -c "DELETE FROM orders"`, `mysql -e "DROP DATABASE shop"`,
  `redis-cli FLUSHALL`, `mongosh --eval 'db.users.deleteMany({})'`; lexer cases
  `WITH d AS (DELETE … )`, `WHERE 1=1`, dollar-quoted bodies, `/*! */`
- DB interactive: `psql`/`mysql` with no `-c`, `redis-cli` with no command, `mongosh` with
  no `--eval` → DANGER before the session opens; opens after approval; safe-mode injected
- Fork bombs: classic `:(){ :|:& };:` and `bomb(){ bomb|bomb& };bomb` (hard-block, text,
  command-position only)

**Documented limits — NOT in must-catch (C7, honest):** `for f in *; do rm -rf "$f"; done`,
`find … -exec rm {} \;` (per-`{}` form), and plain `xargs rm` call the real command once
per item, so each sees one target; caught only if that single item is protected/large.
`sudo bash -c '…'` is a **documented limit, not must-catch (N7):** the sudo shim sees `bash`
(not wrapped) and its inner-argv scan only covers the hard-block list, so the inner `rm`
inside the `-c` string is reached only when the opt-in `--sudoers` secure_path edit is on.
These are listed as limits in §2.2, with a test asserting the *documented* behavior (each
per-file invocation of a non-protected target passes), not a catch.

### 19.3 Must-PASS — the everyday list (zero false positives)
≥ 120 commands that must pass **silently**, including: `ls -la`, `grep -r foo .`,
`cat f`, `find . -name '*.go'`, `git add *.go`, `git commit`, `git pull`, `git push`,
`git checkout -b x`, `tar -czf a.tgz src`, `make`, `go build ./...`, `npm ci`,
`rm -rf node_modules`, `rm -rf build dist target .next`, `rm ~/*.log`, `rm /tmp/*.png`,
`cp report.pdf ~`, `cp -r src/ .`, `mv ../a .`, `rsync -a src/ dest/`,
`chmod +x run.sh`, `chmod -R 755 ./site`, `chmod 644 index.html`,
`d=$(mktemp -d); rm -rf "$d"`, `find . -name '*.tmp' -delete` (small),
`psql -c "SELECT …"`, `mysql -e "UPDATE t SET x=1 WHERE id=5"`, `sqlite3 db ".tables"`,
`redis-cli GET k`, `docker ps`, `kubectl get pods`.

### 19.4 Look-alikes (hard-block must not over-match)
`rm -rf ./build`, `rm -rf ~/tmp`, `rm -rf /tmp/x`, `chmod -R 755 ./site`,
`dd if=a of=b` (regular files), `mkfs` mention inside an echo string → all run normally.

**M5 — hard blocks match command position only, never quoted/argument text:**
`git commit -m "revert the rm -rf ~ change"`, `grep 'rm -rf /' script.sh`,
`echo "do not run rm -rf /"`, `history | grep ':(){ :|:& };:'`, and a file literally named
`rm -rf ~` passed as an operand → **all run normally** (the destructive string is data, not a
command in command position).

### 19.4b Threshold rule (B4 / NB1 — files OR size, build-output exemption)
- A recursive delete of **>2,000 files** under threshold size → **catch** (count arm).
- A recursive delete **>1 GB** but few files → **catch** (size arm). The two arms are **OR**,
  not AND (NB1).
- `rm -rf node_modules` / `rm -rf target` **inside a project root** → **pass** (build-output
  exemption), even over threshold.
- The same build-dir *name* at `/`, `/etc`, directly under `$HOME`, or at a mount root →
  **not** exempt (those are never a project root, NB1) → judged by the OR rule.

### 19.4c Protected-path matching (B3 — node + direct children, not prefix)
- `rm ~/notes.txt`, `rm /var/tmp/x`, `rm /opt/app/build/x` → **pass** (a single non-protected
  file; a protected FHS/home dir matches the node and its direct-children sweep, **not** every
  descendant by prefix).
- `rm -rf ~` , `rm -rf /etc`, `rm *` directly inside `$HOME` or `/etc` → **catch** (node /
  direct-children sweep of a protected dir).
- `rm -rf ~/.myagent` (and the runtime's repo path) → **catch**: the runtime registers them as
  `protect_extra` with a recursive `/**` row (NB1), so they match at any depth.

### 19.4d Transparent-passthrough differential (2b)
On an allowed command the executed argv is **byte-identical** to the user's (argv[0]
preserved), verified against a recorded `execve` for hostile filenames (spaces, newlines,
globs, leading `-`). The one allowed deviation is the §11.4 interactive-REPL safe-mode
injection (a documented exception).

### 19.5 Performance
`--bench` asserts p95 pass-through < 5 ms and recursive-walk cost bounded by threshold on
a 1M-file tree.

### 19.6 Fail-closed behavior
- Spotter binary made to crash / return garbage → wrapped command does **not** run, exit
  122, message shown, `spotter_error` logged.
- Unreadable/invalid config, or missing/unreadable key → exit 122, not run.
- A **walk timeout** on a huge/slow tree → **catch** (§25 #4): command NOT run, pause with the
  three choices, report shows "check timed out", the partial count, and the large-target hint;
  code mode prints an `SS-` code. **Never** an allow, **never** a 122.
- A **DB-probe timeout** and a **`git status` / live-state probe timeout** → the same catch
  (§25 #4), not "unknown-and-allow".
- A probe/connect **error** (not a timeout) still yields "row count unknown" and judges on
  §11.2 shape; the hook decision wait and ask_human wait never produce a 122.
- With `fail = "open"` the crash/config/key cases instead run the real command (opt-in test).
- **Resource backstop (B6):** with `[limits] enabled=true` a fork bomb is bounded to its
  systemd scope/cgroup with no sibling-process failures; with the default `false` the
  spotter sets **no** rlimits (assert `ulimit -u`/RLIMIT_AS untouched; large-vmem `go build`/
  Node/Chrome still start).
- `doctor` liveness probe goes red when the spotter is broken (run at spawn/deploy/on-demand,
  never on a timer, C9).

### 19.7 One-time code binding
- A valid code approves the **identical** command; the real op then executes once.
- Code reused a second time → rejected (`code_rejected`, single-use).
- Code used after `code_ttl_sec` → rejected (expired).
- Same code with any argv/cwd/target change → rejected (binding mismatch); a new report +
  new code is issued.
- An **exported** `SHELLSPOTTER_OK=force`/`=1`/stale code in the environment → ignored,
  `inherited_ok` logged (§15), command still caught (no env-var disable).
- Force-rate monitor: after `max` danger approvals in `window_min`, the next report carries
  the "STOP and check with your human" line and logs `force_rate_alert`; it still does not
  block.

### 19.8 Infra present-only + packs
- On a box without docker/kubectl/terraform, no such shim exists and those commands run
  with zero overhead; after installing docker, `install --refresh` adds the shim.
- With the tool present, `docker system prune -a --volumes`, `kubectl delete ns x`,
  `terraform destroy`, `aws s3 rm --recursive`, `crontab -r` are caught; `docker ps`,
  `kubectl get pods` pass.
- No env var disables any pack; only config does.

### 19.9 Interactive approval hook protocol
- On a catch the shim connects to the `SHELLSPOTTER_HOOK` socket, sends a valid
  `schema_version:"1.0"` catch record, and **blocks** in place (does not exit); schema fields
  present and well-formed; nothing is written to a bare fd 3 (B2).
- **PROCEED** with the returned token → the identical command runs exactly once; token then
  rejected on reuse (single-use).
- **CANCEL** → shim refuses in place, exit 120, `decision`=cancel logged.
- **ASK MY HUMAN** → command held (not run); host-human path invoked; human-proceed runs the
  same bound command; expired token is re-verified against live binding before running.
- **Default-cancel** on: decision timeout (`decision_timeout_sec`), an unparseable/unclear
  answer, and any hook error.
- **Hard block**: record has `level:"hardblock"` and offers no PROCEED option; PROCEED token
  for a hard block is refused.
- **Binding**: a token for one catch is rejected on any argv/cwd/target change, after expiry,
  or reused; no pre-approval (a token minted for a future command does not exist).
- **Force-rate**: N agent PROCEEDs on danger catches in the window trip `force_rate_alert`
  and the STOP line; a human PROCEED does not count.
- **Fallback parity**: with no hook present, `mode="auto"` falls back to codes and the same
  catches resolve via `SHELLSPOTTER_OK=<code>`.
- Log asserts `decided_by` is `agent` / `human` / `default` as appropriate.

### 19.10 Transparent passthrough (differential + fuzz)
Proves §3.7: on the allow path the spotter is invisible.
- **Differential harness**: run each command twice — once through the shims, once with the
  shim dir off PATH — and assert **byte-identical stdout, byte-identical stderr, identical
  exit code**, and (for the spotter's own output) nothing added on a pass.
- **Argv fidelity**: a wrapper built in test mode dumps the `argv` it would `execve`; assert
  it equals the shell-produced `argv` element-for-element, byte-for-byte, including
  `argv[0]`.
- **Hostile filenames / inputs** covered: names with spaces, newlines, single/double quotes,
  backslashes, unicode (NFC/NFD, zero-width, RTL), leading dashes (`-rf`, `--foo` as a
  filename after `--`), globs kept literal inside quotes, `$'\x..'` ANSI-C strings,
  NUL-separated `find -print0 | xargs -0`, very long arg lists near `ARG_MAX`, pipelines,
  here-docs/here-strings on stdin.
- **Streams & control**: stdin streaming (large piped input passes through unbuffered);
  SIGINT/SIGTERM delivered to the real process and reflected in exit status; non-zero exit
  codes preserved; `argv[0]`-sensitive multicall (busybox) behaves identically.
- **Env fidelity**: child environment equals parent minus only the spotter-internal vars;
  nothing else added or reordered in a way the child can observe.
- **Property/fuzz test**: generate random filenames (random bytes excluding `/` and NUL,
  random lengths, random unicode) and random safe operations (`ls`, `cat`, `cp` within a
  temp dir); assert the differential invariant holds for every generated case. Seeded and
  reproducible; runs a bounded iteration count in CI, longer nightly.

### 19.11 Public API / contract stability
- **Schema stability**: a golden `shellspotter.catch/1` record is validated against the
  published JSON schema; a snapshot test fails if any field changes shape without a
  `schema_version` bump; consumers ignore an injected unknown field (forward-compat).
- **Exit-code contract**: assert the documented codes (0/120/121/122/123/127) for allow,
  catch, hard-block, spotter-failure, ask, missing-binary; assert there is **no**
  awaiting-decision code (hook blocks in place, M4) and that none collide with a wrapped
  tool's own 2/3.
- **Decision values**: only `proceed|cancel|ask_human` accepted; an unknown decision string
  → treated as cancel.
- **Transport & concurrency**: catch record + decision are newline-JSON over the
  `SHELLSPOTTER_HOOK` socket, never a bare fd (B2); several shims blocking at once (xargs -P)
  each get the right `catch_id`; a dropped connection defaults to cancel.
- **Code-mode channels**: a `proceed` code via env prefix, via stdin JSON, and via
  `--resume-token` all run the identical command; each rejects a tampered/expired/reused code.
- **Handler errors default to cancel**: a Go `DecisionHandler` returning an error, a
  `hook_command` that exits non-zero / emits unparseable output / drops the connection, and an
  unclear decision all resolve to **cancel**, command not run. `ask_human` is **not** cancelled
  by a short timeout (C3).
- **No secrets leak (B8)**: a catch on `mysql -pS3cret` / `psql postgres://u:pw@h/db` /
  `PGPASSWORD=… psql` produces a redacted record, log line and ask_human message; env is never
  logged; the `SS-` code format survives redaction (M9).
- **Restricted turns (M8)**: a `restricted:true` catch offers no PROCEED.
- **Adapters**: claude/cursor/codex/generic adapters emit each framework's expected shape
  and map its reply back to the right decision.
- **Policy/middleware**: an auto-cancel-in-CI policy cancels every danger catch; a logging
  middleware records a `decision` event with `decided_by`; a custom registered pack/path
  produces a catch.

---

## 20. Documentation plan

Ships with the product so it can open-source cleanly.
1. **README.md** — what it is / is not (incl. the §2.3 honest-limits statement), 60-second
   install, the two-layer model, screenshots of a catch, link to sandboxes as the real
   boundary.
2. **man pages** — `shellspotter(1)` (CLI), `shellspotter(5)` (config), `shellspotter(7)`
   (concepts: catch cases, levels, tokens).
3. **CONFIG.md** — every key, default, and layer precedence (generated from §13).
4. **INTEGRATION.md** — wiring into an agent host. Covers PATH/`BASH_ENV`, sudo
   secure_path, containers, `doctor`, and the **generic agent-instructions block** below.
   Documents the **public approval-hook API (§10.8)** as the primary surface, with **minimal
   working examples in Go, Python and shell**:
   - *Go*: implement `hook.DecisionHandler.OnCatch`, then `hook.Serve` the decision socket (or
     wrap a child via `hook.RunShell`) — there is no `hook.Run`.
   - *Python*: a `hook_command` script reading the catch-record JSON on stdin and printing
     `{"decision": "..."}` on stdout.
   - *Shell*: a one-file `hook_command` that auto-cancels in CI and otherwise prints the
     report and reads a choice.
   Plus the catch-record schema, exit codes, decision values, the socket decision transport
   (and the code-mode `confirm` fallback), the
   Claude/Cursor/Codex adapters, and how to register custom handlers, middleware
   (logging / Slack-chat-email ask_human routing / policy auto-decisions) and rule
   packs / protected paths. A **"Reference integration: the host runtime"** section (mirrors INTEGRATION.md)
   walks the parts of the host runtime's code that matter — where the shell tool runs commands under
   the spotter, how a catch pauses the tool call and presents the three choices, how
   `ask_human` routes to the owner, and how a decision resumes the command — with the
   the host runtime-specific names clearly labeled as examples.
5. **THREATMODEL.md** — §2 verbatim.
6. **CHANGELOG.md** — incl. the tuning-week threshold changes (§4.3).

### 20.1 Generic agent-instructions block (paste into any agent's system prompt / tool description)

```
Shell safety spotter
This environment runs `shellspotter`, an accident spotter in front of destructive
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
       SHELLSPOTTER_OK=SS-7F3K <command>
The code lasts ~2 min, works once, and is tied to that exact command, directory
and target set. There is no on/off switch and no reusable token: do not try to
set SHELLSPOTTER_OK=force or export it; it is ignored.

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

### 20.2 Agent-runtime wiring (example)
- **Shell tool-description line** (one line, always present):
  `A shellspotter may pause unusually risky deletes, permission changes, database drops, or
  opening a DB session, and give you three choices — proceed, cancel & rewrite, or ask your
  human; its message explains the exact effect and a safer rewrite.`
- **agent on-catch note** (loaded only when the spotter fires):
  `The shellspotter stopped a command and is asking you to choose. Read its report: it shows
  exactly what would be hit and a safer rewrite. In most cases a stop means you ran the
  command wrong (bad glob, empty variable, wrong folder, missing WHERE) — so prefer CANCEL &
  REWRITE: drop it, fix the command, and re-run the correct version, without interrupting
  the operator to report a mistake you fixed. Choose PROCEED only when the listed targets are
  EXACTLY what you meant. Choose UNSURE, ASK MY HUMAN only when you are genuinely unsure it's
  right, when there's no safe alternative, or when the spotter warns you've proceeded on
  several dangerous commands recently — that routes to the operator and you can wait or do other
  work. A hard BLOCK offers no proceed. If the spotter itself errors, the command won't run —
  don't work around it; fix the spotter or ask the operator to run it. (If this shell ever falls back
  to code mode, the same judgment applies: re-run the identical command with the one-time
  code only when the effect is exactly intended.)`

---

## 22. Future work (prior-art P2, deferred)

- **Snapshot / trash alternative** offered in the pause message: `trash-put` rewrite, a
  pre-destructive `git stash`/`tar` snapshot (doover/Aider style) as an approval option.
- **Graduated modes / presets** (Standard / Strict / Paranoid) and per-pack toggles
  (dcg, cc-safety-net).
- **Deeper symlink/mount awareness**: auto-suggest `--one-file-system`, resolve symlinked
  targets before classifying, flag `chown/chmod -R -L`.
- **CI `scan` mode** maturity + ShellCheck SC2115/SC2114/SC2164 rule reuse in the pre-check.
- **Finer-grained failure telemetry**: richer `spotter_error` reasons and per-command timeout
  tuning. (Core policy is already fail-closed, §14 — this is observability, not a change of
  default.)
- **Two-person rule** (slb): route a danger catch to a second reviewer agent/human.
- **Wire-level DB gate** (hoop-style proxy) as a stronger alternative to client shims.
- **Undo/backup** subsystem (§2.2 currently a non-goal).

---

## 23. Prior art and license notes

v3 draws on a 2026-10-14 survey (`shellspotter-prior-art-20261014.md`). No license is chosen
yet (§24), so the safe rule holds regardless: **do not copy any third-party code into
shellspotter — borrow ideas only and write our own implementation.** This keeps every
licensing option open for when the project splits into its own repo.

| Source | License | What we take (ideas, not code) |
|---|---|---|
| safe-rm | GPL-3.0 | layered protected-path config incl. glob entries, system defaults |
| rm-protection | MIT | `.shellspotter-protect` marker file (§5.1) |
| trash-cli | GPL-2.0 / MIT | "rerun with trash-put" rewrite (future §22) |
| molly-guard | Artistic/GPL | hostname-confirm for power/remote-danger (§12.3) |
| ShellCheck | GPL-3.0 | SC2115/SC2114/SC2164 patterns for the pre-check (reimplemented) |
| bash-preexec / zsh-defer | MIT | DEBUG-trap / `BASH_ENV` and zsh-widget veto notes (§3.5) |
| Claude Code / Cursor / Codex hooks | proprietary docs | hook-JSON adapter shapes (§3.6) |
| Codex sandbox / writable-roots | Apache-2.0 | project-root scope, `.git/` protected (§5) |
| OpenHands security analyzer | MIT | risk tiers → allow/pause/force logging |
| dcg (destructive_command_guard) | custom "NOASSERTION" — **do not reuse code** | packs, one-time codes, safe-before-destructive ordering, CI scan, timeout→outcome |
| cc-safety-net | MIT | git destructive set, inside-cwd/tmp vs outside rule, recursion into `-c` strings |
| pg-safeupdate | ISC | inject `PGOPTIONS` safeupdate (§11.4) |
| MySQL safe-updates | GPL docs | inject `mysql --safe-updates` (§11.4) |
| Redis ACL / rename-command | docs | FLUSHALL/FLUSHDB handling + ACL recommendation (§11.4) |
| bubblewrap / firejail / sandbox-runtime | LGPL / GPL / check | README pointer: the real security boundary (§2.3) |

Each borrowed idea is independently implemented; `THIRD_PARTY.md` lists sources and
licenses. Before vendoring **any** code (vs. an idea) from a custom/NOASSERTION project
(dcg, slb, shell-safe-rm), read and clear its license first.

---

## 24. Versioning and licensing

- **SemVer.** Pre-1.0 while thresholds/UX settle; 1.0 after the tuning week. Breaking
  changes = any change that turns a previously-allowed command into a catch (so hosts can
  pin). The spotter-log schema and config keys are part of the compatibility surface.
- **License: not chosen yet.** While shellspotter lives inside a host repo as a standalone package, it ships **without a declared open-source license**;
  the license is picked **when it splits into its own repo**. Until then: no third-party
  code is copied in (§23), so all options stay open, and the repo carries a short
  `LICENSE-TBD` note stating the license is pending the split. (Candidates to weigh then,
  not decided now: a permissive license such as Apache-2.0 or MIT.)
- `shellspotter --version` reports the version in every pause message and log line for
  reproducibility.

---

## 25. Decisions — RESOLVED

All of v2's open questions and the five v3 questions are now settled. Decision log:

| # | Question | Decision | Where applied |
|---|---|---|---|
| 1 | License | **None for now.** No declared license while in-repo; chosen when it splits into its own repo. No third-party code copied in meanwhile. | §24, §23 |
| 2 | Approval mechanism | **Interactive approval hook (preferred) + bound one-time codes (fallback).** Hook: host pauses the tool call and offers three worded choices (PROCEED / CANCEL & REWRITE / UNSURE-ASK-HUMAN); the shim **blocks in place** on a host-owned socket and the decision returns by `catch_id` (no token, no re-run); agent never handles a code; default on a decision timeout/unclear/error = cancel (ASK-HUMAN itself has no short timeout, C3); hard blocks offer no proceed. Code fallback: HMAC over argv+cwd+target-hash+level+nonce, ~2 min, single-use, `SHELLSPOTTER_OK=<code>`. No `=1`/`=force`, no env-var disable. Force-rate monitor counts proceeds (5/10 min) and warns, never blocks. Exposed as a **public, versioned, pluggable API** (Go `shellspotter/hook`, language-neutral `hook_command`/stdio, Claude/Cursor/Codex adapters; custom handlers, middleware, packs). | §0, §7, §10, §10.8, §11, §12.3, §19.7, §19.9, §19.11, §20, INTEGRATION.md |
| 2b | Transparent passthrough | On allow the spotter adds nothing: byte-identical argv `execve` (argv[0] preserved), env minus spotter vars, stdin/stdout/stderr/exit/signals untouched; pre-check and adapters never modify the command. Text-parsing approach dropped — bash is the parser. **One documented exception (§11.4):** opening an *interactive* DB REPL injects a server-side safe mode (`mysql --safe-updates`; append to `PGOPTIONS`); never on one-shot `-c/-e/-f`, never `sql_select_limit`/`max_join_size`. | §3.7, §11.4, §19.10 |
| 3 | Infra/power packs | **On by default everywhere**, shim installed only for tools present on the box (`install --refresh`/`doctor` re-check); live-state checks run only where the tool exists; negligible cost. | §3.3, §12.3, §13, §19.8 |
| 4 | Spotter failure & check-timeout behavior | **Fail closed — narrowly.** Only a crash, a bad/unreadable config, or a missing/unreadable key ⇒ command not run (exit 122, clear message). **A walk/probe check that runs too long is NOT a 122 and NOT an allow — the design decides it is a CATCH:** the command does not run; it pauses with the normal PROCEED / CANCEL & REWRITE / UNSURE-ASK-HUMAN choices (code mode refuses with an `SS-` code), and the report states the check timed out, the count reached so far, and that a long scan likely means a very large target. (This supersedes the earlier B7 "timeout ⇒ target unknown/allow".) `fail = "closed"` default. Principle 4 "unclassifiable ⇒ allow" still applies to genuinely unclassifiable targets (unreadable path, unparsed SQL, piped stdin, remote operand), which are not timeouts. Doctor liveness probe at spawn/deploy/on-demand — **no timers** (C9). | §1 pr.4, §9.5, §11.5, §12.3, §13, §14, §16, §19.6 |
| 5 | Interactive DB sessions | **Never permanently prevented**, but opening one is a DANGER catch ("NO protection inside the session; BACK UP FIRST"), suggests one-shot `-c`/`-e`/`-f`; agent approves (hook or code) and the session opens; interactive-only safe mode injected (never on `-c/-e/-f`, §11.4). | §11.1, §11.6, §19.2, §20 |
| — | Thresholds (v2, revised) | Scaled by target type: bulk delete >100; tree delete >2,000 files **OR** >1 GB (NB1: either, not both), with a build-output exemption limited to known build dirs inside a project (`/`, `/etc`, `$HOME`, mount roots are never a project); recursive perms >500; any protected path always. Configurable + per-project; tuned over the log week. | §4 |
| — | Who approves (v2) | The agent decides from the report; usually fix-and-rerun, approve only when the list is exactly intended, escalate only when unsure/no safe path. | §10.7 |
| — | Protected scope (v2) | All home dirs + dotfiles, FHS dirs, key `/etc`, boot/devices/mounts, perms-sensitive files; ordinary site/scratch/build deletes and sub-threshold normal chmods not flagged. | §5 |
| — | DB gate (v2 "anything else") | Added as §11. | §11 |

**Implementation language: Go** (stated in §3.1). The approval hook is a public,
versioned, pluggable integration API (§10.8), with an example host as the labeled reference
consumer (see INTEGRATION.md), not a host-specific feature. No code is written yet; this remains a
spec-only document pending the build.


---
