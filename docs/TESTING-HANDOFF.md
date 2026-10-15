# Testing handoff

Testing is paused. This note is for the next independent review. It does not start a new round.

This copy lives in the Shell Spotter docs repository under `docs/TESTING-HANDOFF.md`.

No command text from the held-out sets is included. No secret values are included.

## 1. Methodology

Reviews are independent of the builder. The reviewer writes the cases, runs them, and reports counts. The builder does not see a held-out set before the review that uses it.

Every case goes through a real bash and the PATH shim. An engine function call is not a result. The shell is `bash --noprofile --norc`. The shim directory is first on `PATH`. Destructive commands in a fixture use a recorder binary ahead of `/bin`, so the shim's allow path runs the recorder and not the real program.

Sets:

- The original set: 477 cases.
- Held-out sets 1 through 6, never shared with the builder. Approximate sizes: 715, 212, 270, 196, 206, 155.
- Each round adds one new held-out set. That set is also withheld from the builder until the review.
- Public disaster corpora, Linux only: 85 public cases, 26 from X, 18 drunk-sysadmin cases, and Stack Exchange in two parts (43 and 24).
- Dry-run fixtures for commands that must not touch the machine.
- Secret-leak probes: 12. A failure is any probe value appearing in a report, a tool result, or a log.
- Timing: p50 and p99 for the shim path, with an unshimmed baseline on the same commands.

A false positive is approved through by a trusted admin, on the session that hit the catch, and the command is checked again afterward. A hard block has no catch id and cannot be approved. A false negative is a command the spec says to catch or block that ran. A broken case is a spotter crash, exit 122, a hang, or a command that did not reach a verdict.

Each round records, per set: false positives, hard blocks, false negatives, and broken cases.

A fixed item gets a regression test on the bash and shim path. Later rounds re-run the earlier sets, not only the new held-out set.

## 2. Results history

The numeric score sheets stayed with the reviewers. They are not in this repository, and this note does not reconstruct them. What follows is the class of miss each round closed, and the commit that closed it. Heads are the builder commits after that round's fixes.

### Round 1

Reviewed the first wired spotter (`d382fbe`).

Closed in `2949b50`. The host tree is protected. Delete targets are counted from the files the command would reach. A catch is bound to the session that hit it. A second catch in one script is returned to the host instead of killing the shell.

### Round 2

Retest of `2949b50`.

Closed in `cb500be`. An unsure or undecided catch cancels the command. One attention line can go out in an hour, with no command text. A trusted admin may proceed, and only from the session that hit the catch. Secrets stay out of logs and tool output. A system install's key is unreadable to other users. Missed deletes and redirects from the retest are catches.

### Round 3

Retest of `cb500be`. Head after the fixes: `dac8568`.

An undecided catch cancels when the prompt returns, so the next turn is not stuck on an open catch. The wrapped program loses the key group before exec. The retest's misses and false positives were reclassified on the bash path. That pass covered token masking, unquoted redirects onto protected files, a single brain-note file versus a folder, `chmod` of `/bin/chmod`, `find /var/log -delete`, a called fork bomb versus a definition that is never called, one level of `psql` include, `dd` onto disk device names, one-command proceed, an ordinary `ln -s`, `rsync` dry-run, and `env -i` of an allowed command.

### Round 4

Retest of `dac8568`. Head after the fixes: `308f90f`.

`find -exec` is judged by the files find would pass, with that command's own flags. A small cleanup stays under the bulk threshold. `env -i` with no `HOME` uses the passwd home. A fork bomb counts when the function is actually called, including a pipe with no `&` and the `function` keyword. Redirects follow bash's own expansion. `~/.config` catches an overwrite of a file that is already there. Secret masking replaces the secret argument, not every copy of a short string. `git`, `systemctl`, and the operator hook drop the key group before they start.

### Round 5

Retest of `308f90f`. Head after the fixes: `60b3ec4`.

A trailing slash or `/.` follows a symlink the way `rm` does. A bare link removes only the link. Quoted fork-bomb text passes. A real bomb keeps a catch id an admin can approve. `/usr/lib` and `/lib` are protected file by file. `find` with a name filter, and `find -delete`, are judged by the files that match. The setgid group is dropped only in the child that execs, so the shim can still read the key for a later catch.

### Round 6

Retest of `60b3ec4`. Head after the fixes: `add7342`.

No argv flag selects the setgid child. A token the user sets does not. Find predicates run left to right and short-circuit. `eval`, a pipe into a shell, and a herestring or heredoc the shell executes are judged as code. A data heredoc still passes. Fork-bomb approvability was left as round 5 had it: a real bomb can still be approved.

The independent record stops at `add7342`.

## 3. Not yet tested

Independent review has not been run on any of the following. Builder-side tests are not a substitute.

- Round 7, head `e336d1a`. It was never independently retested. That includes the disguised root and home wipes (expanded `/*`, command substitution, a variable that expands to `/`, and the top-level directory set), the bomb variants that are actually invoked, a `cd` inside a brace group that still applies to the next redirect, and `cp -t` / `install -t` of a new file into a system library directory.
- The addendum at `3a17695` (an invoked bomb, `python3` `rmtree` of `/`, and `rm -rf` of a symlink to `/` as non-approvable hard blocks). It landed after the round-6 independent retest and has no independent retest of its own.
- Silent mode, the JSON Lines log, rotation, and `spotter-sh report`. No independent bot has run them.
- A live session on the agent using real agent-style commands.
- `install --system` on a real host.
- Long-running behavior and performance at scale. The timing numbers so far are short bash-and-shim samples (p50 and p99 against a baseline), not a soak.
- `iptables` drop-all. This is a spec gap: the case is not specified tightly enough to score, and it has not been run.
- macOS device names. The public corpora were Linux only.
- The absolute `/bin/rm` limitation in spec section 2.2. The shim is a `PATH` entry. A command that names the real binary by absolute path does not go through the shim. That bypass has not been an independent set.

## 4. How to resume

1. Write a fresh held-out set. Do not show it to the builder.
2. Run every set through bash and the shim, not through an engine call:
   - the original 477
   - held-out sets 1 through 6
   - every held-out set added in later rounds, including the new one
   - the public Linux corpora (85, 26, 18, 43, and 24)
   - the dry-run fixtures
   - the 12 secret-leak probes
3. Score each set: false positives, hard blocks, false negatives, broken.
4. Approve through every false positive as a trusted admin, on the session that caught it.
5. Take p50 and p99 against an unshimmed baseline.
6. Include the round-7 head `e336d1a`, the `3a17695` addendum, and silent mode (log, rotation, report, and the sealed `silent` / `enforce` switch).
7. Add a regression test for each item that fails, on the bash and shim path, and re-run the sets after the fix.
