# Testing handoff

Testing is paused. This note is for the next independent review. It does not start a new round.

This copy lives at `docs/TESTING-HANDOFF.md` in the spotter-sh module.

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

### Round 7

Retest had not yet run. Head `e336d1a`.

Recursive delete, chmod, and chown of `/`, of an expanded `/*`, and of the home directory are non-approvable hard blocks. So are an invoked fork bomb, `python3` `rmtree` of `/`, and `rm -rf` of a symlink that follows to `/` (addendum `3a17695`). A `cd` inside a brace group still applies to the next redirect. `cp -t` and `install -t` of a new file into a system library directory are catches.

### Round 8

Silent mode. Head `5a368f2`, with the public-trial wording in `bfc834a` and the testing handoff in `e54d511`.

The sealed mode is `silent` or `enforce`. Silent logs every command and does not block, cancel, delay, or alert. Enforce is unchanged. `SPOTTER_SH_*` is the current environment prefix. `SHELLSPOTTER_*` still applies when the current name is unset.

### Round 9

Retest of `e54d511`. Closed in `9e8a5b5`. The rename to Shell Spotter / `spotter-sh` is `1f3e801`.

An invoked bomb is still a hard block when it arrives through `printf` into a shell, `eval` of a command substitution, or `command` / `builtin` / `env`. A definition that is never called is not. A quoted or escaped tilde is a literal name. `${name:?}` aborts when unset and is not `/`. An expanded `rm -rf` list past the bulk threshold is a catch even with `-r`. One directory still uses the tree walk. `find` piped into `xargs rm` is counted, and an unfiltered `/` or home is a hard block.

### Round 10

Retest of `1f3e801`. The classes below are judged from the command text. Tests call the checker only. They do not run the commands.

A hard block stays non-approvable only for a target that cannot be put back: `/`, the home directory node, a raw disk, or a real fork bomb. Anything else that is dangerous has a catch id an admin can approve.

- Scoped `find` at the home directory (a depth limit and a name, path, or type test both guarding the delete) is a catch. `find` of `/` or of the home directory with no such guard stays a hard block. A read-only `find` is allowed.
- Fork bombs are structural. A function that pipes or backgrounds itself counts, including the subshell form. An unbounded `while` / `until` / `for ((;;))` that backgrounds a job counts. An interpreter `-c` or `-e` payload that loops on fork or spawn counts. `eval` and `bash -c` of a variable, a default expansion, `readarray`, or `xargs` re-scan the text when it is statically known. A value that cannot be read is a catch. A recursive function with a base case, a finite loop, and `eval` of a literal safe command are allowed.
- A pipe, here-string, here-document, or command substitution that feeds a shell or interpreter re-scans a payload that is statically known. An unknown payload is a catch. A decoder (`base64 -d`, `xxd -r`, `openssl enc -d`, `rev`, and the same shape) that feeds a shell or interpreter is always a catch. The bytes are not decoded, so a harmless payload is still caught. Decoding into a file, with nothing executing it, is allowed. A nested shell keeps the shim directory on `PATH` and the sealed `SPOTTER_SH_*` / `SHELLSPOTTER_*` values.
- Several recursive directory operands in the home directory or another sensitive tree are a bulk catch. Each such directory weighs a tenth of the flat bulk threshold, so ten of them catch. One directory still uses the tree walk. A short list of files still uses the flat count.
- A truncating redirect or `tee` onto a raw disk is a hard block. The same onto `/etc/passwd` or a shell dotfile is a catch. Interpreter calls that delete `/` are hard blocks. `env`, `nice`, `nohup`, `sudo`, `command`, `timeout`, and `xargs` are unwrapped before the inner command is judged. `echo` of paths into `xargs rm` is a catch.

### Round 11

Retest of `3542104`. The classes below are judged from the command text. Tests call the checker only. They do not run the commands.

A hard block stays non-approvable for `/`, the home directory node, a raw disk, or a real fork bomb (a self-pipe, a backgrounded self-call, or a shell that re-executes `$0` / `$BASH_SOURCE`). A recursive delete of a system directory such as `/usr` or `/etc` stays an approvable catch. A glob of children under a home or sensitive tree is an approvable catch, including `~/…/*`.

- `xargs rm` judges a list that echo or printf wrote out in full. One to three plain paths are not a bulk delete. A recursive list that is a glob, or that some other program produced, is a catch. A short non-recursive list from an unknown producer is allowed. `find` still counts its own matches. A known `/` or home node stays a hard block.
- One approval covers the approved command and the commands it runs. The host writes an HMAC cover under the install key and the replayed script exports `SPOTTER_SH_COVERED`. The shim turns a later catch into an allow when that cover is live. A hard block is not covered. The cover is removed when the next command starts. An approvable catch is level `danger` with `approve` set. Level `hardblock` is only a hard-block action.
- A shell that reads stdin (`sh -`, `sh -s`, `bash -s --`, `bash /dev/stdin`, `sh -i`) is the same pipe-to-shell rule as a bare `sh`. A known safe payload is allowed. An unknown payload is a catch.
- printf / `echo -e` text that contains `\x`, `\u`, or octal, or a raw `$'...'` word, piped into a shell is a catch. The bytes are not decoded. `\n`, `\t`, and `\r` are spacing, not an encoding. An interpreter call that passes a decoder (`b64decode`, `unhexlify`, `atob`, and the same shape) to `system`, `popen`, `exec`, `eval`, or a `check_*` call is a catch. Printing a decode, with no exec, is allowed.
- A command substitution, including one inside double quotes, an unquoted heredoc, or a herestring, is judged by the same rules as a top-level command. Single quotes, comments, and a quoted heredoc are text.
- Five recursive directory operands in a home or sensitive tree meet the flat bulk threshold. Four do not. One directory still uses the tree walk. `/tmp` does not use the home weight.
- An invoked function that calls itself and has no `if`, `case`, loop, `&&`, or `||` is an approvable catch. A base case stays allowed. An uncalled definition stays allowed.

### Round 12

Retest of `d8265ef`. The classes below are judged from the command text, or from a process-tree stub. Tests do not run the dangerous commands.

A hard block stays non-approvable for `/`, the home directory node, a trailing-slash symlink that follows to `/` or home, a raw disk, or a real fork bomb. A recursive delete of a system directory stays an approvable catch.

- The shim's state directory is the path install wrote beside the real binary. `SPOTTER_SH_HOME`, `SHELLSPOTTER_HOME`, the working directory, and argv do not move it. A command that assigns either name is a catch. `echo SPOTTER_SH_HOME=/tmp` is not an assignment. A key this user owns or can read does not issue or accept a one-time code (exit 120). The host socket still approves. User install is mode 0700/0600 and says codes are off. System install is directory 02770, key `root:spotter-sh` mode 0640, binary setgid, and the install fails if that mode does not stick.
- One approval covers the process tree that sealed over the hook. The seal's parent has to be the subshell of the agent shell. A later catch is allowed only while that leader is alive and the caller is still in the tree. A background child after the leader exits is not covered. `SPOTTER_SH_COVERED` and an HMAC file are not a cover. A hard block is not covered. Silent mode does not seal.
- A backslash inside double quotes does not start a substitution. `echo "\$(rm -rf /)"` is text. `echo "$(rm -rf /)"` is still a hard block.
- A recursive-delete glob is a catch only when the directory part is exactly home (`~`, `$HOME`, `/home/<user>`, `/root`) or a sensitive directory node (`/usr`, `/var`, `/etc`, `/usr/bin`, and the same list). `~/ws/scratch/*.png` and `~/ws/var/www/*` are not that. `~/*` and `/usr/*` are.
- A statically known list into `xargs rm` is judged per item. Two or more filesystem paths are a catch even without `-r`. One path matches one `rm`. Names that are not paths are not a list delete. `git ls-files`, `git diff`, `git grep`, `git status`, and the same shape for `hg` and `svn`, piped into `xargs rm`, are a catch. `ls | head -5 | xargs rm -f` stays allowed.
- `$'...'` with `\x`, `\u`, or octal, passed to an interpreter `-c` or `-e`, is a catch. The bytes are not decoded. `\n`, `\t`, and `\r` are spacing.
- `exec $0`, `exec ${BASH_SOURCE[0]}`, and `exec "$0"` are a fork bomb without `&`. A literal script file (regular file, at most 64KB) named by a shell or by a `.sh` / shebang word is read and judged with the same rule. It is not executed. `echo $0` stays allowed.
- A command substitution in a herestring is judged, including `cat <<< "$(rm -rf ~)"`. A quoted heredoc stays text.
- Four recursive directories in a home or sensitive tree meet the flat bulk threshold. Three do not. `/tmp` does not use the home weight. One directory still uses the tree walk.

### Round 13

Retest of `34f1c13`. The classes below are judged from the command text, or from a real bash path with a recorder stub. Tests do not run the dangerous commands.

A hard block stays non-approvable for `/`, the home directory node, a trailing-slash symlink that follows to `/` or home, a raw disk, or a real fork bomb. A recursive delete of a system directory stays an approvable catch.

- A command inside `(…)`, `{…}`, a background job, a coproc, `disown`, `nohup`, `setsid`, or an async list is judged the same way as the foreground command. `{ rm -rf /; } &` and `coproc NAME { rm -rf /; }` are hard blocks.
- The agent shell should be a child subreaper. A disowned child is reparented to that shell when its subshell exits, so the shim still finds the sealed host. A shim with no sealed host in its ancestor chain judges and does not fall open. Silent mode is not the default for that child. A child outside a live approved tree is not covered.
- `rm -rf -- ~/ws/*/` is an approvable catch, not a hard block. A glob whose directory contains a component exactly `data`, or a component that starts with `.` and is not `..`, is an approvable catch. `rm -rf /var/opt/gitlab/postgresql/data/*` and `rm -rf ~/.claude/skills/*` are catches. `~/ws/scratch/*.png` and `~/ws/var/www/*` stay allowed. `~/*` and `/usr/*` stay catches. `/*` stays a hard block. `/tmp/job/*` stays allowed. An explicit `rm -rf rootlink/` with no glob stays a hard block.
- A script written and then run on the same line is judged from the text when the bytes are visible. `printf 'rm -rf ~\n' > /tmp/x.sh; bash /tmp/x.sh` and `cat > f <<EOF` of a delete followed by `sh f` are catches. The file is not executed. A write with no later shell, `printf 'echo hi\n' > /tmp/x.sh; bash /tmp/x.sh`, and a heredoc that is only data stay allowed.
- `svn ls` and `svn list` piped into `xargs rm` are a catch, the same shape as `git` and `hg`. `svn ls | head -5 | xargs rm -f` stays allowed.
- A bare `SPOTTER_SH_COVERED=` or `SHELLSPOTTER_COVERED=` prefix, and `declare -x`, `typeset -x`, or `sudo -E env` assigning a state-directory or cover name, are an approvable catch. `echo SPOTTER_SH_COVERED=abc` is not an assignment. A cover prefix does not soften `rm -rf /`.

### Round 14

Retest of `5fe08e9`. The classes below are judged from the command text, or from the argv a shim would see. Tests do not run the commands.

A hard block stays non-approvable for `/`, the home directory node, a trailing-slash symlink that follows to `/` or home, a raw disk, or a real fork bomb. A recursive delete of a system directory stays an approvable catch.

- A backgrounded pipeline whose stages are the same shell builtin or no-op is a fork bomb. `:|:&`, `(:|:&)&`, `true|true&`, `builtin : | builtin : &`, and the same shape inside an invoked function or `bash -c` are hard blocks. `:|:` without `&`, `true|false&`, `echo hi | cat &`, `ls | head &`, and an uncalled `f(){ :|:& }` stay allowed.
- A launcher is unwrapped and its payload is judged. That includes `at` and `batch` (a here-string, a here-document, a pipe, or `-f`), `systemd-run`, `script -c`, `flock`, `watch`, `nsenter`, `unshare`, `chroot`, `su -c`, `runuser -c`, `crontab -`, `tmux new` / `screen -dm`, `ssh-agent`, `dbus-launch`, `stdbuf`, `ionice`, `chrt`, `taskset`, and `cpulimit`. `at now + 1 hour <<< 'echo hi'`, `systemd-run --user sleep 1`, `watch ls`, and `script -c 'ls'` stay allowed. `crontab -l` and `at -l` stay allowed. A scheduler with no readable payload (`at now`, `crontab -`, `systemd-run --user`, `at -f` of a file this command did not write) is an approvable catch.
- A backgrounded delete is judged in the text check. `{ rm -rf /var; } &`, `timeout --foreground 5 rm -rf / &`, `timeout -k 1 5 rm -rf /`, `( sleep 3 && rm -rf /lib ) & disown`, and `setsid bash -c 'rm -rf /'` are caught. `timeout 5 echo hi &` and `setsid bash -c 'echo hi'` stay allowed.

### Round 15

Retest of `d11f60d`. The classes below are judged from the command text, or from the argv a shim would see. Tests do not run the commands. `TestRound5QuotedBombAndShellCwd` runs the host shell against a recorder and must stay unskipped.

A hard block stays non-approvable for `/`, the home directory node, a trailing-slash symlink that follows to `/` or home, a raw disk, a real fork bomb, or a recursive delete of every existing top-level directory. A recursive delete of one system directory stays an approvable catch.

- `rm -rf /bin /etc /usr /home /var /lib /sbin /opt /root /boot` is a hard block on the text check, on `hook.PrecheckAt` (the host path), on the engine, and on `shim.Check`. `rm -rf /bin` and `rm -rf /etc /usr` stay approvable catches. The same corpus is asserted across those layers so a tier cannot drift again.
- `{ :|:& }` is a fork bomb. A brace group runs immediately, so it does not need a later call. `f(){ :|:& }` with no call stays allowed.
- `runuser -u root -- rm -rf /` is a hard block. `su`, `runuser`, `nsenter`, `chroot`, `systemd-run`, `sudo -u`, `doas`, `pkexec`, and `machinectl shell` are judged by the command they run. With no readable command, that is an approvable catch. `at --help`, `systemd-run --user --help`, and `--version` stay allowed.

## 3. Not yet tested

Independent review has not been run on round 15. Builder-side tests are not a substitute. Rounds 7 through 14 were retested only as far as the notes above; round 15 has had no independent pass.

- Round 15 of the spotter-sh module. The next held-out set should use fresh commands from the classes in the round-15 note, not the examples already in the builder tests.
- Silent mode, the JSON Lines log, rotation, and `spotter-sh report`. No independent bot has run them. The display name is Shell Spotter.
- A live session on a real agent host, using ordinary commands from that host.
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
6. Include silent mode (log, rotation, report, and the sealed `silent` / `enforce` switch) and the round-14 behavior. Approve one catch and confirm the same command does not open a second catch. Confirm a disowned background delete is caught the same way as the foreground delete.
7. Add a regression test for each item that fails, on the bash and shim path, and re-run the sets after the fix.
