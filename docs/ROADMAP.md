# Roadmap

Shell Spotter is in an independent-retest cycle. This note is the builder's view of what is done and what the next review should cover. It does not start that review.

## Done through round 15

Layer 1 reads the command text. Layer 2 reads the argv bash would execute. Silent mode logs both and does not block. Enforce pauses on a catch (exit 120, an admin can approve) and hard-blocks only a target that cannot be put back (exit 121, no catch id): `/`, the home directory node, a sweep of the existing top-level directories, a raw disk, or a real fork bomb. A recursive delete of one system directory stays an approvable catch. A glob of the top-level children of home or of a sensitive directory, a `data` or dot directory, or a trailing-slash directory glob under home, is an approvable catch.

Round 15 closed the retest of `d11f60d`:

1. A recursive delete that names every existing top-level directory (`/bin`, `/etc`, `/usr`, `/home`, `/var`, `/lib`, `/sbin`, `/opt`, `/root`, `/boot`) is a hard block on the text check, the host precheck, the engine, and the shim. One system directory, or a shorter list, stays an approvable catch. The four layers are checked against one corpus.
2. A brace group runs immediately. `{ :|:& }` is a fork bomb. An uncalled `f(){ :|:& }` stays allowed.
3. A launcher that changes user, namespace, or root, or hands off to systemd, is judged by its payload: `su`, `runuser` (including `runuser -u user -- cmd`), `nsenter`, `chroot`, `systemd-run`, `sudo -u`, `doas`, `pkexec`, and `machinectl shell`. No readable payload is an approvable catch. `at --help`, `systemd-run --user --help`, `--version`, and the same info flags stay allowed.

Round 11 closed the retest of `3542104`:

1. `xargs rm` judges the paths echo or printf actually wrote. A short known list is not bulk. Bulk is a large known recursive list, or a recursive list whose items are not on the command line.
2. Proceeding on a catch covers that command and its children. A second catch does not open, and the shell does not stick on "a catch is already open". Round 12 binds that cover to the approved process tree. An approvable catch is labelled danger.
3. `/`, the home directory node, a symlink that follows to `/` or to the home node, a raw disk, and a fork bomb stay hard blocks. Round 12 keeps a glob catch for the top-level children of home or of a sensitive directory only.
4. `sh -`, `sh -s`, `bash -s --`, `bash /dev/stdin`, and `sh -i` are pipe-to-shell.
5. A shell or interpreter that reads `\x`, octal, `$'...'`, or a decoded argument is a catch. The text is not decoded to decide that it is safe.
6. A shell that backgrounds a re-exec of `$0` or `$BASH_SOURCE` is a fork bomb.
7. Five recursive directories in a home or sensitive tree are a bulk catch. The weight is a fifth of the flat file threshold. One directory still uses the tree walk.
8. `$(...)` and backticks are judged wherever the shell would run them, including inside an argument.
9. An invoked function that calls itself with no base case is an approvable catch.

Round 14 closed the retest of `5fe08e9`:

1. A backgrounded pipeline of the same shell builtin or no-op (`:|:&`, `true|true&`, including inside a subshell or an invoked function) is a fork bomb. A different command on each side, a pipeline that is not backgrounded, and an uncalled definition stay allowed.
2. A launcher is a wrapper. The payload is judged: `at` / `batch` (stdin or `-f`), `systemd-run`, `script -c`, `flock`, `watch`, `nsenter`, `unshare`, `chroot`, `su -c`, `runuser`, `crontab -`, `tmux` / `screen` new, `ssh-agent`, `dbus-launch`, `stdbuf`, `ionice`, `chrt`, `taskset`, and `cpulimit`. A scheduler with no readable payload is an approvable catch.
3. Backgrounded deletes are judged in the text check, including a brace group, `timeout` with its flags, a sleep-then-disown, and `setsid bash -c`.

Round 13 closed the retest of `34f1c13`:

1. A command inside a subshell, a brace group, a background job, a coproc, a `disown` / `nohup` / `setsid` wrapper, or an async list is judged the same way as a foreground command.
2. The agent shell should be a child subreaper when a disowned child must be reparented back to that shell, so the shim still sees the sealed host. A shim with no sealed host in its ancestor chain judges and does not fall open.
3. `rm -rf -- ~/ws/*/` is an approvable catch. A glob of a `data` directory or of a dot directory (`/var/opt/gitlab/postgresql/data/*`, `~/.claude/skills/*`) is an approvable catch. `~/ws/scratch/*.png` and `~/ws/var/www/*` stay on the ordinary rules. `/*` stays a hard block.
4. A script this command writes and then runs (`printf … > /tmp/x.sh; bash /tmp/x.sh`, `cat > f <<EOF … EOF; sh f`) is judged from the text. The file is not executed. A write with no later shell, and a harmless payload, stay allowed.
5. `svn ls` and `svn list` into `xargs rm` are a catch, the same shape as git and hg. A later `head` still limits the list.
6. Assigning `SPOTTER_SH_COVERED`, `SHELLSPOTTER_COVERED`, or a state-directory name, including `declare -x` and `sudo -E env`, is an approvable catch. `echo` of those strings is not an assignment. A cover prefix does not soften `rm -rf /`.

Round 12 closed the retest of `d8265ef`:

1. The shim's key directory is fixed at install. A stamp beside the binary names it. The environment, the working directory, and argv are not consulted. Setting `SPOTTER_SH_HOME` or `SHELLSPOTTER_HOME` on a command is a catch. A key the caller can read does not issue or accept a one-time code. A user install documents that; `install --system` keeps the key `root:spotter-sh` mode 0640.
2. One approval covers the approved process tree. The host seals that tree over the hook socket. The cover ends when the leader exits, so a background child does not outlive it. A hard block is not covered.
3. A backslash inside double quotes is not a command substitution. `echo "\$(rm -rf /)"` is text.
4. A glob is a catch only when its matches are the top-level children of home or of a sensitive directory. A deeper project glob follows the ordinary rules.
5. A statically known `xargs rm` list is judged per path. Two or more filesystem paths are a catch. One path is one `rm`. A repository file list (`git ls-files`, and the same shape) into `rm` is a catch.
6. An ANSI-C quoted `-c` or `-e` payload (`$'...'` with `\x`, `\u`, or octal) is a catch. It is not decoded to decide that it is safe.
7. `exec` of `$0` or `$BASH_SOURCE`, and a script file that re-executes or backgrounds itself, are a fork bomb. The file is read, not executed.
8. A substitution in a herestring is judged, including one passed to a command that is not a shell.
9. Four recursive directories in a home or sensitive tree are a bulk catch. The weight is a quarter of the flat file threshold. Three are not. `/tmp` does not use that weight.

Round 10 closed five classes on top of the earlier split:

1. A `find` that is both depth-limited and filtered by name, path, or type, rooted at the home directory, is a catch. An unfiltered delete of `/` or of the home directory stays a hard block.
2. Fork bombs and runaway process creation are structural: self-recursive functions (including a subshell body), unbounded loops that background jobs, and interpreter `-c` / `-e` payloads that loop on fork or spawn. `eval` and other dynamic exec re-scan a payload when the text is known and catch it when it is not.
3. Pipes, here-strings, here-documents, and substitutions into a shell or interpreter use those same rules. A decoder (`base64 -d`, `xxd -r`, `openssl enc -d`, `rev`, and the same shape) that feeds a shell or interpreter is always a catch. The bytes are not decoded. Decoding to a file is allowed. A nested shell keeps the shim directory and the sealed `SPOTTER_SH_*` environment, with `SHELLSPOTTER_*` still honored when the current name is unset.
4. Several recursive directory deletes in a home or sensitive tree are a bulk catch. From round 12 the weight is a quarter of the flat file threshold per directory, so four of them catch. One directory still uses the tree walk.
5. Truncating redirects and `tee` onto a disk, `/etc/passwd`, or a shell dotfile are judged with the same recoverability split. Wrappers (`env`, `nice`, `nohup`, `sudo`, `command`, `timeout`, `xargs`) are removed before the inner command is judged. Interpreter deletes of `/` are hard blocks.

## Next

An independent retest of the round-15 head, with a fresh held-out set the builder has not seen. Score false positives, hard blocks, false negatives, and broken cases. Approve through every catch. Confirm a top-level directory sweep is a hard block on the host precheck, a brace-group `:|:&` is a fork bomb, and a user-changing launcher is judged by its payload. Time p50 and p99 against an unshimmed baseline. Do not treat builder unit tests as that review.

## Still open

- `iptables` drop-all. The case is not specified tightly enough to score.
- macOS device names. The public corpora were Linux only.
- A command that names a real binary by absolute path does not go through the `PATH` shim.
- `install --system` on a real host, and a long soak past the short bash-and-shim samples.
