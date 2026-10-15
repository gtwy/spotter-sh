# Retest summaries (R1–R7)

Independent reviews of the Shell Spotter implementation. Numeric score sheets stay with
the reviewers; this note records what each round closed, what remained, and the head
that carried the fixes. All dangerous cases in later rounds are judged only — known-
dangerous commands never execute, even if the spotter misses them.

## Round 1 — first wired spotter

Closed: host tree protection; delete-target counting from files the command would reach;
catch bound to the session that hit it; a second catch in one script returned to the host
instead of killing the shell.

## Round 2

Closed: unsure/undecided catch cancels; attention rate limit with no command text; trusted
admin may proceed only from the catching session; secrets stay out of logs and tool
output; system-install key unreadable to other users; missed deletes and redirects become
catches.

## Round 3

Closed: undecided catch cancels when the prompt returns; wrapped program loses the key
group before exec; reclassification of misses and false positives on the bash path
(token masking, unquoted redirects onto protected files, single agent-note file vs folder,
`chmod` of `/bin/chmod`, `find /var/log -delete`, called vs defined fork bomb, one level of
`psql` include, `dd` onto disk devices, one-command proceed, ordinary `ln -s`, `rsync`
dry-run, `env -i` of an allowed command).

## Round 4

Closed: `find -exec` judged by files find would pass; small cleanup under bulk threshold;
`env -i` with no `HOME` uses passwd home; fork bomb counts when actually called; redirects
follow bash expansion; `~/.config` overwrite catch; secret masking replaces the secret
argument; `git` / `systemctl` / operator hook drop the key group before start.

## Round 5

Closed: trailing slash / `/.` follow symlinks the way `rm` does; bare link removes only the
link; quoted fork-bomb text passes; `/usr/lib` and `/lib` protected file by file; `find`
with name filter and `find -delete` judged by matching files; setgid group dropped only in
the child that execs.

## Round 6

Closed: no argv flag or user-set token selects the setgid child; find predicates left-to-
right with short-circuit; `eval`, pipe-into-shell, and executed herestring/heredoc judged
as code; data heredoc still passes. Invoked fork-bomb approvability left as in round 5
(still approvable at that head). Independent record stopped at that head.

## Round 7 — independent retest (incl. later heads through silent-mode work)

Headline fixes verified:

- Disguised / expanded root and home wipes (`rm -rf` of expanded `/`, command substitution,
  variable expanding to `/`, top-level directory set) are non-approvable hard blocks.
- Secret-leak probes (12/12) clean in report, tool output, and log.
- Trusted-admin approve-through of remaining approvable false positives works.
- Timing similar to round 6 (typical low single-digit to tens of ms on the shim path).

Still open (blocks enforce cutover):

- Some invoked fork-bomb forms still pass the text pre-check (`printf … | sh`,
  `eval` of a backtick substitution, `command`/`builtin`/`env` wrappers around `eval`,
  mutual two-function form). Common forms are blocked.
- Quoted-tilde false hard blocks: literal `"~"`, `\~`, and `rm -rf -- "${VAR:?}"/` treated
  as home wipes with no proceed.
- Bulk-count gaps: large `rm -rf` globs, `find -print0 | xargs -0 rm`, and some
  `ls | sed | xargs rm -rf` root-wipe shapes.
- Silent mode: code review says run-first + side log (never blocks/delays/alerts). Live
  silent-mode check on harmless stand-ins passed in a later pass; treat as needing the
  same independent methodology as other rounds before enforce.

## How to read corpora alongside these notes

Use `docs/corpora/heldout/` and `docs/corpora/public/` with the method in
[TESTING-HANDOFF.md](../TESTING-HANDOFF.md). Do not execute known-dangerous rows for real.
