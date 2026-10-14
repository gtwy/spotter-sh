# shellspotter

**An oops guard for AI agents' shells.**

Like a spotter in the gym, shellspotter lets an agent lift whatever it wants and only steps in right before something heavy lands on it. It is not a security sandbox or a lock. It exists to catch honest mistakes, like a wildcard that quietly matches `..`, an empty variable that turns a path into `/`, or a recursive permission change aimed at the wrong folder, before they run.

> Status: in design. Code is not published yet.

## What it will do

- **Check what will actually happen, not the command text.** Bash parses the command exactly as it normally would. shellspotter then inspects the final, fully expanded arguments and the real working directory, right before a risky command (rm, chmod, chown, mv, cp, find, rsync, dd, and others) executes.
- **Transparent passthrough.** Normal commands are handed to the real binary with byte-identical arguments, input, output, exit codes and signals. It never rewrites, re-quotes or rebuilds a command.
- **Quiet by default.** Read-only and everyday file work pass with no output and no noticeable delay.
- **Catches real accidents:**
  - destructive or recursive changes aimed at `/`, home directories, standard system folders, key system files, or mount roots
  - permission changes on files that need specific modes to keep the system working
  - unusually large bulk deletes or permission sweeps
  - empty-variable sweeps and bare `.*` patterns
  - destructive git operations when there is uncommitted work to lose
  - destructive database commands through common CLI clients (DROP, TRUNCATE, unscoped DELETE/UPDATE, FLUSHALL, and similar)
  - common infrastructure wipes (container, cluster, cloud storage, cron)
- **Hard-blocks a short list of certain mistakes**, such as `rm -rf /` and fork bombs.
- **Approvable, not locked.** When it catches something, the agent gets a clear danger report showing what would be affected, why it is risky, the likely mistake, and a safer rewrite. It can then choose to **proceed**, **cancel and rewrite**, or **ask its human**. Approvals are bound to that exact command and expire, so an agent cannot rubber-stamp everything.
- **Fails closed.** If the guard itself fails, the command does not run.
- **Pluggable.** A documented hook API, a language-neutral JSON interface, and adapters for popular coding-agent hook formats let any bot wire in its own approval flow.
- **Ships with agent instructions**, a ready-to-paste block that bot authors can give their agents so they understand catches and how to respond.

## Planned

- Single static Go binary
- Config for thresholds, protected paths and rule packs, with sane defaults and no config required
- Full documentation: README, man pages, config reference, integration guide

## License

Not yet licensed. All rights reserved until a license is chosen.
