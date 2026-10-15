# Shell Spotter

**An oops guard for AI agents' shells.**

Like a spotter in the gym, Shell Spotter lets an agent lift whatever it wants and only steps in right before something heavy lands on it. It is not a security sandbox or a lock. It exists to catch honest mistakes, like a wildcard that quietly matches `..`, an empty variable that turns a path into `/`, or a recursive permission change aimed at the wrong folder, before they run.

## Why this exists

About twenty years ago I was in `/root` trying to tighten permissions on hidden files and ran something like `chmod -R 600 .*`. In bash, `.*` also matches `..`, so the recursive chmod climbed out of `/root` and walked the whole server. The machine was colocated in Miami, about 1,200 miles away. It was effectively bricked; the datacenter ended up pulling the drive.

Threads of the same kind of mistake — typos, fat-finger accidents, drunk or late-night commands — show up online constantly. This project has done its best to gather them up in [docs/corpora/](docs/corpora/).

AI agents make these mistakes too. There are plenty of real-world reports of an LLM agent running one bad command and wiping a workspace or worse. Shell Spotter is the gym spotter I wish I'd had: it lets the work go through and only steps in right before something heavy lands wrong.

> Status: in design. Code is not published yet.

## Recommended rollout

Start in **silent mode**. Let Shell Spotter watch real agent commands for a while without blocking or delaying anything, then have your AI review the silent logs (for example with `spotter-sh report`) for false positives, misses, and anything odd about *your* workload before you switch to enforce mode. Details for hosts and bots are in [docs/INTEGRATION.md](docs/INTEGRATION.md#recommended-rollout).

## What it will do

- **Check what will actually happen, not the command text.** Bash parses the command exactly as it normally would. spotter-sh then inspects the final, fully expanded arguments and the real working directory, right before a risky command (rm, chmod, chown, mv, cp, find, rsync, dd, and others) executes.
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

Licensed under the [Mozilla Public License 2.0](LICENSE) (MPL-2.0).
Forks and redistributions must retain the [NOTICE](NOTICE) file.

## Docs (for bots and implementers)

The planning data in this repo — the design spec, build notes, roadmap, testing method, retest summaries, and command corpora — is included so anyone can port Shell Spotter to another language entirely, without reverse-engineering it.

- [Design specification](docs/SPEC.md)
- [Integration guide](docs/INTEGRATION.md)
- [Build info](docs/BUILD.md)
- [Plan / roadmap](docs/ROADMAP.md)
- [Testing handoff](docs/TESTING-HANDOFF.md)
- [Retest summaries R1–R7](docs/retests/SUMMARY.md)
- [Command corpora](docs/corpora/README.md)

Binary and command name: `spotter-sh`. Display name: Shell Spotter.

# Many Grok Bothans died to bring us this information

Grok Bot and Cursor were building Shell Spotter — a polished guard between an AI harness and the bash commands it sends, meant to stand on its own and be open-sourced. The author lovingly calls us dumbasses. Fair.

To test it, the Grok Bots kept feeding it fork bombs and other disaster commands. He thought they were *simulating* those commands. They were running them live against the product on the Grok Bot cloud computer. When the guard missed some sneaky fork-bomb forms, a real one got through: load around 490, hundreds of stuck processes that could not be killed. He had to rebuild the Grok Bot cloud three times in one week — which had never happened before. So, ya, there's that.

His deadpan — *"um why are you running actual dangerous commands on your own server"* — was the punchline. The bot owned it: it had trusted the guard it was supposed to be testing, the exact bet those tests exist to check. The hard rule now: known-dangerous test commands can never execute, even if the guard misses. They only get judged, or go to recording stubs, so a miss is a failed test — not an incident. Those missed forms are fixed in the guard. We learned it the hard way, same as the author did twenty years ago.
