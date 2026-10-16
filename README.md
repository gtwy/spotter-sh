# Shell Spotter

**An oops guard for AI agents' shells.**

Like a spotter in the gym, Shell Spotter lets an agent lift whatever it wants and only steps in right before something heavy lands on it. It is not a security sandbox or a lock. It exists to catch honest mistakes, like a wildcard that quietly matches `..`, an empty variable that turns a path into `/`, or a recursive permission change aimed at the wrong folder, before they run.

## Why this exists

About twenty years ago James was in `/root` trying to change permissions on the hidden folders and ran something like `chmod -R 600 .*`. In bash, `.*` also matches `..`, so the recursive chmod climbed out of `/root` and walked the whole server. The machine was colocated in Miami, about 1,200 miles away. It was effectively bricked; the datacenter ended up pulling the drive.

Threads of the same kind of mistake — typos, fat-finger accidents, late-night commands — show up online constantly. This project gathers public examples in [docs/corpora/](docs/corpora/).

AI agents make these mistakes too. Shell Spotter lets the work go through and only steps in right before something heavy lands wrong.

James (https://github.com/gtwy) designed and led Shell Spotter.

## What it does

The default mode is `silent`. Every command runs, and the spotter writes a log of the verdict it would have applied. `enforce` pauses unusually risky deletes, permission changes, database drops, and opening a database session, and offers three choices: proceed, cancel and rewrite, or ask your human.

It is not a sandbox. A determined agent can still do damage. See [docs/THREATMODEL.md](docs/THREATMODEL.md).

Two layers:

- **Layer 1** reads the command text. In enforce mode it hard-blocks a few commands that are never legitimate (`rm -rf /`, fork bombs, raw disk writes). It does not rewrite the command.
- **Layer 2** is a PATH shim. Bash expands the command. The shim sees the real argv, and on an allow it `exec`s the real binary with that same argv. In silent mode the real binary runs first. The judgment is written afterward.

Normal commands are handed to the real binary with the same arguments, input, output, exit codes, and signals.

## Install

```sh
# from this module
CGO_ENABLED=0 go build -trimpath -o spotter-sh ./cmd/spotter-sh
./spotter-sh install --user
```

`install --user` writes shims under `~/.local/lib/spotter-sh/shims` and a state directory at `~/.local/state/spotter-sh`. Prepend that shim directory to the agent spawn `PATH` only. Do not put it in a login shell. The install line says the same thing: `do not add this to a login shell; set it on the agent spawn only`.

`install --system` (root) writes shims under `/usr/local/lib/spotter-sh/shims` and state at `/var/lib/spotter-sh`. The key is `root:spotter-sh` mode 0640. The agent user must not be in group `spotter-sh`. A user install owns its key, so one-time codes are disabled until you reinstall with `--system`.

`spotter-sh uninstall` removes the shim directory. `spotter-sh doctor` is green only when `command -v rm` is a shim in that spawn. It prints `ok  mode  silent` or `ok  mode  enforce`.

## Silent mode and enforce mode

Silent mode is the default and the right way to start. The command runs immediately. A detached process judges it and appends one JSON Lines record to `~/.local/state/spotter-sh/silent.jsonl`. A failed or slow judge does not change the command. A catch is not paused. A hard block is not refused. Nobody is asked to approve the command. An assistant should not wait for a prompt or a code. A command cannot change the mode.

`enforce` is the pausing mode. A catch waits for proceed, cancel, or ask-your-human. A hard block is refused.

```sh
spotter-sh report
spotter-sh report --since 168h
spotter-sh check -- <argv>
```

Read `top` before you switch. Switch to `enforce` when those commands are accidents you want stopped and ordinary work is `verdict pass`.

### Turn it on and off

The built-in default is `silent`. Set the mode in the root-owned file, `/etc/spotter-sh/config.toml`:

```toml
mode = "silent"
```

```toml
mode = "enforce"
```

`standard` in an older root-owned file means `enforce`.

The process that starts the agent can seal the same choice before the shell starts:

```sh
SPOTTER_SH_HOST=1
SPOTTER_SH_MODE=silent   # or enforce
```

The shim reads the outermost process that was started with `SPOTTER_SH_HOST=1`. A prefix assignment, an `export` inside the shell, `~/.config/spotter-sh/config.toml`, and a project `.spotter-sh.toml` cannot change the mode. `spotter-sh config` shows the merged value. Every `SPOTTER_SH_*` variable still accepts the older `SHELLSPOTTER_*` name when the new name is unset.

Other files, in order: built-in defaults, `/etc/spotter-sh/config.toml`, `~/.config/spotter-sh/config.toml`, then the nearest `.spotter-sh.toml`. A lower layer may only add `paths.protect_extra` and lower a threshold. The reference is [docs/CONFIG.md](docs/CONFIG.md) and [docs/spotter-sh.5.md](docs/spotter-sh.5.md).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command ran, or silent mode logged a would-be verdict and let it run |
| 120 | Approvable catch. The command did not run. Ask a trusted admin, then rerun the identical command only if they approve |
| 121 | Hard block. The command is never allowed. Do not run it |
| 122 | The spotter itself failed. The command did not run |
| 123 | `precheck --adapter generic` asking the host about a catch |
| 127 | The real binary is missing (`Shell Spotter: <name>: command not found`) |

A hard block on stderr looks like this:

```
Shell Spotter: BLOCKED — rm -rf of / or a home directory. This command is never allowed. If you truly mean it, a human must run it by hand (/bin/<cmd>).
```

An approvable catch from the text check looks like `Shell Spotter: recursive delete of a system directory.` A shim catch in enforce mode prints a report whose header is `Shell Spotter: DANGER — would damage protected paths` or `Shell Spotter: paused — large operation`, then:

```
if this is EXACTLY what you meant, re-run the identical command with the code below
```

Do not invent that code. It is bound to the exact command, works once, and expires in two minutes.

## Shims

`spotter-sh install` symlinks the wrapped commands (`rm`, `chmod`, `find`, `git`, database clients, and the rest of the catalog) at the shim directory. The agent shell's `PATH` must list that directory first. The shim judges the expanded argv and, on an allow, executes the real binary with the original argv.

`spotter-sh doctor` checks the shim directory, the key, that `rm` resolves to a shim, the hook socket when `SPOTTER_SH_HOOK` is set, the config, and the mode.

## Wiring and agent instructions

A short harness example is in [examples/harness-wiring](examples/harness-wiring/). Paste-ready instructions for the agent are in [examples/prompts/instructions.md](examples/prompts/instructions.md) and [docs/AGENT-INSTRUCTIONS.md](docs/AGENT-INSTRUCTIONS.md).

## Limitations

- **Commands run on a remote server through SSH are not currently checked.** Shell Spotter only sees commands on the machine where it's installed, so anything run on another server over `ssh` (a quoted remote command, an interactive session, or a script piped to a remote shell) goes unchecked. A solution for this is coming later.

Further limits (absolute `/bin/rm`, `sudo bash -c`, unscanned SQL pipes) are in [docs/THREATMODEL.md](docs/THREATMODEL.md).

## Contributing disaster-command data

Corpora live in [docs/corpora/](docs/corpora/). Add a command only when it is a real accident pattern and the line contains no personal data: no hostnames, email addresses, IP addresses, account names, home directories from a real machine, or secrets. Use placeholders such as `/home/user` and `example.com`. Do not include output copied from a private machine.

Never execute a corpus line on a live host. Those files are classifier inputs. A miss must be a failed test, not a command that ran. See [docs/corpora/README.md](docs/corpora/README.md).

## License

Licensed under the [Mozilla Public License 2.0](LICENSE) (MPL-2.0).
Forks and redistributions must retain the [NOTICE](NOTICE) file.

## Docs

- [Agent instructions](docs/AGENT-INSTRUCTIONS.md)
- [Integration guide](docs/INTEGRATION.md)
- [Configuration](docs/CONFIG.md)
- [Threat model](docs/THREATMODEL.md)
- [Man pages](docs/spotter-sh.1.md)
- [Design specification](docs/SPEC.md)
- [Build info](docs/BUILD.md)
- [Roadmap](docs/ROADMAP.md)
- [Testing handoff](docs/TESTING-HANDOFF.md)
- [Command corpora](docs/corpora/README.md)

Binary and command name: `spotter-sh`. Display name: Shell Spotter. Module: `github.com/gtwy/spotter-sh`.
