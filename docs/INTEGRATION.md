# Integration

## Go

```go
hook.Serve(ctx, socketPath, handler)
```

`OnCatch` blocks until the host returns `proceed`, `cancel`, or `ask_human`. An error or a dropped connection is cancel. A hard block and a restricted catch cannot proceed.

`hook.RegisterProtected` and `hook.RegisterPack` add rules in-process. `hook.Logging` and `hook.Policy` are middleware.

`hook.Run` is not required. The shims live on PATH inside the shell. The host does not re-exec the command.

## Adapters

`spotter-sh precheck --adapter claude|cursor|codex|generic` reads the command and does not rewrite it.

- generic: exit 0 / 120 / 121 / 123
- claude and cursor: JSON allow/ask/deny, exit 2 on deny
- codex: JSON on stdout, exit 0

## hook_command

The root-owned config may set `hook_command`. The spotter writes the catch JSON to the program's stdin and reads a decision JSON from stdout.

## Silent mode

`mode` is a Shell Spotter setting (`silent` or `enforce`), independent of any one host. Seal it on the process that starts the shell (`SPOTTER_SH_HOST=1` and `SPOTTER_SH_MODE`), or set it in `/etc/spotter-sh/config.toml`. The older `SHELLSPOTTER_*` names still work when the new name is unset. While the mode is silent, the host does not need to pause, notify, or open a catch. The shim logs the would-be verdict on its own. The record can carry the session, the turn, the surface, the sender, and a trust level (`admin`, `trusted`, `untrusted`, or `none`) when the host exports them for that command.

## Harness

A harness prepends the shim directory to `PATH` for the agent shell only, exports `SPOTTER_SH_HOOK`, and calls `spotter-sh precheck` before a command runs. Exit 120 is an approvable catch. Exit 121 is a hard block and is not run. Silent mode is the default: the command runs, and the spotter only writes a log. A worked example is in [examples/harness-wiring](../examples/harness-wiring/). Agent-facing wording is in [examples/prompts](../examples/prompts/).

The older `SHELLSPOTTER_HOOK` name is accepted when `SPOTTER_SH_HOOK` is unset. The host does not edit the command string. While mode is silent, the host does not pause and does not ask for a decision. The command runs.
