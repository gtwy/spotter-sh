# spotter-sh(1)

Shell Spotter pauses unusually risky shell commands and asks for a decision. The default mode, silent, records that decision and lets the command run.

## Synopsis

spotter-sh exec|precheck|check|explain|test|install|uninstall|doctor|log|report|scan|config|init

## Description

Shims on PATH inspect the expanded argv. On an allow the real binary is executed with the same argv. On a catch the shim blocks on SPOTTER_SH_HOOK, or prints a one-time SS- code.

## Silent mode

Silent mode is the trial setting. It is the default. Every shimmed command is logged, including passes. The command starts immediately. Judgment and the log run in a detached process. If that process fails or is slow, the command still runs. A catch is not paused. A hard block is not refused. The spotter does not ask for a decision.

An assistant running under silent mode should not wait for a prompt or a code. A command cannot change the mode.

`enforce` is the pausing mode described above.

`mode` is `silent` or `enforce`. Set it in the root-owned file `/etc/spotter-sh/config.toml`:

```
mode = "silent"
mode = "enforce"
```

`standard` in an old root-owned file means enforce. The built-in default is silent.

The process that starts the agent can seal the same choice before the shell starts, with `SPOTTER_SH_HOST=1` and `SPOTTER_SH_MODE=silent` or `SPOTTER_SH_MODE=enforce`. Every `SPOTTER_SH_*` variable still accepts the older `SHELLSPOTTER_*` name when the new name is unset. The shim reads the outermost host ancestor's initial environment, not its own, so a prefix assignment on the command does not apply. A project file and a user file cannot change it.

`spotter-sh doctor` prints the active mode. `spotter-sh check -- <argv>` prints the verdict enforce would apply to that command. `spotter-sh config` prints the merged configuration.

install --user writes shims under ~/.local/lib/spotter-sh/shims. Put that directory on the agent spawn PATH only.

doctor is green only when command -v rm is a shim in that spawn.

## Report

`spotter-sh report` reads the silent log and prints a summary:

- counts by verdict (`pass`, `catch`, `hardblock`), rule, and trust
- `held`, the number of commands that would have been caught or hard-blocked
- `top`, those commands and how often they appeared
- `p50_ms` and `p99_ms`, judge time

```
spotter-sh report [--log path] [--since 168h] [--export held.jsonl]
```

`--since` takes a Go duration and keeps newer records. `--export` writes the held records as JSON Lines, mode 0600, and omits passes.

Use the report to decide on enforce. Switch when the `top` commands are accidents you want stopped and ordinary work is `verdict pass`. When a `top` line is work you do on purpose, change a protected path or a threshold in the root-owned config, stay on silent, and read the report again. Judge time in the summary is not added to the command while mode is silent.

The log path, rotation, and record schema are in spotter-sh(5).

## See also

spotter-sh(5), spotter-sh(7)
