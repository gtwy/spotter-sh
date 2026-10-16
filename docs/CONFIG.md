# Configuration

Files, in order: built-in defaults, `/etc/spotter-sh/config.toml` (root-owned), `~/.config/spotter-sh/config.toml`, then the nearest `.spotter-sh.toml`.

A lower layer may only add `paths.protect_extra` and lower a threshold. `fail = "open"`, disabling a command, turning off a pack, `mode`, the silent-log keys, and `hook_command` are ignored below the root-owned file. `spotter-sh config` prints the merged values and whether each key was honored.

`mode` is a public setting, `silent` or `enforce`. The built-in default is `silent`, a log-only trial. `enforce` pauses a catch and refuses a hard block. `standard` in an old root-owned file means enforce. The process that starts the agent can seal the mode with `SPOTTER_SH_HOST=1` and `SPOTTER_SH_MODE=silent` or `SPOTTER_SH_MODE=enforce`. Every `SPOTTER_SH_*` variable still accepts the older `SHELLSPOTTER_*` name when the new name is unset. A command run inside the shell cannot change that seal, and neither can `~/.config/spotter-sh/config.toml` or a project `.spotter-sh.toml`.

In silent mode the shim writes `log.silent_path` (default `~/.local/state/spotter-sh/silent.jsonl`). `log.silent_max_mb` defaults to 32. `log.silent_max_age_hours` defaults to 336 (14 days). The active file is rotated when it crosses either cap. A rotated name ends in a UTC timestamp. Rotated files older than the age cap are removed. The write is append-only. The file mode follows the key file beside it and is never world-readable. The record schema and `spotter-sh report` are documented in spotter-sh(1) and spotter-sh(5). Use the report to decide when the trial is ready for `mode = "enforce"`.

Invalid TOML is a failure. The command does not run.

`fail_timeout_ms`, `probe_timeout_ms`, and `walk_timeout_ms` default to 2000, 1500, and 1500. A check that times out is a catch, with the count so far. It is not exit 122 and it is not an allow.

Exit 122 is only a crash, unreadable or invalid config, or a missing or unreadable key.

Default thresholds: 100 bulk targets, 2000 files or 1 GB for a tree, 500 recursive permission files, 100 overwrites. Build-output names (`node_modules`, `dist`, `build`, `target`, `.next`, `.cache`, `__pycache__`, `vendor`) are exempt only inside a project root, and never when that root would be `/`, `/etc`, `$HOME`, or a mount root.
