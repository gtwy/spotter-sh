# spotter-sh(5)

Configuration files are TOML. See docs/CONFIG.md.

The root-owned file is /etc/spotter-sh/config.toml. The user file and a project .spotter-sh.toml may only add protected paths and lower thresholds.

## Mode

`mode` is `silent` or `enforce`. Only the root-owned file may set it. The default is silent. Silent mode logs every shimmed command and lets it run. Enforce mode pauses a catch and refuses a hard block.

The host process may seal the same choice with `SPOTTER_SH_HOST=1` and `SPOTTER_SH_MODE`. A value set from inside a shell command is ignored. `standard` means enforce. Every `SPOTTER_SH_*` variable still accepts the older `SHELLSPOTTER_*` name when the new name is unset.

`spotter-sh report` summarizes the silent log. See spotter-sh(1) for the summary and for how to choose enforce.

## Silent log

Silent logs are append-only JSON Lines, schema 1. One JSON object per line.

`log.silent_path` sets the active file. The default is `~/.local/state/spotter-sh/silent.jsonl`. `log.silent_max_mb` defaults to 32. `log.silent_max_age_hours` defaults to 336 (14 days). Those keys are root-owned. The active file is rotated when it crosses either cap. A rotated name is the active path plus a UTC timestamp, for example `silent.jsonl.20261015T190405.000000000Z`. Rotated files older than the age cap are removed.

The file mode matches the key file in that directory and is never world-readable. The directory is never world-accessible. With no key file beside it, the file is mode 0600 and the directory is mode 0700.

## Record

Every field is present. An empty list is `[]`. An unknown exit code is null. Secrets in `raw`, `argv`, `reason`, and `targets` are masked with the same redactor as pause text.

| Field | Meaning |
| --- | --- |
| schema | 1 |
| ts_utc | UTC time, RFC3339 |
| ts_local | Local time, RFC3339 |
| session_id | Host session id, or empty |
| turn_id | Host turn id, or empty |
| surface | Channel or interface the host named, or empty |
| sender | Sender identity the host named, or empty |
| trust | admin, trusted, untrusted, or none |
| cwd | Working directory |
| raw | Command line as the shell received it |
| argv | Expanded argv for this exec |
| layer | precheck or engine |
| verdict | pass, catch, or hardblock: the enforce verdict |
| rule | Rule or catch id, or empty on a pass |
| catch_id | Empty on a pass. A would- id when the command would have been held. The id does not approve anything |
| reason | Why the verdict would have applied |
| targets | Resolved paths |
| files | Files a delete would reach |
| dirs | Directories a delete would reach |
| protected | Protected markers hit |
| symlink | True when a target was a symlink |
| judge_ms | Judge duration in milliseconds |
| timeout | True when the judge hit its deadline |
| error | Judge or log error, or empty |
| exit_code | Exit status of the command that ran, or null |
| version | Spotter version |
| commit | Git commit of the spotter binary, or empty |

## See also

spotter-sh(1), spotter-sh(7)
