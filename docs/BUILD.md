# Shell Spotter — Build info

| | |
|---|---|
| Binary name | `spotter-sh` |
| Display name | Shell Spotter |
| Language | Go (CGO off), single static binary |
| Module layout | Standalone package; no host-runtime imports |
| Target OS | Linux first; macOS/BSD best-effort |
| Install modes | `spotter-sh install --user` (default) and `--system` |

## What to build

Ship one static binary that dispatches on `argv[0]` for every wrapped command shim.
Subcommands expected by the design: `exec`, `precheck`, `check`, `explain`, `test`,
`install`, `uninstall`, `doctor`, `log`, `report`.

```
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o spotter-sh ./cmd/spotter-sh
```

Exact package paths may move; keep CGO off and the binary name `spotter-sh`.

## Environment prefix

Primary: `SPOTTER_SH_*` (for example `SPOTTER_SH_HOME`, `SPOTTER_SH_HOOK`, `SPOTTER_SH_OK`).
The older `SHELLSPOTTER_*` names are accepted as aliases so existing configs keep working.

## Out of scope for this docs repo

Source code lives elsewhere. This repository holds design, integration, testing method,
retest summaries, and command corpora only.
