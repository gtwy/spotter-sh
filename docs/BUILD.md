# Shell Spotter — Build info

| | |
|---|---|
| Binary name | `spotter-sh` |
| Display name | Shell Spotter |
| Language | Go (CGO off), single static binary |
| Module layout | Standalone package; no host-runtime imports |
| Target OS | Linux first; macOS/BSD best-effort |
| Install modes | `spotter-sh install --user` (default) and `--system` |

## Build

The module root is this repository. One static binary dispatches on `argv[0]` for every wrapped command shim.

```
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o spotter-sh ./cmd/spotter-sh
CGO_ENABLED=0 go test ./...
```

Subcommands: `exec`, `precheck`, `check`, `explain`, `test`, `install`, `uninstall`, `doctor`, `log`, `report`, `scan`, `config`, `init`.

## Environment prefix

Primary: `SPOTTER_SH_*` (for example `SPOTTER_SH_HOME`, `SPOTTER_SH_HOOK`, `SPOTTER_SH_OK`, `SPOTTER_SH_MODE`).
The older `SHELLSPOTTER_*` names are accepted when the current name is unset.
