# Changelog

## 0.1.0

The command, module, and directory are `spotter-sh`. The display name is Shell Spotter. Environment variables are `SPOTTER_SH_*`. An older `SHELLSPOTTER_*` name still applies when the new name is unset.

Invoked fork bombs fed through printf, eval, or command/builtin/env are a hard block, including a called mutual recursion. A quoted or escaped tilde is a literal name, and `${name:?}` does not become the home directory when the name is unset. An expanded list longer than the bulk threshold is a catch even with `-r`. `find | xargs rm` is counted, and `ls /` piped through sed or awk into `xargs rm -rf` is the same hard block.

Silent mode is the documented default. It logs every shimmed command, including passes, and does not block or alert. Enforce mode is unchanged. `spotter-sh report` summarizes the silent log so you can decide when to switch.

First build of the PATH-shim spotter: Layer 1 hard blocks, Layer 2 argv checks, hook socket, one-time codes, database lexer, git and infra packs, and a host approval hook.
