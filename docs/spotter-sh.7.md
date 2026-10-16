# spotter-sh(7)

Cases:

- A — parent of the working directory, or a sweep of a filesystem root
- B — an empty variable that expanded into a root path
- C — a bulk delete or overwrite
- D — /, /*, ~, or ~/
- E — a protected path or a required mode
- F — database, git, infra, or power

A danger catch on a protected path is not a bulk catch. Build output inside a project root is exempt. A check timeout is a catch.

Silent mode is the default trial setting. It records the case that would have applied (`pass`, `catch`, or `hardblock`) and then lets the command run. Enforce mode is the pausing behavior above. Set `mode` in the root-owned config, or seal `SPOTTER_SH_HOST=1` and `SPOTTER_SH_MODE` on the process that starts the agent. A shell command cannot change it.

Read `spotter-sh report` before switching to enforce. `top` lists the commands that would have been caught or hard-blocked. Switch when those are accidents you want stopped. The log path and the record schema are in spotter-sh(5). Turning the mode on and off, and the report flags, are in spotter-sh(1).
