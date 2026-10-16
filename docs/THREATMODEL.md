# Threat model

Shell Spotter reduces oops by a capable assistant. It does not stop a determined agent.

Honest limits:

- `sudo bash -c` is scanned only for the hard-block list. A script that deletes a project tree is not paused.
- `find -exec rm {} \;` and plain `xargs rm` call the real command once per item. A non-protected target passes. `sudo xargs rm` is paused because sudo drops the shim PATH.
- A pipe into a database client is not scanned (`sql_unscanned`).
- SQL the lexer cannot structure is allowed and logged (`sql_unparsed`).
- A user install owns its key (directory 0700, key 0600). The agent can read that key, so one-time codes are refused. `install --system` is the unreadable-key setup: state directory 02770 setgid `spotter-sh`, key `root:spotter-sh` mode 0640, binary setgid `spotter-sh`. The agent must not be in that group. If the caller can read or own the key, codes fail closed. The shim never takes its state directory from the environment, the working directory, or argv. Install writes the path beside the binary. `SPOTTER_SH_HOME` and `SHELLSPOTTER_HOME` on a command line are a catch and do not move the key.
- One approval covers the approved command's process tree. The host records that tree when the command seals over the hook socket. The cover ends when the leader exits, so a background child does not keep it. An environment variable or an HMAC file is not a cover. Assigning `SPOTTER_SH_COVERED` or `SHELLSPOTTER_COVERED` is a catch. A hard block is never covered.
- The agent shell should be a child subreaper if a background or disowned command must be reparented to that shell when its subshell exits, so the shim still finds the sealed host. A shim with no sealed host in its ancestor chain judges and does not fall open. Silent mode is not the default for that child.
- A recursive delete of every existing top-level directory is a hard block, the same as `/`. One system directory stays an approvable catch.
- A launcher runs another command, now or later. The check judges that payload, not the launcher's name. `at`, `batch`, `systemd-run`, and `crontab -` with no readable script are a catch, because the job would otherwise run where this check cannot see it. `su`, `runuser`, `nsenter`, `chroot`, `systemd-run`, `sudo -u`, `doas`, `pkexec`, and `machinectl shell` replace the user, the namespace, the root, or hand off to systemd, so the text check judges them before they start. An unknown payload on that path is a catch. `--help` and `--version` stay allowed. A visible harmless payload stays allowed.
- There is no env var that turns the spotter off. `mode` is `silent` or `enforce`. The default is silent: the spotter still judges and logs, and the command runs. `SPOTTER_SH_MODE` on the host process selects the same setting. The older `SHELLSPOTTER_MODE` name still works when `SPOTTER_SH_MODE` is unset. A shell command cannot change it.

A check timeout is a catch. Exit 122 is a crash, bad config, or a missing key.
