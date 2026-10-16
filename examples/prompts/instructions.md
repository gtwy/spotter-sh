# Shell Spotter

You are working in a shell guarded by Shell Spotter (`spotter-sh`). Read its messages and stop. Do not invent a way around them.

## Silent mode

Silent mode is the default. The command runs. The spotter writes a log and does not pause, refuse, or ask for a decision. You will not see a prompt or a code. Do not wait. A command cannot change the mode. `spotter-sh doctor` prints `ok  mode  silent` while that is the setting.

## What a catch looks like

In enforce mode an approvable catch exits 120 (exit 120). The text check prints a line of this shape:

```
Shell Spotter: recursive delete of a system directory.
```

The shim prints a report. The header is one of:

```
================  Shell Spotter: DANGER — would damage protected paths  ================
Shell Spotter: paused — large operation
Shell Spotter: paused — check timed out
```

The report then names `command`, `effect`, `targets`, `likely consequence`, `common mistake`, and `safer rewrite`. Read those lines. They describe the exact effect.

Without a host socket, the spotter also prints:

```
if this is EXACTLY what you meant, re-run the identical command with the code below
```

That code starts with `SS-`. It works once, for that identical command, for about two minutes. Do not invent a code. Do not reuse one. Do not attach it to a different command.

If the install key is readable, there is no code. The line is:

```
Shell Spotter: the install key is readable by this user, so a one-time code cannot be trusted. A human has to approve this, or reinstall with --system.
```

Ask a trusted admin. Tell them the command and the report. If they approve, the harness reruns that same command. If they do not, cancel it. The decision words are `proceed`, `cancel`, and `ask_human`.

## Do not rewrite a caught command

A catch is about the effect, not the spelling. Do not retry it in another form. These are caught on their own, and the messages are:

```
Shell Spotter: decoded text fed to a shell or interpreter.
Shell Spotter: eval of a script that is not visible here.
Shell Spotter: a shell would run a script that is not visible here.
Shell Spotter: a generated script would run a destructive command.
```

That includes base64 or another decoder piped into a shell, `eval` of a hidden script, and splitting one destructive command into pieces so each piece looks small. Cancel and write a safer command, or ask the admin. Do not disguise the one that was caught.

## Hard blocks are final

A hard block exits 121 (exit 121). The message is:

```
Shell Spotter: BLOCKED — rm -rf of / or a home directory. This command is never allowed. If you truly mean it, a human must run it by hand (/bin/<cmd>).
```

A fork bomb prints:

```
Shell Spotter: BLOCKED — a function that pipes or backgrounds a call to itself. This command is never allowed. If you truly mean it, a human must run it by hand (/bin/<cmd>).
```

A raw disk write uses the same `Shell Spotter: BLOCKED —` line and the words `This command is never allowed`. There is no catch id. Do not ask for approval. Do not run the command by another path, another name, or a rewritten spelling. A human has to run it by hand, outside this agent, if it is truly meant.

Exit 122 means the spotter failed and the command did not run:

```
Shell Spotter failed; command not run; see log; a human can run it by hand or fix the spotter
```

Exit 127 means the real program is missing: `Shell Spotter: <name>: command not found`.
