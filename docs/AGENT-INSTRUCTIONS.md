# Agent instructions

Paste [examples/prompts/instructions.md](../examples/prompts/instructions.md) into the system prompt or the instruction file the harness gives its agent. That file is checked against the exit codes and the message strings the program actually prints.

The short form:

- Silent mode is the default. The command already ran. There is no prompt and no code. Do not wait.
- Exit 120, or a report headed `Shell Spotter: DANGER`, is an approvable catch. Ask a trusted admin. Do not rewrite the command.
- Exit 121, or a line that says `Shell Spotter: BLOCKED` and `This command is never allowed`, is final. Do not run it, and do not disguise it.
- A one-time code is printed by the spotter. Do not invent one. It applies to that exact command, once, for about two minutes.
