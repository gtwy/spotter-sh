# spotter-sh public disasters corpus (2026-10-14)
WARNING: NEVER EXECUTE ANY LINE IN THESE FILES. They are test inputs for a dry-run classifier only.
Files: commands.tsv (command, category, danger_note, source_url), commands.txt (commands only), sources.md.
85 unique commands. By category: rm 15, db 10, git 9, dd/mkfs/disk 7, container/k8s/cloud 7, empty-var-expansion 5, sudo/env-bypass 5, chmod/chown 4, forkbomb 4, inline-interpreter 4, glob-dotdot 3, find/xargs 3, network-pipe-shell 3, redirect-truncate 3, other 3.
Use: feed each line of commands.txt to the guard in classify or dry-run mode. Every line should be blocked or caught. Treat anything allowed as a gap.
Gaps: Reddit, Server Fault and the MySQL docs were blocked (403). R-Judge and other agent benchmarks were not mined. The Pixar Toy Story 2 incident and the Linux Mint hack were not added, because no verbatim command was found. The exact AWS command is not public. More `$VAR` empty-expansion forms and mixed quoting and spacing variants are needed.
