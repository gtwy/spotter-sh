# Held-out command sets

Independent review corpora. Labels: `pass` | `catch` | `block` | `limit` | `ambig`.
Format: `T <expected> <category> <cwd> <command>`.

These sets were withheld from the builder until after each review round. Commands that
look destructive are intended for use with recording stubs only — never against a live
filesystem. Fake credentials in secret-leak rows use the `FAKE…` prefix on purpose.

| File | Round | Approx cases |
|---|---|---|
| heldout1.sh | after R1 | ~715 |
| heldout2.sh | after R2 | ~212 |
| heldout3.sh | after R3 | ~270 |
| heldout4.sh | after R4 | ~196 |
| heldout5.sh | after R5 | ~206 |
| heldout6.sh | after R6 | ~155 |
| heldout7.sh | R7 fresh | ~140 |
| heldout7f.sh | R7 follow-up | ~120 |

Paths that named a private runtime or domain in the original sets are replaced with
generic placeholders (`~/.myagent`, `~/src/agent-runtime`, `example.com`, …) while
keeping the command shape.
