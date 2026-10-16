# Command corpora

- [heldout/](./heldout/) — original 477-case corpus, held-out sets 1–7 / 7f / 7x
- [public/](./public/) — public disaster corpora (Linux), with source URLs

No Shell Spotter source code. Run only through a harness that routes destructive
binaries to recording stubs. Never execute these lines on a live host. A miss
must be a failed test, not a command that ran.

Not included (harness noise / private review): gen scripts, mkfix, run/stub/bench
scripts, per-case `cases.tgz` outputs, results.tsv score sheets, and private review
write-ups.

## Contributing

Add a command only when it is a real accident pattern. The line must not contain
personal data: no hostnames, email addresses, IP addresses, account names, home
directories from a real machine, or secrets. Use placeholders such as `/home/user`
and `example.com`. Do not paste output from a private machine.

Public rows belong in [public/](./public/) with a source URL. Held-out rows are
fresh cases that were not used to write the rule. Keep the existing `T` line
shape in [heldout/](./heldout/).
