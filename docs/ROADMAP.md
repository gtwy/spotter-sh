# Shell Spotter — Plan and roadmap

Status notes for humans and bots. Names only; no host-specific wiring required to read this.

## Near-term rollout

1. **Silent mode first (weeks).** Log every wrapped command's would-be verdict. Never
   block, delay, or alert the agent. Commands must not wait on the spotter. Operators
   review the JSON Lines log afterward (`spotter-sh report`). The sealed mode switch
   (`silent` / `enforce`) is host-owned; a shell or config inside the agent session cannot
   flip it.
2. **Independent retest of silent mode + remaining blockers** before any enforce cutover.
   See [TESTING-HANDOFF.md](./TESTING-HANDOFF.md) and [retests/SUMMARY.md](./retests/SUMMARY.md).
3. **Enforce mode** only after silent-mode log review and the open false-negative /
   false-positive items are closed (invoked fork-bomb forms, quoted-tilde hard-block
   false positives, bulk-delete counting gaps).
4. **System install** (`install --system`) on a real host, with `doctor` green, before
   calling the rollout done.
5. **Open source** the binary and this docs set so others can contribute corpora.

## Design milestones already captured in SPEC.md

- Effects-based Layer-2 shims; tiny Layer-1 text pre-check for hard blocks
- Interactive approval hook (preferred) + bound one-time codes (fallback)
- Hard blocks for certain mistakes; everything else approvable
- Fail closed on spotter failure; check timeouts are catches
- Built-in secret redactor; env never logged
- DB / git / infra / power packs on by default for tools present on the machine

## Explicitly later

- macOS device-name coverage (public corpora so far are Linux-only)
- Soak / scale timing beyond short p50/p99 samples
- Absolute-path bypass of the PATH shim (`/bin/rm`) — documented limit
- Optional undo/backup features (SPEC future work)

## Honest limits (unchanged)

Shell Spotter is an oops spotter, not a sandbox. Determined bypasses (absolute paths,
other languages, PATH resets outside the agent spawn env) are out of scope. See SPEC §2.
