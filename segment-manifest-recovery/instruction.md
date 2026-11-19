QuarryDB tenant recovery is incomplete after a compaction failure. The controller can
point `/app/store/CURRENT` at an epoch that is not fully durable, and the recovery
planner in `/app/src/recover.rs` is missing. The required result is a restored planner
for which `make` in `/app` builds `/app/bin/qrecover`. Its command interface is
`/app/bin/qrecover recover STORE OUTPUT`, and it must recover any valid store that
follows the supplied format. Recovery of `/app/store` must produce
`/app/out/recovered.qdb`.

The exact formats and recovery rules are defined in `/app/docs/storage-format.md`.
Installation details are recorded in `/app/docs/recovery-notes.md`, and the durable
state evidence for this incident is in `/app/audit/night-shift.txt`. The checker
`/app/tools/check-recovery.py` is available for the required output. Recovery must be
deterministic across valid manifests, journal histories, segment sets, snapshots,
transactions, deletions, and checkpoint tails. Only `/app/src/recover.rs` and
`/app/out/recovered.qdb` may change. `/app/Makefile`, `/app/audit`, `/app/docs`,
`/app/store`, `/app/tools`, and every other file under `/app/src` must remain unchanged.
