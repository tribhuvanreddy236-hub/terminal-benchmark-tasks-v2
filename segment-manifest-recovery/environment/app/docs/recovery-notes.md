# West gallery recovery notes

The controller installs an epoch in four movements. It first writes the proposed
manifest and records its seal. The metadata directory and the segment pack are flushed
separately because they sit on different devices. Activation is written only after both
flush acknowledgements return. A controller can write `CURRENT` early while warming
the next process, so that file has never been accepted as proof of durability.

Compaction output is listed as candidate while its pack is being checked. The preceding
active set stays authoritative until the epoch containing that output completes the
journal cycle. Orphan packs are deliberately left in place for the morning scrubber;
opening every file in the segment directory during recovery turns an ordinary crash
into an outage.

The sequence clock belongs to visibility, not to file creation. A committed transaction
appears all at once where its commit landed. This matters to retained snapshots: a
prepared debit cannot leak into an earlier view, even when its prepare record was
already on disk. Deletes are carried through the same merge as values. The old incident
where a deleted lease returned was caused by filtering tombstones before choosing the
newest version.

The checkpoint is the last sequence covered by the selected manifest. Writers can leave
newer records in an active segment before the next manifest is durable. Recovery ignores
that tail; the next normal writer either adopts or replaces it after startup.

