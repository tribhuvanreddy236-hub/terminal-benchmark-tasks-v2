# QuarryDB recovery interchange

QuarryDB keeps each tenant in a store directory. `CURRENT` is the controller's last
pointer write, `journal.log` is the durability witness, `manifests/` describes candidate
epochs, and `segments/` contains immutable records. Recovery may inspect every one of
these, but it must derive authority from the journal rather than treating the pointer as
a commit record.

All files are UTF-8, line oriented, end in a newline, and reject blank lines, extra
whitespace, and unknown records. Identifiers and keys contain no whitespace. Values are
non-empty, lower-case hexadecimal byte strings.

## Manifest and journal

A manifest has this grammar:

```text
quarry-manifest-v2
epoch E
checkpoint S
segment ID GENERATION active|candidate SEAL
snapshot NAME SEQUENCE
seal MANIFEST-SEAL
end
```

There is one epoch, checkpoint and manifest seal. Segment and snapshot records may
repeat. Snapshot names are unique and their sequence may not exceed the checkpoint.
The output preserves snapshot order from the selected manifest. `current` is reserved
and cannot be a snapshot name.

The journal starts with `quarry-journal-v1`, ends with `end`, and contains ordered
records in these forms:

```text
prepare E MANIFEST-SEAL
sync E metadata
sync E segments
activate E MANIFEST-SEAL
```

An epoch is durable only when one uninterrupted cycle contains, in order, a prepare
matching the manifest seal, both distinct sync domains, and then an activation matching
the same seal. A new prepare for the epoch restarts its cycle. Syncs or activations
before that prepare belong to no cycle. Recovery selects the highest durable epoch; the
text in `CURRENT` is only a locator left by the failed controller.

Only `active` segments in the selected manifest participate. Their filename is
`segments/ID.seg`. The file's ID, generation and seal must match the manifest record.
Candidate and unreferenced files are ignored, including malformed ones.

## Segment records

A segment has this grammar:

```text
quarry-segment-v2
id ID
generation GENERATION
put SEQUENCE KEY HEX-VALUE
del SEQUENCE KEY
txput TXN PREPARE-SEQUENCE KEY HEX-VALUE
txdel TXN PREPARE-SEQUENCE KEY
commit TXN COMMIT-SEQUENCE
abort TXN ABORT-SEQUENCE
seal SEGMENT-SEAL
end
```

The header fields and seal occur once. Other records may repeat. Ordinary puts and
deletes take effect at their sequence. Transaction writes are invisible unless the
transaction has a commit record in an active segment. All writes in a committed
transaction take effect at its commit sequence; the final prepared operation for a key,
ordered by prepare sequence and then by active-segment manifest order and record position,
is the one committed. An abort leaves all of that transaction's writes invisible. Transaction IDs
have at most one terminal record, and all effective sequence numbers are unique for a
given key.

Recovery never applies an operation whose effective sequence is above the selected
manifest checkpoint. Segment generation and file order do not override sequence.
A delete remains the newest version of a key just like a put; discarding it before the
versions are merged can resurrect an older value.

## Recovered state

`qrecover recover STORE OUTPUT` writes the following exact format:

```text
quarry-state-v1
epoch E
checkpoint S
view SNAPSHOT-NAME SNAPSHOT-SEQUENCE
put KEY HEX-VALUE
endview
view current S
put KEY HEX-VALUE
endview
end
```

There is one block for each selected-manifest snapshot in manifest order, followed by
the current block at the checkpoint. A view contains the newest effective operation at
or below its sequence for each key. Deleted and never-committed keys are absent. Put
records are ordered by key as raw UTF-8 bytes. The output contains no other lines and
ends with one newline.
