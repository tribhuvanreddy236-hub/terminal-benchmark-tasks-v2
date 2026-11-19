# PCM1 bundled capture format (read-only)

Service trust events ship as little-endian binary under `/app/data/{scenario_id}/capture.pcm`. Scenario defaults live in `/app/data/{scenario_id}.json` (no `events` array).

## File header

| Offset | Field | Type | Rule |
|--------|-------|------|------|
| 0 | magic | 4 bytes | `PCM1` |
| 4 | `format_version` | uint32 **LE** | must be `1`; otherwise fatal (exit non-zero, no report) |

## Records (until EOF)

| Field | Type | Rule |
|-------|------|------|
| `record_seq` | uint32 LE | wire record identity for dedup (independent of JSON `seq`) |
| `flags` | uint16 LE | must be `0` for trust payloads |
| `reserved` | uint16 LE | must be `0` |
| `payload_len` | uint32 LE | byte length of JSON payload |
| `payload` | bytes | UTF-8 JSON object for one replay event |
| `checksum` | uint32 LE | CRC-32 (IEEE) over the 12-byte header (`record_seq`, `flags`, `reserved`, `payload_len`, each little-endian) concatenated with `payload` |

Process records in file order. Each record is **valid** or **rejected**:

| Reason | Rule |
|--------|------|
| `BAD_RESERVED` | `reserved != 0` |
| `BAD_FLAGS` | `flags != 0` |
| `LEN_OVERFLOW` | `payload_len > 4096`; if the full frame fits, skip `payload` and `checksum` and continue; if bytes are missing, set `truncated_tail` and stop |
| `DUP_SEQ` | `record_seq` already seen (valid or rejected earlier) |
| `BAD_CRC` | checksum mismatch |
| `TRUNCATED` (header) | fewer than 12 bytes remain for a header |
| `TRUNCATED` (body) | fewer than `payload_len + 4` bytes remain after a full header was read |

On header `TRUNCATED`: increment `records_rejected`, set `truncated_tail` to `1`, and stop. **Do not** increment `records_total`.

On body `TRUNCATED` after a full header: increment `records_total` and `records_rejected`, set `truncated_tail` to `1`, and stop.

`records_total` counts only records whose complete 12-byte header was read.

Track every `record_seq` in a set, including rejected records. `dup_seq_rejects` counts rejected records whose reason is `DUP_SEQ`. `payload_bytes` sums `payload_len` for **valid** records only.

Evaluate `LEN_OVERFLOW` before `DUP_SEQ` when both would apply.

Only valid payloads are unmarshalled and passed to trust replay (then `TRUST_RULES.md` event sort and `event_id` dedup apply).

## Per-scenario capture block in the report

Each scenario row includes a `capture` object (see `SCHEMA.md`) with: `format_version`, `records_total`, `records_valid`, `records_rejected`, `dup_seq_rejects`, `truncated_tail`, `payload_bytes`.

All bundled capture paths are absolute under `/app/data/{scenario_id}/capture.pcm`.
