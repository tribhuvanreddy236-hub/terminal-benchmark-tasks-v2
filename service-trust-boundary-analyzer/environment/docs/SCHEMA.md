# service_trust_boundary_report.json schema (read-only specification)

Output shape for `/app/build/service_trust_boundary_report.json`. Do not edit files under `/app/docs/`.

Inputs per `scenario_id` in `/app/data/manifest.json`:

- `/app/data/{scenario_id}.json` — scenario defaults only (**must not** contain an `events` array)
- `/app/data/{scenario_id}/capture.pcm` — PCM1 capture (`CAPTURE_FORMAT.md`)

Root: `{ "scenarios": [ ... ] }` in manifest order.

Each scenario:

```json
{
  "scenario_id": "dataset_01",
  "status": "VALID",
  "duplicate_events_skipped": 0,
  "capture": {
    "format_version": 1,
    "records_total": 5,
    "records_valid": 5,
    "records_rejected": 0,
    "dup_seq_rejects": 0,
    "truncated_tail": 0,
    "payload_bytes": 512
  },
  "peer_trust_edges": [
    {"from_service": "orders", "to_service": "billing"}
  ],
  "services": [
    {
      "service_id": "billing",
      "tier": "internal",
      "capabilities": ["billing:read"],
      "trust_boundary_risk": "none"
    }
  ],
  "findings": []
}
```

## capture object

Only these keys, in this order:

`format_version`, `records_total`, `records_valid`, `records_rejected`, `dup_seq_rejects`, `truncated_tail`, `payload_bytes`

Values come from PCM1 decode per `CAPTURE_FORMAT.md`. `records_total` counts only records whose complete 12-byte header was read.

`peer_trust_edges` sorted by `(from_service, to_service)` ascending.

`services` sorted by `service_id`. Each service contains only: `service_id`, `tier`, `capabilities` (sorted array), `trust_boundary_risk` (exactly one of `none`, `elevated`, `critical` per TRUST_RULES.md).

Each finding:

```json
{
  "finding_id": "dataset_03::billing::0004",
  "entity_id": "billing",
  "kind": "UNTRUSTED_PEER",
  "event_seq": 4,
  "action": "POST",
  "detail": "orders"
}
```

`kind` is exactly one of the kinds listed in TRUST_RULES.md. `findings` sorted by `finding_id`. Use `[]` never null. Non-`SERVICE_CALL` findings use `action` = `""`.

Encoding: compact JSON with `separators=(",", ":")` — no space after `:` or `,`. UTF-8, LF line endings, exactly one trailing newline.
