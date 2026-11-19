# Output Report Schema

The analyzer writes exactly one file: `/app/output/kmemleak_report.json`, a
regular file (not a directory, not a symbolic link). No other files,
subdirectories, or symlinks in `/app/output` are permitted. The report must be
UTF-8 encoded JSON with a trailing newline. Integer-typed fields are JSON
numbers without a fractional part. Repeated runs against the same inputs must
be byte identical.

## Top level

```
{
  "summary":  { ... },
  "modules":  [ ... ],
  "groups":   [ ... ]
}
```

Top level keys are exactly `summary`, `modules`, `groups` in that order. No
additional keys.

## summary

```
{
  "host":               string,
  "scan_ts":            int,
  "total_leaks":        int,
  "total_bytes":        int,
  "unique_signatures":  int,
  "unattributed_leaks": int
}
```

`host` and `scan_ts` are echoed from the first kernel record in
`/app/data/kernels.json`. `total_leaks` and `total_bytes` are the global
rollup over every record in `/app/data/leaks.ndjson`. `unique_signatures`
is the count of distinct backtrace signatures across all leaks.
`unattributed_leaks` counts leaks attributed to the synthetic
`unattributable` module.

## modules

One entry per kernel module that owns at least one classified leak, plus a
synthetic `unattributable` row when at least one leak fails attribution.
Sort by `module_name` ascending.

```
{
  "module_name":  string,
  "builtin":      bool,
  "leaks":        int,
  "bytes":        int,
  "signatures":   int
}
```

`builtin` is `true` for modules whose `builtin` flag is set in
`modules.ndjson` and `false` for the synthetic `unattributable` row.
`signatures` is the number of distinct backtrace signatures attributed to
this module.

## groups

One entry per distinct backtrace signature.

```
{
  "group_id":      int,
  "module_name":   string,
  "signature":     string,
  "top_frame":     string | null,
  "leak_count":    int,
  "total_bytes":   int,
  "max_age_sec":   number,
  "leak_ids":      [string, ...]
}
```

`signature` is the leak's backtrace symbol names joined by `;`, in stack
order with the top frame first. `top_frame` is the symbol of the topmost
frame that survives suppression, or `null` when every frame is suppressed.
`leak_ids` is sorted ascending. All leaks sharing a backtrace signature
share identical frame addresses and therefore resolve to the same
`module_name` and `top_frame`; the group inherits that single attribution.

### Group ordering

Sort `groups` by:

1. `total_bytes` descending
2. `module_name` ascending
3. `signature` ascending

After sorting, assign `group_id` sequentially starting at 1 with no gaps,
so the sorted list always has IDs `[1, 2, ..., N]`.
