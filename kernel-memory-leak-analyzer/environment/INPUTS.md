# Input Layouts

All inputs are read from `/app/data` and `/app/config`. Inputs are treated
as immutable; the analyzer must not modify them. The following paths are
the authoritative inputs for verification: `/app/data/leaks.ndjson`,
`/app/data/modules.ndjson`, `/app/data/kernels.json`, and
`/app/config/suppressions.yaml`.

## /app/data/leaks.ndjson

One JSON object per line. One line per leaked allocation captured by the
kmemleak scan.

```
{
  "leak_id":       "L01",
  "address":       "0xffff88003f1c2700",
  "size_bytes":    256,
  "comm":          "nvme-queue",
  "pid":           1241,
  "jiffies":       4294967296,
  "age_sec":       234.5,
  "slab_cache":    "kmalloc-256",
  "scan_ts":       1716000000,
  "backtrace": [
    {"addr": "0xffffffff81234567", "symbol": "kmalloc"},
    {"addr": "0xffffffffa0001234", "symbol": "nvme_alloc_request"}
  ]
}
```

`slab_cache` is `null` for non-slab allocations. `backtrace` is ordered
top first. Frame `addr` values are hex strings and must be parsed as 64
bit unsigned integers.

## /app/data/modules.ndjson

One JSON object per line. One line per loaded kernel module or the
built-in kernel image.

```
{
  "module_name":  "nvme",
  "text_start":   "0xffffffffa0000000",
  "text_end":     "0xffffffffa00f0000",
  "builtin":      false
}
```

A frame's `addr` belongs to a module when `text_start <= addr < text_end`.
Modules do not overlap.

## /app/data/kernels.json

```
{
  "kernels": [
    {
      "host":            "prod-kfleet-09",
      "kernel_version":  "5.15.143-1.amzn2.x86_64",
      "scan_ts":         1716000000,
      "uptime_sec":      8640000
    }
  ]
}
```

The first entry in `kernels` supplies the `host` and `scan_ts` fields
surfaced in the summary block.

## /app/config/suppressions.yaml

```
min_age_sec: 10.0
max_backtrace_depth: 6
allocator_frames:
  - kmalloc
  - __kmalloc
  - kzalloc
  - ...
suppressed_prefixes:
  - __ftrace
  - trace_event_
  - __probe_
```

`min_age_sec` is a numeric threshold; any leak whose `age_sec` is
strictly less than this value is treated as transient and is dropped
entirely before classification. Such leaks contribute nothing to the
summary counters, do not appear in any group, and are not counted in
any module's aggregates.

`max_backtrace_depth` caps how many frames of each retained leak are
considered. Before any other processing, every leak's backtrace is
truncated to its first `max_backtrace_depth` entries (top-down). The
truncated backtrace is the ONLY view used for both signature
computation and suppression peeling; frames beyond the cap are
discarded and have no effect on classification, signatures, or
aggregates. Two leaks that share the same top-`max_backtrace_depth`
symbol sequence therefore belong to the same group even when their
full (untruncated) backtraces diverge below the cap.

`allocator_frames` is a list of symbol names that should never themselves
be the attributable site of a leak (exact match against the frame's
`symbol`).

`suppressed_prefixes` is a list of symbol-name prefixes. A frame is also
non-attributable when its `symbol` starts with any of these prefixes.
Prefix matching is performed in addition to the exact-match list; a
frame is "suppressed" if EITHER rule matches.

To attribute a (retained) leak to a kernel module, walk the truncated
backtrace top-down and take the first frame that is not suppressed by
either rule, then resolve that frame's `addr` to a module via the
text-range table. A leak whose every retained frame is suppressed, or
whose first non-suppressed retained frame's `addr` falls outside every
loaded module's range, is attributed to the synthetic module named
`unattributable`.
