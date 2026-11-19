"""Verification suite for the kernel memory leak analyzer.

The test.sh harness rebuilds /app/bin/analyzer from source, runs it twice
on the shipped dataset for idempotency, swaps in a second hand-authored
leaks file (extra_leaks.ndjson), and generates a procedurally
synthesized leaks file (synth_leaks.ndjson) with a seeded RNG. The
tests below open the resulting artifacts and verify the three documented
suppression rules (min_age_sec, suppressed_prefixes, max_backtrace_depth)
plus exact attribution, grouping, sort, and module rollup behaviour.
Every expected value is recomputed from data; no fixtures are
hard-coded so an agent cannot pass by echoing precomputed numbers.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

OUTPUT_DIR = Path("/app/output")
REPORT_PATH = Path("/app/output/kmemleak_report.json")
REPORT_FIRST = Path("/tests/report_first.json")
REPORT_SECOND = Path("/tests/report_second.json")
REPORT_EXTRA = Path("/tests/report_extra.json")
REPORT_SYNTH = Path("/tests/report_synth.json")
ANALYZER_BIN = Path("/app/bin/analyzer")
LEAKS_PATH = Path("/app/data/leaks.ndjson")
MODULES_PATH = Path("/app/data/modules.ndjson")
KERNELS_PATH = Path("/app/data/kernels.json")
SUPPRESSIONS_PATH = Path("/app/config/suppressions.yaml")
EXTRA_LEAKS = Path("/tests/extra_leaks.ndjson")
SYNTH_LEAKS = Path("/tests/synth_leaks.ndjson")
BASELINE_DIR = Path("/tests/baseline")

SUMMARY_KEYS = [
    "host",
    "scan_ts",
    "total_leaks",
    "total_bytes",
    "unique_signatures",
    "unattributed_leaks",
]
MODULE_KEYS = ["module_name", "builtin", "leaks", "bytes", "signatures"]
GROUP_KEYS = [
    "group_id",
    "module_name",
    "signature",
    "top_frame",
    "leak_count",
    "total_bytes",
    "max_age_sec",
    "leak_ids",
]


def _load(path: Path) -> dict:
    """Read and parse the JSON report at path."""
    with path.open() as fh:
        return json.load(fh)


def _load_yaml_config(path: Path) -> tuple[set[str], tuple[str, ...], float, int]:
    """Parse suppressions.yaml: allocator_frames, suppressed_prefixes, min_age_sec, max_backtrace_depth.

    Returns:
        (frames, prefixes, min_age_sec, max_backtrace_depth)
        max_backtrace_depth defaults to a very large sentinel if absent.
    """
    frames: set[str] = set()
    prefixes: list[str] = []
    min_age_sec = 0.0
    max_depth = 10**9
    section: str | None = None
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if indent == 0:
            if stripped.endswith(":"):
                section = stripped.rstrip(":")
            else:
                section = None
                if ":" in stripped:
                    key, _, value = stripped.partition(":")
                    key = key.strip()
                    value = value.strip()
                    if key == "min_age_sec":
                        try:
                            min_age_sec = float(value)
                        except ValueError:
                            pass
                    elif key == "max_backtrace_depth":
                        try:
                            max_depth = int(value)
                        except ValueError:
                            pass
        elif section is not None and stripped.startswith("- "):
            item = stripped[2:].strip()
            if section == "allocator_frames":
                frames.add(item)
            elif section == "suppressed_prefixes":
                prefixes.append(item)
    return frames, tuple(prefixes), min_age_sec, max_depth


def _is_suppressed(symbol: str, frames: set[str], prefixes: tuple[str, ...]) -> bool:
    """Return True if symbol is suppressed by EITHER the exact-match list or any prefix."""
    if symbol in frames:
        return True
    return any(symbol.startswith(p) for p in prefixes)


def _retained_backtrace(leak: dict, max_depth: int) -> list[dict]:
    """Return the leak's backtrace truncated to the first max_depth frames (top-down)."""
    return leak["backtrace"][:max_depth]


def _retained_leaks(path: Path) -> list[dict]:
    """Parse an ndjson file and return the leaks after applying min_age_sec and max_backtrace_depth.

    Truncated backtraces replace the original in the returned dicts; downstream
    helpers treat the truncated view as the only valid one (per INPUTS.md).
    """
    _, _, min_age_sec, max_depth = _load_yaml_config(SUPPRESSIONS_PATH)
    out: list[dict] = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        leak = json.loads(line)
        if float(leak.get("age_sec", 0.0)) < min_age_sec:
            continue
        leak["backtrace"] = _retained_backtrace(leak, max_depth)
        out.append(leak)
    return out


def _load_modules(path: Path) -> list[dict]:
    """Parse modules.ndjson into a list of module records."""
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _module_for_addr(addr_hex: str, modules: list[dict]) -> str | None:
    """Return the module name whose text range covers addr_hex, or None."""
    addr = int(addr_hex, 16)
    for m in modules:
        if int(m["text_start"], 16) <= addr < int(m["text_end"], 16):
            return m["module_name"]
    return None


def _signature(leak: dict) -> str:
    """Signature = ';'-joined symbols of the (already-truncated) backtrace, top-down."""
    return ";".join(f["symbol"] for f in leak["backtrace"])


def _expected_attribution(
    leak: dict,
    modules: list[dict],
    frames: set[str],
    prefixes: tuple[str, ...],
) -> tuple[str, str | None]:
    """Apply suppression peeling + addr->module to derive (module_name, top_frame).

    Assumes leak["backtrace"] is already truncated to max_backtrace_depth.
    """
    for frame in leak["backtrace"]:
        if not _is_suppressed(frame["symbol"], frames, prefixes):
            mod = _module_for_addr(frame["addr"], modules)
            return (mod or "unattributable", frame["symbol"])
    return ("unattributable", None)


def _module_builtin_map(modules: list[dict]) -> dict[str, bool]:
    """module_name -> builtin flag; the synthetic 'unattributable' row defaults to False."""
    out = {m["module_name"]: bool(m["builtin"]) for m in modules}
    out.setdefault("unattributable", False)
    return out


def _check_invariants(report: dict, retained_leaks: list[dict]) -> None:
    """Cross-check the report against the retained-leak set using rules computed from data."""
    s = report["summary"]
    assert s["total_leaks"] == len(retained_leaks), (
        f"summary.total_leaks={s['total_leaks']} != retained_leaks={len(retained_leaks)}"
    )
    expected_total_bytes = sum(int(lk["size_bytes"]) for lk in retained_leaks)
    assert s["total_bytes"] == expected_total_bytes, (
        f"summary.total_bytes={s['total_bytes']} != sum(size_bytes)={expected_total_bytes}"
    )
    expected_unique = len({_signature(lk) for lk in retained_leaks})
    assert s["unique_signatures"] == expected_unique, (
        f"summary.unique_signatures={s['unique_signatures']} != distinct sigs={expected_unique}"
    )
    module_leaks_sum = sum(m["leaks"] for m in report["modules"])
    module_bytes_sum = sum(m["bytes"] for m in report["modules"])
    assert module_leaks_sum == s["total_leaks"]
    assert module_bytes_sum == s["total_bytes"]
    group_leaks_sum = sum(g["leak_count"] for g in report["groups"])
    group_bytes_sum = sum(g["total_bytes"] for g in report["groups"])
    assert group_leaks_sum == s["total_leaks"]
    assert group_bytes_sum == s["total_bytes"]
    sigs = {g["signature"] for g in report["groups"]}
    assert len(sigs) == s["unique_signatures"]
    unattr_from_groups = sum(
        g["leak_count"] for g in report["groups"] if g["module_name"] == "unattributable"
    )
    assert unattr_from_groups == s["unattributed_leaks"]
    for mod in report["modules"]:
        name = mod["module_name"]
        mg_leaks = sum(g["leak_count"] for g in report["groups"] if g["module_name"] == name)
        mg_bytes = sum(g["total_bytes"] for g in report["groups"] if g["module_name"] == name)
        mg_sigs = len({g["signature"] for g in report["groups"] if g["module_name"] == name})
        assert mod["leaks"] == mg_leaks, f"module {name} leaks={mod['leaks']} != groups sum={mg_leaks}"
        assert mod["bytes"] == mg_bytes
        assert mod["signatures"] == mg_sigs


# -----------------------------------------------------------------------------
# Foundation: structural contract & determinism (consolidated)
# -----------------------------------------------------------------------------


def test_report_meets_schema_contract():
    """Structural gate: binary built, report exists at canonical path, top-level + nested key order, field types, trailing newline + UTF-8, modules sorted ASC, /app/output contains only the canonical regular file."""
    assert ANALYZER_BIN.exists() and os.access(ANALYZER_BIN, os.X_OK), (
        "analyzer binary missing or not executable"
    )
    assert REPORT_PATH.exists(), "kmemleak_report.json missing"
    raw = REPORT_PATH.read_bytes()
    assert raw.endswith(b"\n"), "report missing trailing newline"
    raw.decode("utf-8")
    report = json.loads(raw)
    assert list(report.keys()) == ["summary", "modules", "groups"], (
        f"top-level key order wrong: {list(report.keys())}"
    )
    assert list(report["summary"].keys()) == SUMMARY_KEYS
    s = report["summary"]
    assert isinstance(s["host"], str) and s["host"]
    for k in ("scan_ts", "total_leaks", "total_bytes", "unique_signatures", "unattributed_leaks"):
        assert isinstance(s[k], int) and not isinstance(s[k], bool), f"summary.{k} not int"
    module_names = [m["module_name"] for m in report["modules"]]
    assert module_names == sorted(module_names), f"modules not sorted ASC: {module_names}"
    for m in report["modules"]:
        assert list(m.keys()) == MODULE_KEYS, (
            f"module {m.get('module_name')} key order wrong: {list(m.keys())}"
        )
        assert isinstance(m["module_name"], str)
        assert isinstance(m["builtin"], bool)
        for k in ("leaks", "bytes", "signatures"):
            assert isinstance(m[k], int) and not isinstance(m[k], bool), f"module.{k} not int"
    for g in report["groups"]:
        assert list(g.keys()) == GROUP_KEYS, f"group {g.get('group_id')} key order wrong"
        for k in ("group_id", "leak_count", "total_bytes"):
            assert isinstance(g[k], int) and not isinstance(g[k], bool), f"group.{k} not int"
        assert isinstance(g["module_name"], str)
        assert isinstance(g["signature"], str)
        top = g["top_frame"]
        assert top is None or isinstance(top, str), f"group {g.get('group_id')}: top_frame wrong type"
        assert top is None or top, (
            f"group {g.get('group_id')}: top_frame must be JSON null or non-empty string, got {top!r}"
        )
        assert isinstance(g["max_age_sec"], (int, float)) and not isinstance(g["max_age_sec"], bool)
        assert isinstance(g["leak_ids"], list)
        for lid in g["leak_ids"]:
            assert isinstance(lid, str)
    entries = sorted(p.name for p in OUTPUT_DIR.iterdir())
    assert entries == ["kmemleak_report.json"], (
        f"/app/output must contain only kmemleak_report.json, got: {entries}"
    )
    only = OUTPUT_DIR / "kmemleak_report.json"
    assert only.is_file() and not only.is_symlink(), (
        "kmemleak_report.json must be a regular file (no symlinks/dirs)"
    )


def test_inputs_unchanged_across_run():
    """All four input files must be byte-identical to their pre-run baseline snapshots."""
    for name, live in (
        ("leaks.ndjson", LEAKS_PATH),
        ("modules.ndjson", MODULES_PATH),
        ("kernels.json", KERNELS_PATH),
        ("suppressions.yaml", SUPPRESSIONS_PATH),
    ):
        baseline = BASELINE_DIR / name
        assert baseline.exists(), f"baseline {name} missing; harness did not snapshot"
        assert live.read_bytes() == baseline.read_bytes(), (
            f"{name} was modified across the run"
        )


def test_top_frame_never_empty_string_all_harness_reports():
    """`top_frame` must be JSON null or a non-empty symbol string, never \"\".

    Empty string satisfies `isinstance(str)` in looser schema checks but violates
    the contract described in INPUTS.md and instruction.md; agents often emit it
    when all frames are suppressed.
    """
    paths: list[tuple[str, Path]] = [
        ("primary", REPORT_PATH),
        ("first", REPORT_FIRST),
        ("second", REPORT_SECOND),
        ("extra", REPORT_EXTRA),
        ("synth", REPORT_SYNTH),
    ]
    for label, path in paths:
        if not path.exists():
            continue
        report = _load(path)
        for g in report["groups"]:
            top = g.get("top_frame")
            assert top is None or isinstance(top, str), (
                f"{label} group {g.get('group_id')}: top_frame bad type {type(top).__name__}"
            )
            assert top is None or top, (
                f"{label} group {g.get('group_id')}: top_frame must be null or non-empty, got {top!r}"
            )


def test_consecutive_harness_runs_byte_identical_json_files():
    """test.sh runs the analyzer twice on the same inputs; the two captured JSON files must match byte-for-byte.

    Instruction.md requires two runs to be byte-identical; comparing parsed JSON
    only is insufficient because key ordering or whitespace differences would slip through.
    """
    assert REPORT_FIRST.exists() and REPORT_SECOND.exists(), (
        "harness must write /tests/report_first.json and /tests/report_second.json"
    )
    first = REPORT_FIRST.read_bytes()
    second = REPORT_SECOND.read_bytes()
    assert first == second, (
        "consecutive analyzer runs must serialize to identical bytes "
        f"(got {len(first)} vs {len(second)} bytes)"
    )
    assert first.endswith(b"\n"), "first snapshot must end with newline byte"
    assert second.endswith(b"\n"), "second snapshot must end with newline byte"


# -----------------------------------------------------------------------------
# Rule-by-rule tests: each suppression rule must be exercised in isolation
# -----------------------------------------------------------------------------


def test_min_age_filter_excludes_transient_leaks():
    """Every leak whose age_sec < min_age_sec must be ABSENT from the report (no group, no module aggregate).

    Cascade: failing to honor min_age_sec will leave transient leaks counted in
    summary/modules/groups, which conflicts with the documented filter.
    """
    _, _, min_age_sec, _ = _load_yaml_config(SUPPRESSIONS_PATH)
    assert min_age_sec > 0.0, "test precondition: min_age_sec must be configured > 0"
    raw_leaks = [
        json.loads(line)
        for line in LEAKS_PATH.read_text().splitlines()
        if line.strip()
    ]
    transient_ids = {
        lk["leak_id"]
        for lk in raw_leaks
        if float(lk.get("age_sec", 0.0)) < min_age_sec
    }
    assert transient_ids, (
        "test precondition: at least one shipped leak must have age_sec < min_age_sec"
    )
    report = _load(REPORT_PATH)
    found = {lid for g in report["groups"] for lid in g["leak_ids"]}
    leaked = found & transient_ids
    assert not leaked, (
        f"min_age_sec filter violated: transient leaks appeared in groups: {sorted(leaked)}"
    )
    retained_count = len(raw_leaks) - len(transient_ids)
    assert report["summary"]["total_leaks"] == retained_count, (
        f"summary.total_leaks={report['summary']['total_leaks']} but retained = "
        f"{retained_count} after dropping {len(transient_ids)} transient leaks"
    )


def test_prefix_suppression_peels_traced_frames():
    """Frames matching any suppressed_prefixes entry must be peeled exactly like exact-match allocator_frames.

    Verified by locating leaks whose first non-allocator frame's symbol starts
    with a configured prefix and asserting they are NOT attributed via that
    frame (the next, non-prefix frame must be the top_frame instead).
    """
    frames, prefixes, _, _ = _load_yaml_config(SUPPRESSIONS_PATH)
    assert prefixes, "test precondition: suppressed_prefixes must be configured"
    leaks = _retained_leaks(LEAKS_PATH)
    modules = _load_modules(MODULES_PATH)
    report = _load(REPORT_PATH)
    actual = {
        lid: (g["module_name"], g["top_frame"])
        for g in report["groups"]
        for lid in g["leak_ids"]
    }
    exercised = 0
    for leak in leaks:
        prefix_hit = False
        for f in leak["backtrace"]:
            if f["symbol"] in frames:
                continue
            if any(f["symbol"].startswith(p) for p in prefixes):
                prefix_hit = True
                continue
            break
        if not prefix_hit:
            continue
        exercised += 1
        expected = _expected_attribution(leak, modules, frames, prefixes)
        assert actual[leak["leak_id"]] == expected, (
            f"prefix-suppression peeling broken for {leak['leak_id']}: "
            f"got {actual[leak['leak_id']]}, rules require {expected}"
        )
        for f in leak["backtrace"]:
            if any(f["symbol"].startswith(p) for p in prefixes):
                assert actual[leak["leak_id"]][1] != f["symbol"], (
                    f"leak {leak['leak_id']} top_frame must not be a prefix-suppressed symbol, "
                    f"got {f['symbol']!r}"
                )
                break
    assert exercised >= 3, (
        f"test precondition: at least 3 leaks must exercise prefix peeling, found {exercised}"
    )


def test_max_backtrace_depth_truncates_before_peeling_and_signature():
    """A leak whose real-module frame is past max_backtrace_depth MUST attribute to 'unattributable'.

    This is the most subtle rule: a naive implementation that walks the full
    backtrace will attribute these leaks to their deep module and silently
    miscount. The test computes the expected attribution from the TRUNCATED
    backtrace and compares to the report.
    """
    _, _, _, max_depth = _load_yaml_config(SUPPRESSIONS_PATH)
    assert max_depth > 0, "test precondition: max_backtrace_depth must be configured"
    raw_leaks = [
        json.loads(line)
        for line in LEAKS_PATH.read_text().splitlines()
        if line.strip()
    ]
    deep_leak_ids = [
        lk["leak_id"]
        for lk in raw_leaks
        if len(lk["backtrace"]) > max_depth
    ]
    assert len(deep_leak_ids) >= 2, (
        f"test precondition: at least 2 leaks must have backtrace depth > max_backtrace_depth "
        f"({max_depth}); found {len(deep_leak_ids)}"
    )
    leaks = _retained_leaks(LEAKS_PATH)
    modules = _load_modules(MODULES_PATH)
    frames, prefixes, _, _ = _load_yaml_config(SUPPRESSIONS_PATH)
    report = _load(REPORT_PATH)
    actual = {
        lid: (g["module_name"], g["top_frame"])
        for g in report["groups"]
        for lid in g["leak_ids"]
    }
    for leak in leaks:
        if leak["leak_id"] not in deep_leak_ids:
            continue
        expected = _expected_attribution(leak, modules, frames, prefixes)
        assert actual[leak["leak_id"]] == expected, (
            f"max_backtrace_depth violation for {leak['leak_id']}: agent attributed "
            f"{actual[leak['leak_id']]}, but truncated-backtrace rule requires {expected}"
        )
        assert len(leak["backtrace"]) == max_depth, (
            f"helper invariant: retained backtrace for {leak['leak_id']} should be "
            f"truncated to {max_depth}, got {len(leak['backtrace'])}"
        )


def test_max_backtrace_depth_collapses_signatures_when_top_n_matches():
    """Two leaks that share top-N symbols but diverge below max_backtrace_depth MUST collapse into one group.

    Cascade: an agent that uses the FULL backtrace to compute signatures will
    produce one extra group per pair, throwing off summary.unique_signatures,
    group counts, and per-module signature counts.
    """
    _, _, _, max_depth = _load_yaml_config(SUPPRESSIONS_PATH)
    raw_leaks = [
        json.loads(line)
        for line in LEAKS_PATH.read_text().splitlines()
        if line.strip()
    ]
    truncated_sigs: dict[str, list[str]] = {}
    for lk in raw_leaks:
        sig = ";".join(f["symbol"] for f in lk["backtrace"][:max_depth])
        truncated_sigs.setdefault(sig, []).append(lk["leak_id"])
    paired = {sig: ids for sig, ids in truncated_sigs.items() if len(ids) >= 2}
    eligible_pairs = []
    for sig, ids in paired.items():
        full_sigs = set()
        for lid in ids:
            lk = next(x for x in raw_leaks if x["leak_id"] == lid)
            full_sigs.add(";".join(f["symbol"] for f in lk["backtrace"]))
        if len(full_sigs) >= 2:
            eligible_pairs.append((sig, sorted(ids)))
    assert eligible_pairs, (
        "test precondition: at least one pair of leaks must share top-N symbols "
        "but have divergent full backtraces"
    )
    report = _load(REPORT_PATH)
    by_sig = {g["signature"]: g for g in report["groups"]}
    for sig, ids in eligible_pairs:
        assert sig in by_sig, (
            f"truncated signature {sig!r} (shared by {ids}) must appear as a SINGLE group; "
            f"got groups with signatures: {sorted(by_sig)}"
        )
        g = by_sig[sig]
        actual_ids_sorted = sorted(g["leak_ids"])
        for lid in ids:
            assert lid in actual_ids_sorted, (
                f"leak {lid} should be a member of the collapsed group {sig!r}, "
                f"but group members are {actual_ids_sorted}"
            )


def test_signatures_are_top_down_truncated_symbols():
    """signature = ';'-joined symbols of the truncated (top-max_depth) backtrace, in stack order."""
    _, _, _, max_depth = _load_yaml_config(SUPPRESSIONS_PATH)
    leaks_by_id = {lk["leak_id"]: lk for lk in _retained_leaks(LEAKS_PATH)}
    report = _load(REPORT_PATH)
    checked = 0
    for g in report["groups"]:
        first_lid = g["leak_ids"][0]
        leak = leaks_by_id.get(first_lid)
        if leak is None:
            continue
        expected = ";".join(f["symbol"] for f in leak["backtrace"])
        assert g["signature"] == expected, (
            f"group {g['group_id']} (leak {first_lid}): signature {g['signature']!r} "
            f"!= top-{max_depth} symbols joined {expected!r}"
        )
        for other_lid in g["leak_ids"][1:]:
            other = leaks_by_id.get(other_lid)
            if other is None:
                continue
            other_sig = ";".join(f["symbol"] for f in other["backtrace"])
            assert other_sig == expected, (
                f"group {g['group_id']}: member {other_lid} has divergent truncated signature "
                f"{other_sig!r} vs canonical {expected!r}"
            )
        checked += 1
    assert checked >= 5, f"expected to verify ≥5 groups, got {checked}"


def test_out_of_range_top_frame_becomes_unattributable():
    """When the top non-suppressed frame's addr lies outside every module's range, attribute to 'unattributable'."""
    frames, prefixes, _, _ = _load_yaml_config(SUPPRESSIONS_PATH)
    leaks = _retained_leaks(LEAKS_PATH)
    modules = _load_modules(MODULES_PATH)
    report = _load(REPORT_PATH)
    actual = {lid: g["module_name"] for g in report["groups"] for lid in g["leak_ids"]}
    exercised = 0
    for leak in leaks:
        first = next(
            (f for f in leak["backtrace"] if not _is_suppressed(f["symbol"], frames, prefixes)),
            None,
        )
        if first is not None and _module_for_addr(first["addr"], modules) is None:
            exercised += 1
            assert actual[leak["leak_id"]] == "unattributable", (
                f"leak {leak['leak_id']} top non-suppressed addr {first['addr']} is "
                f"out-of-range; expected unattributable, got {actual[leak['leak_id']]}"
            )
    assert exercised >= 1, (
        "test precondition: at least one retained leak must have an out-of-range top frame"
    )


# -----------------------------------------------------------------------------
# End-to-end attribution & aggregation: rule-derived oracle on three datasets
# -----------------------------------------------------------------------------


def test_per_leak_attribution_matches_rules_on_default_dataset():
    """Every retained leak's (module, top_frame) must equal the value derived from all three rules."""
    leaks = _retained_leaks(LEAKS_PATH)
    modules = _load_modules(MODULES_PATH)
    frames, prefixes, _, _ = _load_yaml_config(SUPPRESSIONS_PATH)
    expected = {
        leak["leak_id"]: _expected_attribution(leak, modules, frames, prefixes)
        for leak in leaks
    }
    report = _load(REPORT_PATH)
    actual = {
        lid: (g["module_name"], g["top_frame"])
        for g in report["groups"]
        for lid in g["leak_ids"]
    }
    for lid, exp in expected.items():
        assert lid in actual, f"leak {lid} missing from any group"
        assert actual[lid] == exp, (
            f"leak {lid}: attribution {actual[lid]} != rule-derived {exp}"
        )


def test_per_leak_attribution_matches_rules_on_extra_dataset():
    """Same rule-derived attribution must hold on the anti-cheating swapped dataset (extra_leaks.ndjson)."""
    leaks = _retained_leaks(EXTRA_LEAKS)
    modules = _load_modules(MODULES_PATH)
    frames, prefixes, _, _ = _load_yaml_config(SUPPRESSIONS_PATH)
    expected = {
        leak["leak_id"]: _expected_attribution(leak, modules, frames, prefixes)
        for leak in leaks
    }
    report = _load(REPORT_EXTRA)
    actual = {
        lid: (g["module_name"], g["top_frame"])
        for g in report["groups"]
        for lid in g["leak_ids"]
    }
    for lid, exp in expected.items():
        assert actual.get(lid) == exp, (
            f"extra leak {lid}: attribution {actual.get(lid)} != rule-derived {exp}"
        )


def test_per_leak_attribution_matches_rules_on_synth_dataset():
    """Same rule-derived attribution must hold on the procedurally generated synth dataset."""
    assert SYNTH_LEAKS.exists() and REPORT_SYNTH.exists(), (
        "synth dataset/report missing; harness did not produce them"
    )
    leaks = _retained_leaks(SYNTH_LEAKS)
    modules = _load_modules(MODULES_PATH)
    frames, prefixes, _, _ = _load_yaml_config(SUPPRESSIONS_PATH)
    expected = {
        leak["leak_id"]: _expected_attribution(leak, modules, frames, prefixes)
        for leak in leaks
    }
    report = _load(REPORT_SYNTH)
    actual = {
        lid: (g["module_name"], g["top_frame"])
        for g in report["groups"]
        for lid in g["leak_ids"]
    }
    for lid, exp in expected.items():
        assert actual.get(lid) == exp, (
            f"synth leak {lid}: attribution {actual.get(lid)} != rule-derived {exp}"
        )


def test_module_aggregates_match_rule_derived_totals():
    """Each module row's (leaks, bytes, signatures, builtin) must equal the rule-derived per-module rollup."""
    leaks = _retained_leaks(LEAKS_PATH)
    modules = _load_modules(MODULES_PATH)
    frames, prefixes, _, _ = _load_yaml_config(SUPPRESSIONS_PATH)
    builtin = _module_builtin_map(modules)
    exp_leaks: dict[str, int] = {}
    exp_bytes: dict[str, int] = {}
    exp_sigs: dict[str, set[str]] = {}
    for leak in leaks:
        mod, _ = _expected_attribution(leak, modules, frames, prefixes)
        exp_leaks[mod] = exp_leaks.get(mod, 0) + 1
        exp_bytes[mod] = exp_bytes.get(mod, 0) + int(leak["size_bytes"])
        exp_sigs.setdefault(mod, set()).add(_signature(leak))
    report = _load(REPORT_PATH)
    actual = {m["module_name"]: m for m in report["modules"]}
    assert set(actual) == set(exp_leaks), (
        f"module set: actual={set(actual)} vs rule-derived={set(exp_leaks)}"
    )
    for mod, row in actual.items():
        assert row["leaks"] == exp_leaks[mod], f"{mod}.leaks: {row['leaks']} != {exp_leaks[mod]}"
        assert row["bytes"] == exp_bytes[mod], f"{mod}.bytes: {row['bytes']} != {exp_bytes[mod]}"
        assert row["signatures"] == len(exp_sigs[mod]), (
            f"{mod}.signatures: {row['signatures']} != {len(exp_sigs[mod])}"
        )
        assert row["builtin"] == builtin.get(mod, False), (
            f"{mod}.builtin: {row['builtin']} != {builtin.get(mod, False)}"
        )


def test_groups_collapse_with_rule_derived_membership():
    """Every group must contain EXACTLY the retained leaks that share its (truncated) signature."""
    leaks = _retained_leaks(LEAKS_PATH)
    by_sig: dict[str, list[dict]] = {}
    for leak in leaks:
        by_sig.setdefault(_signature(leak), []).append(leak)
    report = _load(REPORT_PATH)
    report_by_sig = {g["signature"]: g for g in report["groups"]}
    assert set(report_by_sig) == set(by_sig), (
        f"signature set mismatch: report={set(report_by_sig)} vs rule-derived={set(by_sig)}"
    )
    for sig, members in by_sig.items():
        g = report_by_sig[sig]
        expected_ids = sorted(m["leak_id"] for m in members)
        assert g["leak_ids"] == expected_ids, (
            f"signature {sig!r}: leak_ids {g['leak_ids']} != expected {expected_ids}"
        )
        assert g["leak_count"] == len(members)
        assert g["total_bytes"] == sum(int(m["size_bytes"]) for m in members)


def test_groups_sorted_with_sequential_ids_and_correct_tiebreaks():
    """Groups must sort by (-total_bytes, module ASC, signature ASC); group_id assigned sequentially from 1."""
    report = _load(REPORT_PATH)
    groups = report["groups"]
    assert [g["group_id"] for g in groups] == list(range(1, len(groups) + 1)), (
        f"group_ids not sequential from 1: {[g['group_id'] for g in groups]}"
    )
    prev = (-(10**18), "", "")
    for g in groups:
        key = (-g["total_bytes"], g["module_name"], g["signature"])
        assert key >= prev, f"groups out of order: {key} after {prev}"
        prev = key
    by_bytes: dict[int, list[dict]] = {}
    for g in groups:
        by_bytes.setdefault(g["total_bytes"], []).append(g)
    for total, cluster in by_bytes.items():
        if len(cluster) < 2:
            continue
        expected = sorted(cluster, key=lambda x: (x["module_name"], x["signature"]))
        assert cluster == expected, (
            f"tie-break wrong for total_bytes={total}: got "
            f"{[(g['module_name'], g['signature']) for g in cluster]}, "
            f"expected {[(g['module_name'], g['signature']) for g in expected]}"
        )


def test_aggregate_invariants_hold_on_all_three_datasets():
    """Per-module/global rollups must be internally consistent on default, extra, and synth datasets."""
    _check_invariants(_load(REPORT_PATH), _retained_leaks(LEAKS_PATH))
    _check_invariants(_load(REPORT_EXTRA), _retained_leaks(EXTRA_LEAKS))
    _check_invariants(_load(REPORT_SYNTH), _retained_leaks(SYNTH_LEAKS))


def test_group_attribution_consistent_across_all_member_leaks():
    """Every member leak of a group must INDEPENDENTLY resolve to the same (module, top_frame) the group is stamped with."""
    leaks_by_id = {leak["leak_id"]: leak for leak in _retained_leaks(LEAKS_PATH)}
    modules = _load_modules(MODULES_PATH)
    frames, prefixes, _, _ = _load_yaml_config(SUPPRESSIONS_PATH)
    report = _load(REPORT_PATH)
    for g in report["groups"]:
        attributions: set[tuple[str, str | None]] = set()
        for lid in g["leak_ids"]:
            leak = leaks_by_id.get(lid)
            if leak is None:
                continue
            attr = _expected_attribution(leak, modules, frames, prefixes)
            attributions.add(attr)
            assert attr == (g["module_name"], g["top_frame"]), (
                f"group {g['group_id']}: member {lid} resolves to {attr}, "
                f"but group is stamped ({g['module_name']!r}, {g['top_frame']!r})"
            )
        assert len(attributions) <= 1, (
            f"group {g['group_id']}: members produce conflicting attributions {attributions}"
        )


# -----------------------------------------------------------------------------
# Hard rule-interaction tests (new — target subtle cross-rule failure modes)
# -----------------------------------------------------------------------------


def test_max_age_sec_per_group_equals_max_member_age():
    """Each group's max_age_sec MUST equal max(age_sec) across its retained member leaks (on all three datasets).

    Cascade: an agent that aggregates max_age_sec on the un-filtered leaks set
    (i.e., before applying min_age_sec) will produce a larger value when a
    transient leak shares a signature with retained ones. An agent that picks
    the wrong field (first instead of max) will fail on multi-member groups.
    """
    for label, leaks_path, report_path in (
        ("default", LEAKS_PATH, REPORT_PATH),
        ("extra", EXTRA_LEAKS, REPORT_EXTRA),
        ("synth", SYNTH_LEAKS, REPORT_SYNTH),
    ):
        leaks = _retained_leaks(leaks_path)
        ages_by_sig: dict[str, list[float]] = {}
        for leak in leaks:
            ages_by_sig.setdefault(_signature(leak), []).append(float(leak["age_sec"]))
        report = _load(report_path)
        for g in report["groups"]:
            expected = max(ages_by_sig[g["signature"]])
            actual = float(g["max_age_sec"])
            assert abs(actual - expected) < 1e-9, (
                f"{label}.group {g['group_id']} (sig={g['signature']!r}): "
                f"max_age_sec={actual} != max(member ages)={expected}; "
                f"member ages={ages_by_sig[g['signature']]}"
            )


def test_builtin_flag_propagates_correctly_per_module():
    """Each non-unattributable module row's `builtin` MUST equal the value in modules.ndjson; 'unattributable' MUST be false.

    Easy to get wrong if you copy from the wrong source (kernels.json) or
    forget to default the synthetic row. This test pins both halves.
    """
    truth = {m["module_name"]: bool(m["builtin"]) for m in _load_modules(MODULES_PATH)}
    report = _load(REPORT_PATH)
    for row in report["modules"]:
        name = row["module_name"]
        if name == "unattributable":
            assert row["builtin"] is False, (
                f"synthetic 'unattributable' row must have builtin=false, got {row['builtin']!r}"
            )
            continue
        assert name in truth, (
            f"module {name!r} appears in report but is not declared in modules.ndjson"
        )
        assert row["builtin"] == truth[name], (
            f"module {name!r}: report.builtin={row['builtin']!r} != "
            f"modules.ndjson.builtin={truth[name]!r}"
        )


def test_truncation_runs_before_suppression_peeling():
    """For any leak whose top-N retained frames are ALL suppressed but whose untruncated backtrace has a real frame below N, attribution MUST be 'unattributable'.

    This is the exact trap that catches agents who suppress-then-truncate
    (or skip the cap entirely). The expected attribution is computed strictly
    from the truncated view; if an agent walks past max_backtrace_depth, the
    'unattributable' verdict will be wrong on these leaks.
    """
    _, _, _, max_depth = _load_yaml_config(SUPPRESSIONS_PATH)
    frames, prefixes, _, _ = _load_yaml_config(SUPPRESSIONS_PATH)
    raw_leaks = [
        json.loads(line)
        for line in LEAKS_PATH.read_text().splitlines()
        if line.strip()
    ]
    modules = _load_modules(MODULES_PATH)
    trapped_ids: list[str] = []
    for lk in raw_leaks:
        bt = lk["backtrace"]
        if len(bt) <= max_depth:
            continue
        top_n = bt[:max_depth]
        if not all(_is_suppressed(f["symbol"], frames, prefixes) for f in top_n):
            continue
        tail_has_attributable = any(
            (not _is_suppressed(f["symbol"], frames, prefixes))
            and _module_for_addr(f["addr"], modules) is not None
            for f in bt[max_depth:]
        )
        if tail_has_attributable:
            trapped_ids.append(lk["leak_id"])
    assert trapped_ids, (
        "test precondition: at least one leak must have all-suppressed top-N frames "
        "AND a real attributable frame past max_backtrace_depth"
    )
    report = _load(REPORT_PATH)
    actual = {
        lid: (g["module_name"], g["top_frame"])
        for g in report["groups"]
        for lid in g["leak_ids"]
    }
    for lid in trapped_ids:
        mod, top = actual[lid]
        assert mod == "unattributable", (
            f"truncate-before-suppress violation: leak {lid} has a real frame past "
            f"max_backtrace_depth={max_depth} but ALL frames within the cap are suppressed; "
            f"got module={mod!r}, top_frame={top!r} (must be 'unattributable')"
        )
        assert top is None, (
            f"leak {lid}: fully-suppressed retained backtrace must yield null top_frame, got {top!r}"
        )


def test_summary_host_and_scan_ts_mirror_kernels_json_first_object():
    """summary.host and summary.scan_ts MUST equal kernels.json[0].host and kernels.json[0].scan_ts on every dataset.

    instruction.md and INPUTS.md state these fields come from the first kernel
    record. The test asserts the EXACT values (not just non-empty/type) on the
    default, extra, and synth dataset reports — so any agent who reads from
    a later record, or echoes a wrong field, will fail here.
    """
    with KERNELS_PATH.open() as fh:
        first_kernel = json.load(fh)["kernels"][0]
    expected_host = first_kernel["host"]
    expected_scan_ts = first_kernel["scan_ts"]
    assert isinstance(expected_host, str) and expected_host, (
        "test precondition: kernels.json[0].host must be a non-empty string"
    )
    assert isinstance(expected_scan_ts, int), (
        "test precondition: kernels.json[0].scan_ts must be an int"
    )
    for label, report_path in (
        ("default", REPORT_PATH),
        ("extra", REPORT_EXTRA),
        ("synth", REPORT_SYNTH),
    ):
        report = _load(report_path)
        s = report["summary"]
        assert s["host"] == expected_host, (
            f"{label}.summary.host={s['host']!r} != kernels.json[0].host={expected_host!r}"
        )
        assert s["scan_ts"] == expected_scan_ts, (
            f"{label}.summary.scan_ts={s['scan_ts']} != kernels.json[0].scan_ts={expected_scan_ts}"
        )


def test_unattributable_module_row_present_iff_at_least_one_leak_failed():
    """The synthetic 'unattributable' module row must appear iff summary.unattributed_leaks > 0, with builtin=false and leak count equal to summary.unattributed_leaks.

    Closes the gap the quality checker flagged on Behavior In Tests: an agent
    that always emits an empty 'unattributable' row, or one that omits it
    when leaks DO fail attribution, will fail here.
    """
    report = _load(REPORT_PATH)
    summary_unattr = report["summary"]["unattributed_leaks"]
    module_names = [m["module_name"] for m in report["modules"]]
    if summary_unattr > 0:
        assert "unattributable" in module_names, (
            f"summary.unattributed_leaks={summary_unattr} but no 'unattributable' module row"
        )
        unattr_row = next(m for m in report["modules"] if m["module_name"] == "unattributable")
        assert unattr_row["builtin"] is False, (
            f"'unattributable' module row must have builtin=false, got {unattr_row['builtin']!r}"
        )
        assert unattr_row["leaks"] == summary_unattr, (
            f"'unattributable'.leaks={unattr_row['leaks']} != summary.unattributed_leaks={summary_unattr}"
        )
    else:
        assert "unattributable" not in module_names, (
            "summary.unattributed_leaks=0 but 'unattributable' module row was emitted"
        )


def test_top_frame_is_first_non_suppressed_retained_frame_exactly():
    """For every retained leak with at least one non-suppressed retained frame, top_frame MUST be that exact symbol.

    Cascade: agents who pick the deepest non-suppressed frame, or the bottom
    of the retained backtrace, or skip past too many frames, will fail here.
    """
    frames, prefixes, _, _ = _load_yaml_config(SUPPRESSIONS_PATH)
    leaks = _retained_leaks(LEAKS_PATH)
    report = _load(REPORT_PATH)
    actual_top = {
        lid: g["top_frame"]
        for g in report["groups"]
        for lid in g["leak_ids"]
    }
    exercised = 0
    for leak in leaks:
        first_non_supp = None
        for f in leak["backtrace"]:
            if not _is_suppressed(f["symbol"], frames, prefixes):
                first_non_supp = f["symbol"]
                break
        if first_non_supp is None:
            continue
        exercised += 1
        assert actual_top[leak["leak_id"]] == first_non_supp, (
            f"leak {leak['leak_id']}: top_frame={actual_top[leak['leak_id']]!r} "
            f"!= first non-suppressed retained symbol {first_non_supp!r}"
        )
    assert exercised >= 10, (
        f"test precondition: ≥10 retained leaks must have at least one non-suppressed frame; got {exercised}"
    )
