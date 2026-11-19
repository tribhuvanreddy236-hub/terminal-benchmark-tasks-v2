"""Verification for service trust boundary analyzer (Go mesh trust replayer)."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import subprocess
import zlib
from pathlib import Path
from typing import Any

import pytest

REPORT_PATH = Path("/app/build/service_trust_boundary_report.json")
REPORT_FIRST = Path("/logs/verifier/report_first.json")
VERIFIER_DIR = Path("/logs/verifier")
DATA_DIR = Path("/app/data")
MANIFEST_PATH = DATA_DIR / "manifest.json"
APP_DIR = Path("/app")
BINARY = APP_DIR / "build" / "trustbound"
MAIN_GO = APP_DIR / "cmd" / "trustbound" / "main.go"
MAKEFILE = APP_DIR / "Makefile"

SCENARIO_KEY_ORDER = [
    "scenario_id",
    "status",
    "duplicate_events_skipped",
    "capture",
    "peer_trust_edges",
    "services",
    "findings",
]

CAPTURE_KEY_ORDER = [
    "format_version",
    "records_total",
    "records_valid",
    "records_rejected",
    "dup_seq_rejects",
    "truncated_tail",
    "payload_bytes",
]

FINDING_KINDS = frozenset(
    {
        "UNVERIFIED_CALLER",
        "PRIVILEGE_ESCALATION",
        "UNTRUSTED_PEER",
        "UNKNOWN_CALLEE",
        "UNKNOWN_CALLER",
        "DUPLICATE_SERVICE",
        "DUPLICATE_TRUST",
        "LATERAL_MOVEMENT",
        "RESTRICTED_ESCALATION",
        "MESH_ASYMMETRY",
        "OPEN_PRIVILEGE_PATH",
        "ADMIN_UNBOUND",
    }
)

FINDING_ID_RE = re.compile(r"^[^:]+::[^:]+::\d{4}$")
TRUST_RISK_VALUES = frozenset({"none", "elevated", "critical"})
IMMUTABLE_SHA256: dict[str, str] = {}


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decode_capture_bytes(data: bytes) -> tuple[dict[str, int], list[dict[str, Any]]]:
    """Decode PCM1 little-endian capture per CAPTURE_FORMAT.md."""
    if len(data) < 8 or data[:4] != b"PCM1":
        raise ValueError("bad magic")
    format_version = struct.unpack_from("<I", data, 4)[0]
    stats: dict[str, int] = {
        "format_version": format_version,
        "records_total": 0,
        "records_valid": 0,
        "records_rejected": 0,
        "dup_seq_rejects": 0,
        "truncated_tail": 0,
        "payload_bytes": 0,
    }
    if format_version != 1:
        raise ValueError("unsupported format_version")
    off = 8
    seen: set[int] = set()
    events: list[dict[str, Any]] = []
    while off < len(data):
        if off + 12 > len(data):
            stats["records_rejected"] += 1
            stats["truncated_tail"] = 1
            break
        record_seq, flags, reserved, plen = struct.unpack_from("<I H H I", data, off)
        off += 12
        stats["records_total"] += 1
        reason = ""
        if reserved != 0:
            reason = "BAD_RESERVED"
        elif flags != 0:
            reason = "BAD_FLAGS"
        elif plen > 4096:
            reason = "LEN_OVERFLOW"
        elif record_seq in seen:
            reason = "DUP_SEQ"
        if reason == "LEN_OVERFLOW":
            if off + plen + 4 <= len(data):
                off += plen + 4
                stats["records_rejected"] += 1
                seen.add(record_seq)
                continue
            stats["records_rejected"] += 1
            stats["truncated_tail"] = 1
            break
        if off + plen + 4 > len(data):
            stats["records_rejected"] += 1
            stats["truncated_tail"] = 1
            break
        payload = data[off : off + plen]
        off += plen
        checksum = struct.unpack_from("<I", data, off)[0]
        off += 4
        if reason == "":
            hdr = struct.pack("<I H H I", record_seq, flags, reserved, plen)
            if zlib.crc32(hdr + payload) & 0xFFFFFFFF != checksum:
                reason = "BAD_CRC"
        seen.add(record_seq)
        if reason:
            stats["records_rejected"] += 1
            if reason == "DUP_SEQ":
                stats["dup_seq_rejects"] += 1
            continue
        events.append(json.loads(payload.decode("utf-8")))
        stats["records_valid"] += 1
        stats["payload_bytes"] += plen
    return stats, events


def decode_capture(path: Path) -> tuple[dict[str, int], list[dict[str, Any]]]:
    return decode_capture_bytes(path.read_bytes())


def _run_make(target: str, log_name: str) -> None:
    VERIFIER_DIR.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["make", target],
        cwd=APP_DIR,
        capture_output=True,
        text=True,
    )
    (VERIFIER_DIR / log_name).write_text(proc.stdout + proc.stderr, encoding="utf-8")
    if proc.returncode != 0:
        pytest.fail(f"make {target} failed; see /logs/verifier/{log_name}")


@pytest.fixture(scope="session", autouse=True)
def _verifier_preflight() -> None:
    """Build trustbound and snapshot first run for byte-identical rerun checks."""
    VERIFIER_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.unlink(missing_ok=True)
    for path in VERIFIER_DIR.glob("*.log"):
        path.unlink()

    _run_make("build", "build.log")
    _run_make("run", "run.log")
    if not REPORT_PATH.is_file():
        pytest.fail("service_trust_boundary_report.json missing after make run")
    shutil.copy(REPORT_PATH, REPORT_FIRST)

    _run_make("run", "run2.log")
    if REPORT_PATH.read_bytes() != REPORT_FIRST.read_bytes():
        pytest.fail("make run not byte-identical across consecutive invocations")


@pytest.fixture(scope="session", autouse=True)
def _capture_immutable_hashes(_verifier_preflight: None) -> None:
    """Record SHA-256 of bundled data and docs (including capture.pcm trees)."""
    if IMMUTABLE_SHA256:
        return
    for rel in ("Makefile", "go.mod"):
        IMMUTABLE_SHA256[rel] = _sha256_file(APP_DIR / rel)
    for subdir in ("docs", "data"):
        root = APP_DIR / subdir
        for path in sorted(root.rglob("*")):
            if path.is_file():
                rel = path.relative_to(APP_DIR).as_posix()
                IMMUTABLE_SHA256[rel] = _sha256_file(path)


def _finding_id(sid: str, entity: str, seq: int) -> str:
    return f"{sid}::{entity}::{seq:04d}"


def _resolve_bools(scenario: dict[str, Any]) -> tuple[bool, bool]:
    require = bool(scenario.get("require_token_on_internal", True))
    block = bool(scenario.get("block_partner_to_privileged", True))
    overrides = scenario.get("policy_overrides") or {}
    if "require_token_on_internal" in overrides:
        require = bool(overrides["require_token_on_internal"])
    if "block_partner_to_privileged" in overrides:
        block = bool(overrides["block_partner_to_privileged"])
    return require, block


def _trust_risk(tier: str) -> str:
    if tier == "partner":
        return "elevated"
    if tier == "privileged":
        return "critical"
    return "none"


def analyze_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    """Independent replay implementing /app/docs/TRUST_RULES.md from bundled capture."""
    sid = scenario["scenario_id"]
    cap_stats, events = decode_capture(DATA_DIR / sid / "capture.pcm")
    require_token, block_partner = _resolve_bools(scenario)
    services: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str]] = set()
    findings: list[dict[str, Any]] = []
    dup_skipped = 0
    seen_event: set[str] = set()
    priv_flagged: set[str] = set()
    max_seq = 0

    events = sorted(
        events,
        key=lambda e: (e["seq"], e.get("service_id", ""), e.get("event_id", "")),
    )

    def add_finding(entity: str, kind: str, seq: int, action: str = "", detail: str = "") -> None:
        findings.append(
            {
                "finding_id": _finding_id(sid, entity, seq),
                "entity_id": entity,
                "kind": kind,
                "event_seq": seq,
                "action": action,
                "detail": detail,
            }
        )

    def has_edge(frm: str, to: str) -> bool:
        return (frm, to) in edges

    def first_missing(caps: set[str], propagated: list[str]) -> str:
        missing = sorted(p for p in propagated if p not in caps)
        return missing[0] if missing else ""

    for ev in events:
        seq = ev["seq"]
        max_seq = max(max_seq, seq)
        kind = ev["kind"]
        eid = ev.get("event_id", "")
        if eid:
            if eid in seen_event:
                dup_skipped += 1
                continue
            seen_event.add(eid)

        if kind == "REGISTER_SERVICE":
            svc = ev["service_id"]
            if svc in services:
                add_finding(svc, "DUPLICATE_SERVICE", seq)
                continue
            services[svc] = {"tier": ev["tier"], "caps": set()}
            continue

        if kind == "ALLOW_TRUST":
            frm, to = ev["from_service"], ev["to_service"]
            if frm not in services:
                add_finding(frm, "UNKNOWN_CALLER", seq, detail=kind)
                continue
            if to not in services:
                add_finding(to, "UNKNOWN_CALLEE", seq, detail=kind)
                continue
            if (frm, to) in edges:
                add_finding(to, "DUPLICATE_TRUST", seq, detail=frm)
                continue
            edges.add((frm, to))
            continue

        if kind == "REVOKE_TRUST":
            frm, to = ev["from_service"], ev["to_service"]
            if frm not in services:
                add_finding(frm, "UNKNOWN_CALLER", seq, detail=kind)
                continue
            if to not in services:
                add_finding(to, "UNKNOWN_CALLEE", seq, detail=kind)
                continue
            edges.discard((frm, to))
            continue

        if kind == "BIND_CAPABILITY":
            svc = ev["service_id"]
            if svc not in services:
                add_finding(svc, "UNKNOWN_CALLER", seq, detail=kind)
                continue
            services[svc]["caps"].add(ev["capability"])
            continue

        if kind == "SERVICE_CALL":
            caller, callee = ev["caller_id"], ev["callee_id"]
            action = ev.get("action", "")
            propagated = ev.get("propagated_capabilities") or []
            if callee not in services:
                add_finding(callee, "UNKNOWN_CALLEE", seq, action=action, detail=kind)
                continue
            if caller not in services:
                add_finding(caller, "UNKNOWN_CALLER", seq, action=action, detail=kind)
                continue
            if not has_edge(caller, callee):
                add_finding(callee, "UNTRUSTED_PEER", seq, action=action, detail=caller)
                continue
            if (
                block_partner
                and services[caller]["tier"] == "partner"
                and services[callee]["tier"] == "privileged"
            ):
                add_finding(caller, "RESTRICTED_ESCALATION", seq, action=action, detail=callee)
                continue
            if require_token and services[callee]["tier"] == "internal" and not ev.get("has_token"):
                add_finding(callee, "UNVERIFIED_CALLER", seq, action=action)
                continue
            miss = first_missing(services[caller]["caps"], propagated)
            if miss:
                key = f"{caller}::{miss}"
                if key not in priv_flagged:
                    priv_flagged.add(key)
                    add_finding(caller, "PRIVILEGE_ESCALATION", seq, action=action, detail=miss)
            orig = ev.get("original_caller") or ""
            if orig and orig != caller:
                miss2 = first_missing(services[caller]["caps"], propagated)
                if miss2:
                    add_finding(orig, "LATERAL_MOVEMENT", seq, action=action, detail=miss2)

    audit_seq = max_seq + 1
    mesh_flagged: set[str] = set()
    open_flagged: set[str] = set()

    for frm, to in sorted(edges):
        if frm not in services or to not in services:
            continue
        if services[frm]["tier"] == "partner" and services[to]["tier"] == "internal":
            mkey = f"{frm}::{to}"
            if mkey not in mesh_flagged and not has_edge(to, frm):
                mesh_flagged.add(mkey)
                add_finding(to, "MESH_ASYMMETRY", audit_seq, detail=frm)

    for svc_id in sorted(services):
        st = services[svc_id]
        if st["tier"] != "privileged":
            continue
        if "mesh:audit" in st["caps"]:
            continue
        partners = sorted(
            frm
            for frm, to in edges
            if to == svc_id and frm in services and services[frm]["tier"] == "partner"
        )
        if partners and svc_id not in open_flagged:
            open_flagged.add(svc_id)
            add_finding(svc_id, "OPEN_PRIVILEGE_PATH", audit_seq, detail=partners[0])

    for svc_id in sorted(services):
        if services[svc_id]["tier"] == "privileged" and "mesh:admin" not in services[svc_id]["caps"]:
            add_finding(svc_id, "ADMIN_UNBOUND", audit_seq)

    edge_out = [
        {"from_service": frm, "to_service": to}
        for frm, to in sorted(edges)
    ]
    out_services = [
        {
            "service_id": svc_id,
            "tier": services[svc_id]["tier"],
            "capabilities": sorted(services[svc_id]["caps"]),
            "trust_boundary_risk": _trust_risk(services[svc_id]["tier"]),
        }
        for svc_id in sorted(services)
    ]

    findings.sort(key=lambda f: f["finding_id"])
    capture = {k: cap_stats[k] for k in CAPTURE_KEY_ORDER}
    return {
        "scenario_id": sid,
        "status": "VALID" if not findings else "INVALID",
        "duplicate_events_skipped": dup_skipped,
        "capture": capture,
        "peer_trust_edges": edge_out,
        "services": out_services,
        "findings": findings,
    }


def _build_report() -> dict[str, Any]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return {
        "scenarios": [
            analyze_scenario(json.loads((DATA_DIR / f"{sid}.json").read_text(encoding="utf-8")))
            for sid in manifest["scenarios"]
        ]
    }


def _scenario_row(report: dict[str, Any], scenario_id: str) -> dict[str, Any]:
    for row in report["scenarios"]:
        if row["scenario_id"] == scenario_id:
            return row
    raise KeyError(scenario_id)


@pytest.fixture(scope="module")
def report() -> dict[str, Any]:
    assert REPORT_PATH.is_file(), f"missing {REPORT_PATH}"
    return json.loads(REPORT_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def expected_report() -> dict[str, Any]:
    return _build_report()


def _report_digest(report: dict[str, Any]) -> str:
    payload = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _assert_no_json_null(value: Any, path: str = "report") -> None:
    if value is None:
        raise AssertionError(f"null at {path}")
    if isinstance(value, dict):
        for key, item in value.items():
            _assert_no_json_null(item, f"{path}.{key}")
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            _assert_no_json_null(item, f"{path}[{idx}]")


def _assert_schema_sort_order(row: dict[str, Any]) -> None:
    edges = row["peer_trust_edges"]
    assert edges == sorted(edges, key=lambda e: (e["from_service"], e["to_service"]))
    svc_ids = [s["service_id"] for s in row["services"]]
    assert svc_ids == sorted(svc_ids)
    for svc in row["services"]:
        assert svc["capabilities"] == sorted(svc["capabilities"])
    finding_ids = [f["finding_id"] for f in row["findings"]]
    assert finding_ids == sorted(finding_ids)


def test_full_replay_equivalence_invariant(
    report: dict[str, Any], expected_report: dict[str, Any]
) -> None:
    """Every manifest scenario must match the rules-engine replay with no drift."""
    assert report == expected_report
    kinds = {f["kind"] for row in report["scenarios"] for f in row["findings"]}
    assert kinds == FINDING_KINDS
    assert len(report["scenarios"]) == 20
    assert _report_digest(report) == _report_digest(expected_report)


def test_solution_contract_integrity(report: dict[str, Any]) -> None:
    """Bundled immutability, manifest order, schema keys, compact JSON, determinism."""
    for path in APP_DIR.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(APP_DIR).as_posix()
        if rel.startswith(("cmd/", "internal/", "build/")):
            continue
        assert rel in IMMUTABLE_SHA256, f"untracked path {rel}"
        assert _sha256_file(path) == IMMUTABLE_SHA256[rel], f"modified {rel}"

    expected_ids = [f"dataset_{i:02d}" for i in range(1, 21)]
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["scenarios"] == expected_ids
    assert [row["scenario_id"] for row in report["scenarios"]] == expected_ids

    for row in report["scenarios"]:
        assert list(row.keys()) == SCENARIO_KEY_ORDER
        assert list(row["capture"].keys()) == CAPTURE_KEY_ORDER
        for finding in row["findings"]:
            assert FINDING_ID_RE.match(finding["finding_id"])
            assert finding["kind"] in FINDING_KINDS

    _assert_no_json_null(report)
    raw = REPORT_PATH.read_bytes()
    assert raw.endswith(b"\n") and b": " not in raw and b", " not in raw
    assert b"null" not in raw
    canonical = json.dumps(report, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    assert raw == canonical
    assert REPORT_FIRST.is_file() and raw == REPORT_FIRST.read_bytes()


def test_scenario_arrays_sorted_per_schema_md(report: dict[str, Any]) -> None:
    """peer_trust_edges, services, findings follow SCHEMA.md sort order."""
    for row in report["scenarios"]:
        _assert_schema_sort_order(row)


def test_edit_scope_top_level_app_allowlist() -> None:
    allowed_top = {"cmd", "internal", "build", "docs", "data", "go.mod", "Makefile"}
    for entry in APP_DIR.iterdir():
        assert entry.name in allowed_top, f"unexpected /app/{entry.name}"


def test_make_build_artifact_only_under_build_dir() -> None:
    assert not (APP_DIR / "trustbound").exists()
    assert (APP_DIR / "build" / "trustbound").is_file()


def test_cross_run_replay_byte_identity_chain(report: dict[str, Any]) -> None:
    """Consecutive make run on unchanged /app/data must leave a byte-identical report."""
    raw = REPORT_PATH.read_bytes()
    assert raw.endswith(b"\n")
    assert REPORT_FIRST.is_file()
    assert raw == REPORT_FIRST.read_bytes()


def test_immutable_bundled_files_unmodified() -> None:
    """Makefile, go.mod, docs/, and data/ must remain byte-identical to the image."""
    for rel, expected in IMMUTABLE_SHA256.items():
        path = APP_DIR / rel
        assert path.is_file(), rel
        assert _sha256_file(path) == expected, rel


def test_report_path_is_absolute_app_build_target() -> None:
    """Report must live at the absolute path /app/build/service_trust_boundary_report.json."""
    assert REPORT_PATH.is_file()
    assert str(REPORT_PATH) == "/app/build/service_trust_boundary_report.json"
    assert REPORT_PATH.name == "service_trust_boundary_report.json"


def test_report_is_regular_file_not_symlink() -> None:
    """Report output must be a regular file, not a symlink or directory."""
    assert REPORT_PATH.is_file() and not REPORT_PATH.is_symlink()


def test_build_directory_contains_only_trustbound_and_report() -> None:
    """After make run, /app/build contains only trustbound and the report JSON."""
    build_dir = APP_DIR / "build"
    names = {p.name for p in build_dir.iterdir()}
    assert names == {"trustbound", "service_trust_boundary_report.json"}


def test_bundled_captures_live_under_app_data_directories() -> None:
    """Each scenario PCM1 capture must exist at /app/data/{id}/capture.pcm."""
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for sid in manifest["scenarios"]:
        cap = DATA_DIR / sid / "capture.pcm"
        assert cap.is_file(), f"missing bundled capture at absolute path {cap}"
        assert cap.read_bytes()[:4] == b"PCM1"


def test_main_go_uses_absolute_app_data_paths() -> None:
    """trustbound main must use absolute /app/data and /app/build paths per instruction.md."""
    text = MAIN_GO.read_text(encoding="utf-8")
    assert '"/app/data"' in text
    assert "capture.pcm" in text
    assert "/app/build/service_trust_boundary_report.json" in text
    assert "manifest.json" in text


def test_makefile_uses_absolute_build_output_path() -> None:
    """Makefile must write the binary to /app/build/trustbound."""
    text = MAKEFILE.read_text(encoding="utf-8")
    assert "/app/build/trustbound" in text or "build/trustbound" in text


def test_scenario_config_json_has_no_events_array() -> None:
    """Each /app/data/{id}.json must be scenario defaults only (no events array)."""
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for sid in manifest["scenarios"]:
        obj = json.loads((DATA_DIR / f"{sid}.json").read_text(encoding="utf-8"))
        assert "events" not in obj, f"{sid}.json must not contain events (use capture.pcm)"


def test_program_capture_records_total_only_full_headers(report: dict[str, Any]) -> None:
    """Program capture.records_total follows CAPTURE_FORMAT: only complete 12-byte headers count."""
    blob = b"PCM1" + struct.pack("<I", 1) + b"\x01\x02\x03"
    ref_stats, _ = decode_capture_bytes(blob)
    assert ref_stats["records_total"] == 0
    assert ref_stats["records_rejected"] >= 1
    assert ref_stats["truncated_tail"] == 1
    for sc in report["scenarios"]:
        dec_stats, _ = decode_capture(DATA_DIR / sc["scenario_id"] / "capture.pcm")
        assert sc["capture"]["records_total"] == dec_stats["records_total"], sc["scenario_id"]


def test_capture_format_version_one(report: dict[str, Any]) -> None:
    """Each scenario capture block must report PCM1 format_version 1."""
    for sc in report["scenarios"]:
        assert sc["capture"]["format_version"] == 1


def test_report_capture_stats_match_pcm1_decoder(report: dict[str, Any]) -> None:
    """Each capture block matches independent LE PCM1 decode (payload_len, CRC, dup_seq, etc.)."""
    for sc in report["scenarios"]:
        stats, _ = decode_capture(DATA_DIR / sc["scenario_id"] / "capture.pcm")
        expected = {k: stats[k] for k in CAPTURE_KEY_ORDER}
        assert sc["capture"] == expected, sc["scenario_id"]


def test_dataset_05_capture_dup_seq_rejects(report: dict[str, Any]) -> None:
    """dataset_05 bundled capture includes duplicate record_seq rejection."""
    row = _scenario_row(report, "dataset_05")
    assert row["capture"]["dup_seq_rejects"] == 1


def test_dataset_20_capture_truncated_tail(report: dict[str, Any]) -> None:
    """dataset_20 bundled capture ends with a truncated tail frame."""
    row = _scenario_row(report, "dataset_20")
    assert row["capture"]["truncated_tail"] == 1


def test_capture_nonzero_reserved_or_flags_rejects() -> None:
    """PCM1 record flags and reserved must be zero or the frame is rejected."""
    ev = {
        "seq": 1,
        "event_id": "e1",
        "service_id": "billing",
        "kind": "REGISTER_SERVICE",
        "tier": "internal",
    }
    payload = json.dumps(ev, separators=(",", ":")).encode("utf-8")
    plen = len(payload)
    hdr_bad_reserved = struct.pack("<I H H I", 1, 0, 1, plen)
    blob_reserved = (
        b"PCM1"
        + struct.pack("<I", 1)
        + hdr_bad_reserved
        + payload
        + struct.pack("<I", zlib.crc32(hdr_bad_reserved + payload) & 0xFFFFFFFF)
    )
    stats_r, _ = decode_capture_bytes(blob_reserved)
    assert stats_r["records_rejected"] == 1
    hdr_bad_flags = struct.pack("<I H H I", 1, 1, 0, plen)
    blob_flags = (
        b"PCM1"
        + struct.pack("<I", 1)
        + hdr_bad_flags
        + payload
        + struct.pack("<I", zlib.crc32(hdr_bad_flags + payload) & 0xFFFFFFFF)
    )
    stats_f, _ = decode_capture_bytes(blob_flags)
    assert stats_f["records_rejected"] == 1


def test_capture_header_truncated_tail_does_not_increment_records_total() -> None:
    """Header-truncated tail increments records_rejected but not records_total."""
    ev = {
        "seq": 1,
        "event_id": "e1",
        "service_id": "billing",
        "kind": "REGISTER_SERVICE",
        "tier": "internal",
    }
    payload = json.dumps(ev, separators=(",", ":")).encode("utf-8")
    rec_hdr = struct.pack("<I H H I", 1, 0, 0, len(payload))
    checksum = zlib.crc32(rec_hdr + payload) & 0xFFFFFFFF
    blob = b"PCM1" + struct.pack("<I", 1) + rec_hdr + payload + struct.pack("<I", checksum) + b"\xab"
    stats, events = decode_capture_bytes(blob)
    assert stats["records_total"] == 1
    assert stats["records_valid"] == 1
    assert stats["records_rejected"] == 1
    assert stats["truncated_tail"] == 1
    assert len(events) == 1


def test_capture_len_overflow_rejects_without_truncated_tail() -> None:
    """payload_len above 4096 rejects the frame per CAPTURE_FORMAT.md buffer cap."""
    rec_hdr = struct.pack("<I H H I", 1, 0, 0, 5000)
    blob = b"PCM1" + struct.pack("<I", 1) + rec_hdr + (b"\x00" * 5000) + struct.pack("<I", 0)
    stats, events = decode_capture_bytes(blob)
    assert stats["records_rejected"] == 1
    assert stats["truncated_tail"] == 0
    assert events == []


def test_capture_valid_crc_over_le_twelve_byte_header_plus_payload() -> None:
    """CRC-32 (IEEE) is computed over the 12-byte LE record header concatenated with payload."""
    ev = {
        "seq": 1,
        "event_id": "e1",
        "service_id": "orders",
        "kind": "BIND_CAPABILITY",
        "capability": "billing:read",
    }
    payload = json.dumps(ev, separators=(",", ":")).encode("utf-8")
    rec_hdr = struct.pack("<I H H I", 1, 0, 0, len(payload))
    checksum = zlib.crc32(rec_hdr + payload) & 0xFFFFFFFF
    blob = b"PCM1" + struct.pack("<I", 1) + rec_hdr + payload + struct.pack("<I", checksum)
    stats, events = decode_capture_bytes(blob)
    assert stats["records_valid"] == 1
    assert stats["records_rejected"] == 0
    assert len(events) == 1


def test_capture_bad_crc_counts_rejected() -> None:
    """CRC-32 over the 12-byte LE header plus payload rejects bad checksums."""
    ev = {
        "seq": 1,
        "event_id": "e1",
        "service_id": "billing",
        "kind": "REGISTER_SERVICE",
        "tier": "internal",
    }
    payload = json.dumps(ev, separators=(",", ":")).encode("utf-8")
    rec_hdr = struct.pack("<I H H I", 1, 0, 0, len(payload))
    blob = b"PCM1" + struct.pack("<I", 1) + rec_hdr + payload + struct.pack("<I", 0)
    stats, events = decode_capture_bytes(blob)
    assert stats["records_rejected"] == 1
    assert stats["records_valid"] == 0
    assert events == []


def test_capture_partial_payload_truncates_body() -> None:
    """Partial payload bytes after a full header set truncated_tail and stop decoding."""
    ev = {
        "seq": 1,
        "event_id": "e1",
        "service_id": "billing",
        "kind": "REGISTER_SERVICE",
        "tier": "internal",
    }
    payload = json.dumps(ev, separators=(",", ":")).encode("utf-8")
    rec_hdr = struct.pack("<I H H I", 1, 0, 0, len(payload))
    blob = b"PCM1" + struct.pack("<I", 1) + rec_hdr + payload[:4]
    stats, events = decode_capture_bytes(blob)
    assert stats["records_total"] == 1
    assert stats["records_rejected"] == 1
    assert stats["truncated_tail"] == 1
    assert events == []


def test_perturbed_capture_changes_report_then_restores(report: dict[str, Any]) -> None:
    """Anti-cheat: perturbing a bundled capture must change replay output; restore yields baseline."""
    sid = "dataset_01"
    cap_path = DATA_DIR / sid / "capture.pcm"
    clean = VERIFIER_DIR / f"{sid}_capture_clean.pcm"
    shutil.copy(cap_path, clean)
    baseline = REPORT_PATH.read_bytes()
    try:
        data = bytearray(cap_path.read_bytes())
        if len(data) > 20:
            data[20] ^= 0xFF
        cap_path.write_bytes(data)
        REPORT_PATH.unlink(missing_ok=True)
        _run_make("run", "perturb_run.log")
        assert REPORT_PATH.read_bytes() != baseline
    finally:
        shutil.copy(clean, cap_path)
        REPORT_PATH.unlink(missing_ok=True)
        _run_make("run", "restore_run.log")
        assert REPORT_PATH.read_bytes() == baseline


def test_main_go_rejects_shell_substitution_paths() -> None:
    """main.go must not use command substitution for /app paths."""
    text = MAIN_GO.read_text(encoding="utf-8")
    assert "$(" not in text
    assert "; curl" not in text
    assert "bash -c" not in text


def test_data_paths_are_absolute_under_app() -> None:
    """Bundled data directory lives at absolute /app/data (not a symlink)."""
    assert DATA_DIR.is_dir()
    assert str(DATA_DIR) == "/app/data"
    assert not DATA_DIR.is_symlink()


def test_trustbound_binary_is_regular_file_not_symlink() -> None:
    """Built trustbound binary must be a regular file under /app/build."""
    assert BINARY.is_file() and not BINARY.is_symlink()


def test_unverified_caller_empty_detail(report: dict[str, Any]) -> None:
    row = _scenario_row(report, "dataset_05")
    finding = next(f for f in row["findings"] if f["kind"] == "UNVERIFIED_CALLER")
    assert finding["detail"] == ""


def test_trust_boundary_risk_by_tier(report: dict[str, Any]) -> None:
    for row in report["scenarios"]:
        for svc in row["services"]:
            assert svc["trust_boundary_risk"] in TRUST_RISK_VALUES
            if svc["tier"] == "internal":
                assert svc["trust_boundary_risk"] == "none"
            elif svc["tier"] == "partner":
                assert svc["trust_boundary_risk"] == "elevated"
            elif svc["tier"] == "privileged":
                assert svc["trust_boundary_risk"] == "critical"


def test_policy_override_allows_partner_privileged_call(report: dict[str, Any]) -> None:
    row = _scenario_row(report, "dataset_15")
    assert row["status"] == "VALID"


def test_duplicate_events_skipped_dataset_14(report: dict[str, Any]) -> None:
    row = _scenario_row(report, "dataset_14")
    assert row["duplicate_events_skipped"] == 1
    assert row["status"] == "VALID"


def test_admin_unbound_empty_detail(report: dict[str, Any]) -> None:
    row = _scenario_row(report, "dataset_13")
    finding = next(f for f in row["findings"] if f["kind"] == "ADMIN_UNBOUND")
    assert finding["detail"] == ""


def test_privilege_escalation_first_missing_sorted(report: dict[str, Any]) -> None:
    row = _scenario_row(report, "dataset_20")
    kinds = [f["kind"] for f in row["findings"]]
    assert kinds.count("PRIVILEGE_ESCALATION") == 2
    details = [f["detail"] for f in row["findings"] if f["kind"] == "PRIVILEGE_ESCALATION"]
    assert details == ["b", "c"]


def test_dataset_01_valid_clean_fixtures(report: dict[str, Any]) -> None:
    row = _scenario_row(report, "dataset_01")
    assert row["status"] == "VALID"
    assert row["findings"] == []
