"""Behavioral verifier for the QuarryDB recovery task."""

import hashlib
import os
import shutil
import signal
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

APP = Path("/app")
SEALED_ROOT = Path("/tests/sealed")
WORK = Path("/work")
SANDBOX_UID = 12000
SANDBOX_GID = 12000
CASE_IDS = {
    "primary": "c4a8e7f1",
    "activation": "19bd62a4",
    "transactions": "e7310cb9",
    "tombstones": "54a90df2",
    "composed": "a826f35c",
}


def _load_sealed():
    if not SEALED_ROOT.is_dir():
        raise RuntimeError("sealed verifier material is missing")
    material = {
        path.relative_to(SEALED_ROOT).as_posix(): path.read_bytes()
        for path in SEALED_ROOT.rglob("*")
        if path.is_file()
    }
    shutil.rmtree(SEALED_ROOT)
    return material


SEALED = _load_sealed()


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assert_plain_tree(root):
    for path in [root, *root.rglob("*")]:
        mode = path.lstat().st_mode
        assert not stat.S_ISLNK(mode), f"symbolic links are not accepted: {path}"
        assert stat.S_ISREG(mode) or stat.S_ISDIR(mode), f"special filesystem entry: {path}"


def chown_tree(root):
    for path in [root, *root.rglob("*")]:
        os.chown(path, SANDBOX_UID, SANDBOX_GID, follow_symlinks=False)


def run_sandbox(command, cwd, timeout=90):
    cwd = Path(cwd)
    home = cwd / ".h"
    if home.exists():
        shutil.rmtree(home)
    home.mkdir()
    os.chown(home, SANDBOX_UID, SANDBOX_GID)
    env = {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "PATH": "/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONSAFEPATH": "1",
        "RUSTUP_HOME": "/usr/local/rustup",
        "CARGO_HOME": "/usr/local/cargo",
    }
    secured = ["setpriv", "--no-new-privs", "--", *command]
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(
            secured,
            cwd=cwd,
            env=env,
            stdout=stdout,
            stderr=stderr,
            user=SANDBOX_UID,
            group=SANDBOX_GID,
            extra_groups=[],
            start_new_session=True,
        )
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            returncode = -signal.SIGKILL
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        stdout.seek(0)
        stderr.seek(0)
        return subprocess.CompletedProcess(command, returncode, stdout.read().decode(errors="replace"), stderr.read().decode(errors="replace"))


def materialize(prefix, destination):
    marker = prefix.rstrip("/") + "/"
    for name, data in SEALED.items():
        if name.startswith(marker):
            target = destination / name[len(marker):]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)


@pytest.fixture(scope="session")
def binary():
    assert_plain_tree(APP)
    build = WORK / "build"
    if build.exists():
        shutil.rmtree(build)
    build.mkdir()
    shutil.copytree(APP / "src", build / "src", symlinks=True)
    chown_tree(build)
    result = run_sandbox(
        ["rustc", "--edition=2021", "-C", "opt-level=2", "-o", str(build / "qrecover"), "src/main.rs"],
        build,
        180,
    )
    assert result.returncode == 0, f"Rust rebuild failed:\n{result.stdout}\n{result.stderr}"
    assert (build / "qrecover").is_file(), "rebuild did not produce qrecover"
    os.chown(build / "qrecover", 0, 0)
    os.chmod(build / "qrecover", 0o555)
    return build / "qrecover"


@pytest.fixture(scope="session")
def results(binary):
    output = {}
    primary = WORK / "cases" / CASE_IDS["primary"]
    if primary.exists():
        shutil.rmtree(primary)
    shutil.copytree(APP / "store", primary / "store", symlinks=True)
    chown_tree(primary)
    for name in ["primary", "activation", "transactions", "tombstones", "composed"]:
        case = primary if name == "primary" else WORK / "cases" / CASE_IDS[name]
        if name != "primary":
            if case.exists():
                shutil.rmtree(case)
            materialize(f"{name}/store", case / "store")
            chown_tree(case)
        destination = case / "actual.qdb"
        result = run_sandbox([str(binary), "recover", str(case / "store"), str(destination)], case)
        assert result.returncode == 0, f"{name} recovery failed:\n{result.stdout}\n{result.stderr}"
        assert "recovered epoch" in result.stdout, f"{name} recovery did not report its boundary"
        output[name] = destination.read_bytes()
    return output


def expected(name):
    path = "primary.qdb" if name == "primary" else f"{name}/expected.qdb"
    return SEALED[path]


def lines(result):
    return result.decode().splitlines()


def test_tool_rebuilds_and_reports_usage(binary):
    """The delivered Rust source rebuilds and exposes only the documented command form."""
    result = run_sandbox([str(binary)], WORK)
    assert result.returncode == 2
    assert result.stderr == "usage: qrecover recover <store-dir> <output-file>\n"


def test_sandbox_cannot_read_verifier_material():
    """The execution identity cannot read tests or traverse verifier logs."""
    probe = "from pathlib import Path\nfor action in (lambda: Path('/tests/test_outputs.py').read_bytes(), lambda: list(Path('/logs/verifier').iterdir())):\n try:\n  action()\n except PermissionError:\n  continue\n raise SystemExit(1)"
    result = run_sandbox(["python3", "-c", probe], WORK)
    assert result.returncode == 0, f"verifier privacy probe failed:\n{result.stdout}\n{result.stderr}"


def test_primary_recovery_matches_certified_state(results):
    """The shipped crash store recovers to the certified state bytes."""
    assert results["primary"] == expected("primary")


def test_required_primary_artifact_is_current(results):
    """The required recovered artifact exists and agrees with a fresh rebuild and run."""
    delivered = APP / "out" / "recovered.qdb"
    assert delivered.is_file(), f"missing {delivered}"
    assert delivered.read_bytes() == results["primary"]


def test_visible_acceptance_checker_passes(binary):
    """The recovered primary state satisfies the shipped night-shift acceptance record."""
    result = run_sandbox(
        ["python3", str(APP / "tools" / "check-recovery.py"), str(APP / "out" / "recovered.qdb")],
        WORK,
    )
    assert result.returncode == 0, f"acceptance check failed:\n{result.stdout}\n{result.stderr}"
    assert result.stdout == "recovery agrees with the night-shift acceptance record\n"


def test_incomplete_activation_never_becomes_authoritative(results):
    """A higher pointer without both ordered sync witnesses loses to the durable epoch."""
    assert results["activation"] == expected("activation")


def test_checkpoint_excludes_visible_segment_tail(results):
    """Records physically present beyond the selected checkpoint remain invisible."""
    text = "\n".join(lines(results["activation"]))
    assert "tail" not in text and "future" not in text


def test_transactions_take_effect_at_commit_sequence(results):
    """Prepared writes enter snapshots together at their commit sequence."""
    assert results["transactions"] == expected("transactions")


def test_aborted_and_unfinished_transactions_stay_invisible(results):
    """Aborted and unterminated transaction records never enter recovered views."""
    text = "\n".join(lines(results["transactions"]))
    assert "ghost" not in text and "loose" not in text and "626164" not in text


def test_tombstones_prevent_older_values_resurrecting(results):
    """Deletes remain in the version merge and suppress earlier segment values."""
    assert results["tombstones"] == expected("tombstones")


def test_snapshot_boundaries_preserve_historical_values(results):
    """Snapshots immediately before and on a delete boundary retain distinct states."""
    rows = lines(results["tombstones"])
    before_start = rows.index("view before 19")
    before_end = rows.index("endview", before_start)
    boundary_start = rows.index("view boundary 20")
    boundary_end = rows.index("endview", boundary_start)
    before = rows[before_start + 1:before_end]
    boundary = rows[boundary_start + 1:boundary_end]
    assert "put red 6f6e65" in before and all(" red " not in row for row in boundary)


def test_candidate_and_orphan_segments_are_not_opened(results):
    """Malformed candidate packs do not prevent recovery of the active segment set."""
    assert results["activation"].startswith(b"quarry-state-v1\n")
    assert results["composed"].startswith(b"quarry-state-v1\n")


def test_composed_crash_history_recovers_all_axes(results):
    """Manifest restart, snapshots, transactions, deletes and cutoff compose correctly."""
    assert results["composed"] == expected("composed")


def test_output_uses_manifest_view_order_and_sorted_keys(results):
    """Snapshot blocks retain manifest order and each view orders keys bytewise."""
    rows = lines(results["composed"])
    views = [row.split()[1] for row in rows if row.startswith("view ")]
    assert views == ["early", "mid", "current"]
    for index, row in enumerate(rows):
        if row.startswith("view "):
            end = rows.index("endview", index)
            keys = [item.split()[1] for item in rows[index + 1:end]]
            assert keys == sorted(keys, key=lambda key: key.encode())


def test_recovery_is_byte_deterministic(binary, results):
    """A second isolated run over every hidden store produces identical bytes."""
    for name in ("activation", "transactions", "tombstones", "composed"):
        case = WORK / "repeat" / CASE_IDS[name]
        if case.exists():
            shutil.rmtree(case)
        materialize(f"{name}/store", case / "store")
        chown_tree(case)
        destination = case / "again.qdb"
        result = run_sandbox([str(binary), "recover", str(case / "store"), str(destination)], case)
        assert result.returncode == 0 and "recovered epoch" in result.stdout
        assert destination.read_bytes() == results[name]


def test_read_only_task_material_is_unchanged():
    """The store, documentation, parser, build manifest and acceptance tool remain delivered bytes."""
    references = SEALED["shipped.sha256"].decode().splitlines()
    required = {"src/recover.rs"}
    for line in references:
        digest, relative = line.split("  ", 1)
        required.add(relative)
        path = APP / relative
        assert path.is_file(), f"required shipped file is missing: {relative}"
        assert sha256(path) == digest, f"read-only task file changed: {relative}"
    delivered = {
        path.relative_to(APP).as_posix()
        for path in APP.rglob("*")
        if path.is_file() and path.relative_to(APP).parts[0] not in {"bin", "out"}
    }
    assert delivered == required, "files outside the permitted source and output paths changed"
