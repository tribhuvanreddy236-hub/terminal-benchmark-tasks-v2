#!/usr/bin/env bash
set -uo pipefail

TEST_DIR="${TEST_DIR:-/tests}"
mkdir -p /logs/verifier

# Default reward to 0 so we never leave the harness without a value.
echo 0 > /logs/verifier/reward.txt

cd /app

# Test-only Python tooling: install at test time rather than baking into the
# runtime image. We ALWAYS run apt-get install with pinned versions so that
# the test environment is fully reproducible regardless of whether the base
# image already ships python3 (apt is a no-op if the pinned version is
# already present, otherwise it upgrades/installs to the exact pin).
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
    python3=3.11.2-1+b1 \
    python3-pip=23.0.1+dfsg-1 \
    python3-venv=3.11.2-1+b1 >/dev/null

# Snapshot every input that should remain byte-identical across the agent's run.
mkdir -p /tests/baseline
cp /app/data/leaks.ndjson      /tests/baseline/leaks.ndjson
cp /app/data/modules.ndjson    /tests/baseline/modules.ndjson
cp /app/data/kernels.json      /tests/baseline/kernels.json
cp /app/config/suppressions.yaml /tests/baseline/suppressions.yaml

# Force a fresh build so the binary cannot be staged ahead of time.
rm -f /app/bin/analyzer

# Note: we never `exit 0` on intermediate failures here. If something
# upstream breaks (missing binary, build error, runtime crash), we still
# fall through to pytest so harbor records real per-test failures instead
# of the synthetic verifier_did_not_run signal.
make build >/tests/build.log 2>&1 || {
    echo "build failed" >&2
    cat /tests/build.log >&2 || true
}

[ -x /app/bin/analyzer ] || echo "analyzer binary missing after build" >&2

mkdir -p /app/output

# First run: produces primary output for assertion.
rm -f /app/output/kmemleak_report.json
if [ -x /app/bin/analyzer ]; then
    /app/bin/analyzer >/tests/run.log 2>&1 || {
        echo "first analyzer run failed" >&2
        cat /tests/run.log >&2 || true
    }
    [ -f /app/output/kmemleak_report.json ] && \
        cp /app/output/kmemleak_report.json /tests/report_first.json

    # Second run: idempotency snapshot.
    /app/bin/analyzer >/tests/run2.log 2>&1 || {
        echo "second analyzer run failed" >&2
        cat /tests/run2.log >&2 || true
    }
    [ -f /app/output/kmemleak_report.json ] && \
        cp /app/output/kmemleak_report.json /tests/report_second.json
fi

# Anti hardcode round 1: swap in a curated extra leaks log and re run.
cp /app/data/leaks.ndjson /tests/leaks_backup.ndjson 2>/dev/null || true
if [ -x /app/bin/analyzer ] && [ -f /tests/extra_leaks.ndjson ]; then
    cp /tests/extra_leaks.ndjson /app/data/leaks.ndjson
    rm -f /app/output/kmemleak_report.json
    /app/bin/analyzer >/tests/run_extra.log 2>&1 || {
        echo "extra dataset run failed" >&2
        cat /tests/run_extra.log >&2 || true
    }
    [ -f /app/output/kmemleak_report.json ] && \
        cp /app/output/kmemleak_report.json /tests/report_extra.json
    [ -f /tests/leaks_backup.ndjson ] && \
        cp /tests/leaks_backup.ndjson /app/data/leaks.ndjson
fi

# Anti hardcode round 2: procedurally generated leaks the agent never sees.
python3 - >/tests/synth_leaks.ndjson <<'PYEOF'
import json
import random

rng = random.Random(0xCAFEBABE)
modules = [
    ("vmlinux",      0xffffffff81000000, 0xffffffff81e00000),
    ("nvme",         0xffffffffa0000000, 0xffffffffa00f0000),
    ("xfs",          0xffffffffa0100000, 0xffffffffa01f0000),
    ("mlx5_core",    0xffffffffa0200000, 0xffffffffa02e0000),
    ("nf_conntrack", 0xffffffffa0300000, 0xffffffffa033f000),
    ("ib_core",      0xffffffffa0400000, 0xffffffffa04a0000),
    ("ext4",         0xffffffffa0500000, 0xffffffffa05e0000),
    ("bcache",       0xffffffffa0600000, 0xffffffffa063f000),
]
allocator = ["kmalloc", "__kmalloc", "kzalloc", "vmalloc",
             "kmem_cache_alloc", "krealloc", "kvmalloc"]
prefix_traced = [
    "__ftrace_caller",
    "__ftrace_synth_handler",
    "trace_event_raw_event_synth",
    "trace_event_buffer_lock_reserve",
    "__probe_handler_synth",
]
symbols = {
    "vmlinux":      ["__schedule", "sys_open", "kthread_create"],
    "nvme":         ["nvme_alloc_request", "nvme_submit_io", "nvme_pci_setup_prps"],
    "xfs":          ["xfs_alloc_inode", "xfs_buf_alloc"],
    "mlx5_core":    ["mlx5_alloc_cq", "mlx5_alloc_qp"],
    "nf_conntrack": ["nf_conntrack_alloc"],
    "ib_core":      ["ib_alloc_pd"],
    "ext4":         ["ext4_alloc_inode", "ext4_buffer_uptodate"],
    "bcache":       ["bcache_btree_alloc"],
}

records = []
for i in range(1, 25):
    cat = (i - 1) % 6
    bt = [{"addr": "0xffffffff80100000", "symbol": rng.choice(allocator)}]
    if cat == 0:
        m = modules[i % len(modules)]
        sym = rng.choice(symbols[m[0]])
        addr = m[1] + ((i * 0x1234) % (m[2] - m[1] - 0x2000))
        bt.append({"addr": f"0x{addr:016x}", "symbol": sym})
    elif cat == 1:
        m = modules[(i * 3) % len(modules)]
        sym = rng.choice(symbols[m[0]])
        addr = m[1] + ((i * 0x4321) % (m[2] - m[1] - 0x2000))
        bt = [
            {"addr": "0xffffffff80100000", "symbol": rng.choice(allocator)},
            {"addr": "0xffffffff80100000", "symbol": rng.choice(allocator)},
            {"addr": f"0x{addr:016x}", "symbol": sym},
        ]
    elif cat == 2:
        bt.append({"addr": "0xffffffff80100000", "symbol": rng.choice(allocator)})
    elif cat == 3:
        bt.append({"addr": "0xffff0000deadbeef", "symbol": "alien_func"})
    elif cat == 4:
        m = modules[(i * 5) % len(modules)]
        sym = rng.choice(symbols[m[0]])
        addr = m[1] + ((i * 0x2345) % (m[2] - m[1] - 0x2000))
        traced_sym = prefix_traced[i % len(prefix_traced)]
        bt = [
            {"addr": "0xffffffff80100000", "symbol": rng.choice(allocator)},
            {"addr": "0xffffffff81abc000", "symbol": traced_sym},
            {"addr": f"0x{addr:016x}", "symbol": sym},
        ]
    else:
        # Deep-backtrace leak: real frame past the depth cap, top-N all suppressed.
        m = modules[(i * 7) % len(modules)]
        sym = rng.choice(symbols[m[0]])
        addr = m[1] + ((i * 0x3456) % (m[2] - m[1] - 0x2000))
        bt = [
            {"addr": "0xffffffff80100000", "symbol": rng.choice(allocator)},
            {"addr": "0xffffffff81abc011", "symbol": "__ftrace_synth_a"},
            {"addr": "0xffffffff81abc021", "symbol": "__ftrace_synth_b"},
            {"addr": "0xffffffff81abc031", "symbol": "__ftrace_synth_c"},
            {"addr": "0xffffffff81abc041", "symbol": "__ftrace_synth_d"},
            {"addr": "0xffffffff81abc051", "symbol": "__ftrace_synth_e"},
            {"addr": f"0x{addr:016x}", "symbol": sym},
        ]
    records.append({
        "leak_id":    f"S{i:02d}",
        "address":    f"0xffff{i:04x}00000000",
        "size_bytes": [64, 128, 256, 512, 1024, 2048][i % 6],
        "comm":       "synth-task",
        "pid":        1000 + i,
        "jiffies":    4294990000 + i,
        "age_sec":    round(2.0 + i * 1.5, 2),
        "slab_cache": "kmalloc-256" if i % 3 else None,
        "scan_ts":    1716200000,
        "backtrace":  bt,
    })

for r in records:
    print(json.dumps(r, separators=(",", ":")))
PYEOF

if [ -x /app/bin/analyzer ] && [ -f /tests/synth_leaks.ndjson ]; then
    cp /tests/synth_leaks.ndjson /app/data/leaks.ndjson
    rm -f /app/output/kmemleak_report.json
    /app/bin/analyzer >/tests/run_synth.log 2>&1 || {
        echo "synth dataset run failed" >&2
        cat /tests/run_synth.log >&2 || true
    }
    [ -f /app/output/kmemleak_report.json ] && \
        cp /app/output/kmemleak_report.json /tests/report_synth.json
    [ -f /tests/leaks_backup.ndjson ] && \
        cp /tests/leaks_backup.ndjson /app/data/leaks.ndjson
fi

# Restore the primary report so test_outputs.py sees the original output.
rm -f /app/output/kmemleak_report.json
if [ -x /app/bin/analyzer ]; then
    /app/bin/analyzer >/tests/run_final.log 2>&1 || {
        echo "final analyzer run failed" >&2
        cat /tests/run_final.log >&2 || true
    }
fi

cd "$TEST_DIR" 2>/dev/null || cd /tests || true

# Install test dependencies at test time, not in the image. Always install
# uv at the pinned version so the test environment is reproducible regardless
# of any preexisting uv binary.
python3 -m pip install --quiet --no-cache-dir --break-system-packages \
    --force-reinstall uv==0.4.30 || true
uv venv --quiet /tests/.venv 2>/dev/null || true
# shellcheck disable=SC1091
if [ -f /tests/.venv/bin/activate ]; then
    set +u
    # shellcheck disable=SC1091
    source /tests/.venv/bin/activate
    set -u
    uv pip install --quiet pytest==8.3.3 || true
fi

TEST_FILE="${TEST_DIR}/test_outputs.py"
if [ ! -f "$TEST_FILE" ]; then
    TEST_FILE="/tests/test_outputs.py"
fi

# Always run pytest so the harness records per-test outcomes.
if [ -x /tests/.venv/bin/pytest ]; then
    /tests/.venv/bin/pytest "$TEST_FILE" -rA -v
elif command -v pytest >/dev/null 2>&1; then
    pytest "$TEST_FILE" -rA -v
else
    python3 -m pip install --quiet --no-cache-dir --break-system-packages pytest==8.3.3 || true
    python3 -m pytest "$TEST_FILE" -rA -v
fi

if [ $? -eq 0 ]; then
    echo 1 > /logs/verifier/reward.txt
else
    echo 0 > /logs/verifier/reward.txt
fi
