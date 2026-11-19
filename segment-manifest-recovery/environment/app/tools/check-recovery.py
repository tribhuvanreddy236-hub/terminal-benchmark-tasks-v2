#!/usr/bin/env python3
import sys
from pathlib import Path


def fail(message):
    print(f"check-recovery: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse(path):
    text = Path(path).read_text()
    if not text.endswith("\n"):
        fail("output has no final newline")
    lines = text.splitlines()
    if len(lines) < 5 or lines[0] != "quarry-state-v1" or lines[-1] != "end":
        fail("invalid output envelope")
    if lines[1] != "epoch 41" or lines[2] != "checkpoint 90":
        fail("the recovered durability boundary disagrees with the handoff")
    views = {}
    index = 3
    while index < len(lines) - 1:
        fields = lines[index].split(" ")
        if len(fields) != 3 or fields[0] != "view":
            fail(f"unexpected line {index + 1}")
        name = fields[1]
        index += 1
        entries = {}
        while index < len(lines) and lines[index] != "endview":
            row = lines[index].split(" ")
            if len(row) != 3 or row[0] != "put" or row[1] in entries:
                fail(f"invalid put line {index + 1}")
            entries[row[1]] = row[2]
            index += 1
        if index == len(lines):
            fail(f"view {name} is not closed")
        views[name] = entries
        index += 1
    expected_counts = {"handoff": 6, "audit": 6, "current": 6}
    if {name: len(rows) for name, rows in views.items()} != expected_counts:
        fail("view names or live-key counts disagree with the handoff")
    if "ledger:x" in views["handoff"]:
        fail("a prepared transaction leaked into the handoff view")
    for name in ("audit", "current"):
        if "stale:item" in views[name] or "account:beta" in views[name]:
            fail(f"deleted keys returned in {name}")
    print("recovery agrees with the night-shift acceptance record")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        fail("usage: check-recovery.py OUTPUT")
    parse(sys.argv[1])

