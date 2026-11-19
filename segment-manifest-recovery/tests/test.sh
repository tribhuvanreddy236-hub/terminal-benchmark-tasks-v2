#!/bin/bash
set -uo pipefail

mkdir -p /logs/verifier
chmod 700 /logs/verifier
/venv/bin/python -m pytest --ctrf /logs/verifier/ctrf.json /tests/test_outputs.py -rA
rc=$?
pkill -KILL -u 12000 >/dev/null 2>&1 || true

if [ "$rc" -eq 0 ]; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi
