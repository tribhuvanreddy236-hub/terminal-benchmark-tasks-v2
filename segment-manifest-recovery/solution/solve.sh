#!/bin/bash
set -e
cd /app
cp "$(dirname "$0")/recover.rs" /app/src/recover.rs
make clean
make
/app/bin/qrecover recover /app/store /app/out/recovered.qdb
python3 /app/tools/check-recovery.py /app/out/recovered.qdb
