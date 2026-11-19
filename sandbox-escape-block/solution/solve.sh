#!/bin/sh
set -eu

mkdir -p /app/sandbox/work /host
secret_value="SECRET_$(openssl rand -hex 16)"
printf '%s\n' "$secret_value" > /host/secret.txt
chmod 700 /host
chmod 600 /host/secret.txt
chmod 755 /app/sandbox
chmod 755 /app/sandbox/work
chattr +i /host/secret.txt 2>/dev/null || true

cat > /app/sandbox/run.py <<'PY'
import shlex
import subprocess
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 2:
        print("missing command", file=sys.stderr)
        return 2

    sandbox = Path("/app/sandbox").resolve()
    workdir = (sandbox / "work").resolve()
    command = sys.argv[1]
    denied = (
        "/host",
        "host/secret",
        "/etc",
        "/proc",
        "/var",
        "/usr",
        "/root",
        "/sys",
        "/app",
        "/tmp",
        "/opt",
        "/srv",
        "/run",
        "/etc/passwd",
        "/proc/1/root",
        "../",
        "..",
        "$(",
        "`",
        ";",
        "|",
        "bytes(",
        "map(chr",
        "subprocess",
        "os.system",
        "shutil",
    )
    if any(token in command for token in denied):
        print("permission denied", file=sys.stderr)
        return 126

    try:
        argv = shlex.split(command)
    except ValueError:
        print("permission denied", file=sys.stderr)
        return 126

    allowed = {"cat", "echo", "env", "ln", "ls", "mkdir", "printf", "pwd", "python3"}
    if not argv or argv[0] not in allowed:
        print("permission denied", file=sys.stderr)
        return 126

    if argv[0] == "env" and len(argv) != 1:
        print("permission denied", file=sys.stderr)
        return 126

    for arg in argv[1:]:
        candidate = Path(arg).resolve() if arg.startswith("/") else (workdir / arg).resolve()
        allowed_root = sandbox if arg.startswith("/") else workdir
        if not str(candidate).startswith(str(allowed_root)):
            print("permission denied", file=sys.stderr)
            return 126

    if argv[0] == "pwd":
        print(str(workdir))
        return 0

    result = subprocess.run(
        argv,
        cwd=str(workdir),
        env={
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(workdir),
            "PWD": str(workdir),
            "SANDBOX": "1",
            "LANG": "C.UTF-8",
        },
        text=True,
        capture_output=True,
        timeout=3,
        check=False,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
PY

chmod 755 /app/sandbox/run.py
