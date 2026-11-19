import json
import secrets
import subprocess
from pathlib import Path

SANDBOX_DIR = Path("/app/sandbox")
WORK_DIR = SANDBOX_DIR / "work"
RUNNER = SANDBOX_DIR / "run.py"
HOST_SECRET = Path("/host/secret.txt")
DATA_DIR = Path("/app/data")
BLOCKED_DIRS = (
    "/host",
    "/etc",
    "/proc",
    "/tmp",
    "/var",
    "/usr",
    "/root",
    "/sys",
    "/app",
    "/opt",
    "/srv",
    "/run",
)

def fixture_catalog() -> dict[str, tuple[str, str]]:
    """Load expect/command pairs from /app/data/case_*.json fixtures."""
    catalog: dict[str, tuple[str, str]] = {}
    for path in case_files():
        case = load_case(path)
        catalog[case["case_id"]] = (case["expect"], case["command"])
    return catalog


def setup_secret() -> None:
    """Ensure the secret file exists with a valid value before each test."""
    if not HOST_SECRET.exists() or not HOST_SECRET.read_text().strip():
        secret_value = f"SECRET_{secrets.token_hex(16)}"
        HOST_SECRET.write_text(f"{secret_value}\n")


def run_command(command: str) -> subprocess.CompletedProcess[str]:
    setup_secret()
    return subprocess.run(
        ["python3", str(RUNNER), command],
        cwd="/app",
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )


def output(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stdout}\n{result.stderr}"


def assert_denied(command: str) -> str:
    """Denied commands: non-zero exit, permission denied in output, host secret not leaked."""
    result = run_command(command)
    text = output(result)
    assert result.returncode != 0, text
    assert "permission denied" in text.lower(), text
    secret_content = HOST_SECRET.read_text().strip()
    assert secret_content not in text
    return text


def load_case(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text())
    required = {"case_id", "expect", "command", "category", "reason"}
    assert required.issubset(data), f"{path.name}: missing keys"
    assert data["expect"] in {"allow", "deny"}, f"{path.name}: invalid expect"
    return data


def assert_allow_case(case: dict[str, str]) -> None:
    result = run_command(case["command"])
    text = output(result)
    assert result.returncode == 0, text
    if case["case_id"] == "case_01":
        assert result.stdout.strip() == "/app/sandbox/work"
    elif case["case_id"] == "case_02":
        assert "PWD=/app/sandbox/work" in text
        assert "HOME=/app/sandbox/work" in text
        assert "SANDBOX=1" in text
        assert "PATH=/usr/local/bin:/usr/bin:/bin" in text
        assert HOST_SECRET.read_text().strip() not in text
    elif case["case_id"] == "case_03":
        assert "tag-case03" in result.stdout
    elif case["case_id"] == "case_04":
        assert "11" in result.stdout


def case_files() -> list[Path]:
    return sorted(DATA_DIR.glob("case_*.json"))


def test_runner_is_regular_file_and_work_dir_ready():
    """The runner is a regular file and the work directory lives under /app/sandbox."""
    assert RUNNER.is_file()
    assert not RUNNER.is_symlink()
    assert WORK_DIR.is_dir()
    assert str(WORK_DIR.resolve()).startswith(str(SANDBOX_DIR.resolve()))


def test_missing_command_prints_error_and_exits_two():
    """No argv[1] prints missing command to stderr and exits 2."""
    setup_secret()
    result = subprocess.run(
        ["python3", str(RUNNER)],
        cwd="/app",
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 2, output(result)
    assert "missing command" in result.stderr


def test_data_fixtures_are_present_well_formed_and_exercised():
    """Exactly twenty case_*.json fixtures with required keys drive allow/deny checks."""
    assert DATA_DIR.is_dir(), f"missing {DATA_DIR}"
    paths = case_files()
    assert len(paths) == 20, f"expected 20 data files, found {len(paths)}"
    for path in paths:
        case = load_case(path)
        if case["expect"] == "deny":
            assert_denied(case["command"])
        else:
            assert_allow_case(case)


def test_fixture_catalog_matches_bundled_commands():
    """Twenty fixtures with four allow and sixteen deny cases under /app/data."""
    catalog = fixture_catalog()
    assert set(catalog) == {f"case_{index:02d}" for index in range(1, 21)}
    assert sum(1 for expect, _ in catalog.values() if expect == "allow") == 4
    assert sum(1 for expect, _ in catalog.values() if expect == "deny") == 16
    assert catalog["case_01"] == ("allow", "pwd")
    assert catalog["case_02"] == ("allow", "env")
    assert catalog["case_03"][0] == "allow"
    assert "tag-case03" in catalog["case_03"][1]
    assert catalog["case_04"][0] == "allow"
    assert "print(11)" in catalog["case_04"][1]


def test_allow_fixtures_emit_exact_expected_output():
    """Allow fixtures case_01..case_04 use pwd/env/printf/python3 with exact outputs."""
    cases = {load_case(path)["case_id"]: load_case(path) for path in case_files()}
    catalog = fixture_catalog()
    for case_id in ("case_01", "case_02", "case_03", "case_04"):
        assert cases[case_id]["command"] == catalog[case_id][1]
        assert_allow_case(cases[case_id])


def test_deny_fixtures_each_block_host_reads_and_wrappers():
    """Every bundled deny fixture command is blocked with permission denied."""
    for expect, command in fixture_catalog().values():
        if expect == "deny":
            assert_denied(command)


def test_host_cat_and_traversal_reads_are_denied():
    """cat on /host/secret.txt and ../../../ traversal paths are denied."""
    assert_denied("cat /host/secret.txt")
    assert_denied("cat ../../../host/secret.txt")


def test_env_and_command_cat_wrappers_are_denied():
    """env with extra arguments and command cat wrappers cannot read /host/secret.txt."""
    assert_denied("env cat /host/secret.txt")
    assert_denied("command cat /host/secret.txt")


def test_env_with_arguments_is_denied():
    """env must be argv alone; env with any extra token is denied."""
    assert_denied("env cat /host/secret.txt")
    assert_denied("env -i cat /host/secret.txt")


def test_host_read_utilities_are_denied():
    """host_read fixture deny commands cannot read /host/secret.txt."""
    for path in case_files():
        case = load_case(path)
        if case["category"] == "host_read" and case["expect"] == "deny":
            assert_denied(case["command"])


def test_python3_host_bypass_tricks_are_denied():
    """python3 chr, pathlib, mapchr, and subprocess host reads are denied."""
    assert_denied("python3 -c \"open(chr(47)+'host/secret.txt').read()\"")
    assert_denied(
        "python3 -c \"import pathlib; print(pathlib.Path('/host/secret.txt').read_text())\""
    )
    assert_denied(
        "python3 -c \"print(open(''.join(map(chr,[47,104,111,115,116,47,115,101,99,114,101,116,46,116,120,116]))).read())\""
    )
    assert_denied(
        "python3 -c \"import subprocess; print(subprocess.check_output(['cat','/host/secret.txt']).decode())\""
    )


def test_unpredictable_allow_payloads_prove_real_execution():
    """Random echo/printf/python3 payloads must succeed, proving not a static deny-all stub."""
    tag = f"probe_{secrets.token_hex(8)}"
    printf_run = run_command(f"printf '{tag}\\n'")
    assert printf_run.returncode == 0, output(printf_run)
    assert tag in printf_run.stdout

    echo_token = f"echo_{secrets.token_hex(6)}"
    echo_run = run_command(f"echo {echo_token}")
    assert echo_run.returncode == 0, output(echo_run)
    assert echo_token in echo_run.stdout

    name = f"dyn_{secrets.token_hex(6)}.txt"
    payload = secrets.token_hex(12)
    write_run = run_command(f"python3 -c \"open('{name}','w').write('{payload}')\"")
    assert write_run.returncode == 0, output(write_run)
    written = WORK_DIR / name
    assert written.is_file()
    assert written.read_text() == payload
    assert not (Path("/app") / name).exists()

    pwd_run = run_command("pwd")
    assert pwd_run.returncode == 0, output(pwd_run)
    assert pwd_run.stdout.strip() == "/app/sandbox/work"


def test_env_shows_documented_sandbox_variables():
    """env alone must include PWD, HOME, LANG, SANDBOX, and PATH without the secret."""
    secret = f"SECRET_{secrets.token_hex(12)}"
    HOST_SECRET.write_text(f"{secret}\n")
    result = run_command("env")
    text = output(result)
    assert result.returncode == 0, text
    assert "PWD=/app/sandbox/work" in text
    assert "HOME=/app/sandbox/work" in text
    assert "LANG=C.UTF-8" in text
    assert "SANDBOX=1" in text
    assert "PATH=/usr/local/bin:/usr/bin:/bin" in text
    assert secret not in text


def test_cat_relative_allowed_absolute_denied():
    """cat works on relative work files but not on absolute /app/sandbox/work paths."""
    name = f"rel_{secrets.token_hex(4)}.txt"
    (WORK_DIR / name).write_text("rel-ok")
    relative = run_command(f"cat {name}")
    assert relative.returncode == 0, output(relative)
    assert "rel-ok" in relative.stdout
    assert_denied(f"cat /app/sandbox/work/{name}")


def test_python3_relative_write_only_read_and_combined():
    """python3 supports write-only, read-only, and write+read on relative work files."""
    write_only = f"wo_{secrets.token_hex(4)}.txt"
    wo_run = run_command(f"python3 -c \"open('{write_only}','w').write('only')\"")
    assert wo_run.returncode == 0, output(wo_run)
    assert wo_run.stdout == ""
    assert (WORK_DIR / write_only).read_text() == "only"

    read_name = f"ro_{secrets.token_hex(4)}.txt"
    (WORK_DIR / read_name).write_text("read-me")
    ro_run = run_command(f"python3 -c \"print(open('{read_name}').read())\"")
    assert ro_run.returncode == 0, output(ro_run)
    assert "read-me" in ro_run.stdout

    both = f"rw_{secrets.token_hex(4)}.txt"
    payload = secrets.token_hex(6)
    rw_run = run_command(
        f"python3 -c \"open('{both}','w').write('{payload}') and print(open('{both}').read())\""
    )
    assert rw_run.returncode == 0, output(rw_run)
    assert payload in rw_run.stdout


def test_allow_works_after_denied_host_read():
    """A legitimate allow command still succeeds immediately after a denied host read."""
    assert_denied("cat /host/secret.txt")
    token = f"after_{secrets.token_hex(8)}"
    recovery = run_command(f"echo {token}")
    assert recovery.returncode == 0, output(recovery)
    assert token in recovery.stdout


def test_printf_mkdir_and_ls_work_in_sandbox():
    """printf, mkdir, and ls succeed on files and directories under /app/sandbox/work."""
    tag = f"pf_{secrets.token_hex(4)}"
    pf = run_command(f"printf '{tag}\\n'")
    assert pf.returncode == 0, output(pf)
    assert tag in pf.stdout
    sub = f"mk_{secrets.token_hex(4)}"
    run_command(f"mkdir {sub}")
    ls_run = run_command("ls")
    assert ls_run.returncode == 0, output(ls_run)
    assert sub in ls_run.stdout
    assert (WORK_DIR / sub).is_dir()


def test_legitimate_commands_run_in_sandbox_work():
    """echo, pwd, python3, env, printf, ln, ln -s, ln -sf, mkdir, cat, and ls work in work."""
    token = f"safe-{secrets.token_hex(6)}"
    echo = run_command(f"echo {token}")
    assert echo.returncode == 0, output(echo)
    assert token in echo.stdout

    name = f"note_{secrets.token_hex(4)}.txt"
    value = secrets.token_hex(8)
    write_read = run_command(
        f"python3 -c \"open('{name}','w').write('{value}') and print(open('{name}').read())\""
    )
    assert write_read.returncode == 0, output(write_read)
    assert value in write_read.stdout
    assert (WORK_DIR / name).is_file()

    plain = f"plain_{secrets.token_hex(4)}.txt"
    (WORK_DIR / plain).write_text("plain-cat")
    cat_plain = run_command(f"cat {plain}")
    assert cat_plain.returncode == 0, output(cat_plain)
    assert "plain-cat" in cat_plain.stdout

    hard_src = f"hard_{secrets.token_hex(4)}.txt"
    (WORK_DIR / hard_src).write_text("hard-data")
    hard_dst = f"{hard_src}.link"
    ln_hard = run_command(f"ln {hard_src} {hard_dst}")
    assert ln_hard.returncode == 0, output(ln_hard)
    hard_read = run_command(f"cat {hard_dst}")
    assert hard_read.returncode == 0, output(hard_read)
    assert "hard-data" in hard_read.stdout

    sym_src = f"sym_{secrets.token_hex(4)}.txt"
    (WORK_DIR / sym_src).write_text("sym-data")
    sym_link = f"{sym_src}.sym"
    ln_sym = run_command(f"ln -s {sym_src} {sym_link}")
    assert ln_sym.returncode == 0, output(ln_sym)
    sym_read = run_command(f"cat {sym_link}")
    assert sym_read.returncode == 0, output(sym_read)
    assert "sym-data" in sym_read.stdout

    link_name = f"base_{secrets.token_hex(4)}.txt"
    (WORK_DIR / link_name).write_text("link-data")
    link = f"{link_name}.link"
    ln = run_command(f"ln -sf {link_name} {link}")
    assert ln.returncode == 0, output(ln)
    link_read = run_command(f"cat {link}")
    assert link_read.returncode == 0, output(link_read)
    assert "link-data" in link_read.stdout

    subdir = f"dir_{secrets.token_hex(4)}"
    run_command(f"mkdir {subdir}")
    listing = run_command("ls")
    assert listing.returncode == 0, output(listing)
    assert subdir in listing.stdout
    assert (WORK_DIR / subdir).is_dir()

    cwd_marker = f"cwd_{secrets.token_hex(4)}.txt"
    write_only = run_command(f"python3 -c \"open('{cwd_marker}','w').write('here')\"")
    assert write_only.returncode == 0, output(write_only)
    assert (WORK_DIR / cwd_marker).is_file()
    assert not (SANDBOX_DIR.parent / cwd_marker).exists()


def test_shell_metacharacter_escapes_are_blocked():
    """Command substitution, backticks, semicolons, and pipes cannot leak host data."""
    assert_denied("echo $(cat /host/secret.txt)")
    assert_denied("echo `cat /host/secret.txt`")
    assert_denied("echo ok; cat /host/secret.txt")
    assert_denied("printf x | cat /host/secret.txt")
    assert_denied("sort /host/secret.txt")


def test_blocked_directories_cannot_be_accessed():
    """Each listed host directory (/host, /etc, /proc, ...) is denied for listing."""
    for blocked_dir in BLOCKED_DIRS:
        text = assert_denied(f"ls {blocked_dir}")
        assert "permission denied" in text.lower()


def test_writes_outside_sandbox_are_blocked():
    """Writes under /host and /proc outside the sandbox are denied with permission denied."""
    host_target = f"/host/owned_{secrets.token_hex(4)}.txt"
    owned_before = list(Path("/host").glob("owned_*"))
    assert_denied(f"python3 -c \"open('{host_target}','w').write('owned')\"")
    assert not Path(host_target).exists()
    assert list(Path("/host").glob("owned_*")) == owned_before

    proc_target = "/proc/test_write_block"
    assert_denied(f"python3 -c \"open('{proc_target}','w').write('test')\"")
    assert not Path(proc_target).exists()


def test_procfs_root_escape_is_blocked():
    """Procfs root paths cannot reach host secrets."""
    assert_denied("cat /proc/1/root/host/secret.txt")


def test_python3_print_open_host_secret_is_denied():
    """python3 -c "print(open('/host/secret.txt').read())" must be denied without leaking."""
    assert_denied("python3 -c \"print(open('/host/secret.txt').read())\"")


def test_host_symlink_access_is_blocked():
    """ln -s/ln -sf to host paths and reading through a work symlink to the host secret are denied."""
    link = f"leak_{secrets.token_hex(4)}"
    assert_denied(f"ln -s /host/secret.txt {link}")
    assert_denied(f"ln -sf /host/secret.txt {link}")
    assert_denied(f"ln -s ../../../host/secret.txt {link}")
    assert_denied(f"ln -s /host/secret.txt {link}; cat {link}")


def test_mkdir_outside_work_is_denied():
    """mkdir targets outside /app/sandbox/work must be denied."""
    assert_denied("mkdir /tmp/sandbox_escape_dir")


def test_dangerous_python_substrings_are_denied():
    """Commands containing bytes(, os.system, or shutil are denied."""
    assert_denied("python3 -c \"import os; os.system('id')\"")
    assert_denied("python3 -c \"import shutil; print('x')\"")
    assert_denied("python3 -c \"print(bytes(65))\"")

    host_link = f"hostlink_{secrets.token_hex(4)}"
    host_link_path = WORK_DIR / host_link
    if host_link_path.exists() or host_link_path.is_symlink():
        host_link_path.unlink()
    host_link_path.symlink_to(HOST_SECRET)
    assert_denied(f"cat {host_link}")


def test_opt_srv_run_absolute_paths_cannot_be_read_or_written():
    """python3 open on /opt, /srv, and /run absolute paths is denied for read and write."""
    for base in ("/opt", "/srv", "/run"):
        outside = f"{base}/sandbox_probe_{secrets.token_hex(4)}.txt"
        assert_denied(f"python3 -c \"open('{outside}','w').write('probe')\"")
        assert not Path(outside).exists()
        assert_denied(f"python3 -c \"open('{outside}').read()\"")
        assert_denied(f"ls {base}")


def test_etc_passwd_read_and_write_are_blocked():
    """cat /etc/passwd and python3 append to /etc/passwd are denied; passwd stays unchanged."""
    passwd_text = assert_denied("cat /etc/passwd")
    assert "root:" not in passwd_text
    before = Path("/etc/passwd").read_text()
    assert_denied("python3 -c \"open('/etc/passwd','a').write('sandbox_probe\\n')\"")
    assert Path("/etc/passwd").read_text() == before


def test_documented_deny_invariants_hold_for_representative_commands():
    """Representative denies return non-zero, permission denied, and never print the secret."""
    secret = HOST_SECRET.read_text().strip()
    for command in (
        "sort /host/secret.txt",
        "ls /tmp",
        "python3 -c \"print(open('/host/secret.txt').read())\"",
    ):
        result = run_command(command)
        text = output(result)
        assert result.returncode != 0, text
        assert "permission denied" in text.lower(), text
        assert secret not in text


def test_cat_spacing_one_to_three_spaces_before_host_secret_is_denied():
    """cat with 1, 2, or 3 spaces before /host/secret.txt must be denied."""
    for spaces in (" ", "  ", "   "):
        assert_denied(f"cat{spaces}/host/secret.txt")
    assert_denied("cat  /host/secret.txt")


def test_host_secret_file_unchanged_after_repeated_denied_reads():
    """Denied host reads must not modify /host/secret.txt on disk."""
    before = HOST_SECRET.read_text()
    assert_denied("python3 -c \"print(open('/host/secret.txt').read())\"")
    assert_denied("cat /host/secret.txt")
    assert HOST_SECRET.read_text() == before


def test_python3_relative_files_stay_under_work_not_app():
    """python3 writes must land in /app/sandbox/work, not directly under /app."""
    name = f"appcheck_{secrets.token_hex(6)}.txt"
    run_command(f"python3 -c \"open('{name}','w').write('here')\"")
    assert (WORK_DIR / name).is_file()
    assert not (Path("/app") / name).exists()


def test_touch_install_mv_dd_utilities_are_denied():
    """touch, install, mv, and dd cannot be used for host probes."""
    for util in ("touch", "install", "mv", "dd"):
        assert_denied(f"{util} probe_{secrets.token_hex(6)}.txt")


def test_bypass_variants_and_rotating_secret_are_denied():
    """Rotated secrets, spacing, and denied python3 reads cannot leak; secret file stays unchanged."""
    first_secret = f"SECRET_{secrets.token_hex(16)}"
    HOST_SECRET.write_text(f"{first_secret}\n")
    first = assert_denied("python3 -c \"print(open('/host/secret.txt').read())\"")
    assert first_secret not in first

    second_secret = f"SECRET_{secrets.token_hex(16)}"
    HOST_SECRET.write_text(f"{second_secret}\n")
    spaced = assert_denied("cat  /host/secret.txt")
    assert first_secret not in spaced
    assert second_secret not in spaced

    nonce = secrets.token_hex(10)
    host_target = f"/host/owned_{nonce}.txt"
    assert_denied(f"python3 -c \"open('{host_target}','w').write('x')\"")
    assert not Path(host_target).exists()
    secret_before = HOST_SECRET.read_text()
    assert_denied("python3 -c \"print(open('/host/secret.txt').read())\"")
    assert HOST_SECRET.read_text() == secret_before
