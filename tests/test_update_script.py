"""Tests for update.sh / auto-update.sh / backup.sh (audit 2026-10-16: H2a, H2b, M6, M8, B11).

The scripts are NEVER executed as such. Tests are either static (text analysis,
`bash -n`, shellcheck when installed) or source update.sh inside a sandbox
under tmp_path (fake git repo created by the test, restricted PATH, no network)
and call individual functions; update.sh only runs main() when executed, not
when sourced.
"""
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ["update.sh", "auto-update.sh", "backup.sh"]
UPDATE = ROOT / "update.sh"
BACKUP = ROOT / "backup.sh"

HAVE_GPG = shutil.which("gpg") is not None
HAVE_OPENSSL = shutil.which("openssl") is not None


def code_lines(name):
    """Script lines without full-line comments."""
    text = (ROOT / name).read_text()
    return [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]


def code(name):
    return "\n".join(code_lines(name))


# ------------------------------------------------------------------ syntax

@pytest.mark.parametrize("name", SCRIPTS)
def test_bash_syntax(name):
    subprocess.run(["bash", "-n", str(ROOT / name)], check=True)


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
@pytest.mark.parametrize("name", SCRIPTS)
def test_shellcheck(name):
    res = subprocess.run(
        ["shellcheck", "--severity=error", str(ROOT / name)], capture_output=True, text=True
    )
    assert res.returncode == 0, res.stdout


# ------------------------------------------------------------------ static

def test_no_git_pull():
    for name in SCRIPTS:
        assert not re.search(r"\bgit\s+pull\b", code(name)), name


def test_verify_before_merge():
    src = code("update.sh")
    # the only merge/checkout/reset of the new code goes through verify_target
    assert "git verify-commit --raw" in src
    merge = src.index("git merge --ff-only")
    assert src.index('verify_target "$TARGET"') < merge
    assert src.index("fetch_target ||") < src.index('verify_target "$TARGET"')
    assert "git checkout" not in src
    assert "--ff-only" in src
    # fail closed unless explicitly overridden
    assert "UPDATE_ALLOW_UNSIGNED" in src and "UPDATE_GPG_HOME" in src
    assert "UPDATE_TRUSTED_FINGERPRINTS" in src


def test_auto_update_requires_signature_policy():
    src = code("auto-update.sh")
    assert "require_signature_policy" in src
    assert src.index("require_signature_policy\n") < src.index('line="$cron')
    assert "./update.sh --auto" in src  # delegates to update.sh (which verifies)


def test_hashed_install_and_no_unpinned_tools():
    src = code("update.sh")
    assert "--require-hashes -r requirements.lock" in src
    assert not re.search(r"pip\s+install[^\n]*--upgrade\s+pip(\s|$)", src)
    assert not re.search(r"pip\s+install[^\n]*pip-audit", src)
    assert not re.search(r"pip\s+install[^\n]*gunicorn", src)
    assert "-m pip_audit" not in src  # not run from the production venv
    assert "uvx" in src or "pipx" in src


def test_rollback_restores_database():
    src = (ROOT / "update.sh").read_text()
    m = re.search(r"\nrollback\(\) \{.*?\n\}\n", src, re.S)
    assert m
    body = m.group(0)
    assert "restore_db_from_backup" in body
    assert "install_deps" in body
    assert "your data is untouched" not in src
    assert "flask db current" in src
    assert "DB_TOUCHED=1" in src
    assert "uploads" not in re.search(r"\nrestore_db_from_backup\(\) \{.*?\n\}\n", src, re.S).group(0).replace(
        "uploads/, .env", ""
    ).split("local archive")[1]


def test_backup_encrypted_and_private():
    src = code("update.sh")
    assert "umask 077" in src
    assert "encrypt_stream" in src and "BACKUP_PASSPHRASE" in src
    assert "--exclude='instance/quarantine'" in src
    assert "chmod 600" in src


def test_backup_sh_authenticated_fallback():
    src = code("backup.sh")
    assert "-pbkdf2 -iter 600000" in src
    assert ".enc.hmac" in src
    # gpg is tried first
    assert src.index("command -v gpg") < src.index("openssl enc -aes-256-cbc")


# ------------------------------------------------------------------ sandbox helpers

def tool_path(tmp_path, with_gpg=True):
    """PATH made of symlinks to the few tools the functions need (no pip/systemctl/network)."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    tools = ["bash", "cat", "date", "mkdir", "chmod", "ls", "tail", "head", "xargs", "awk", "find",
             "rm", "mktemp", "cp", "mv", "sed", "grep", "cut", "tar", "gzip", "sort", "git",
             "openssl", "env", "dirname", "tr", "true", "false"]
    if with_gpg:
        tools += ["gpg", "gpgconf", "gpg-agent"]
    for t in tools:
        p = shutil.which(t)
        if p and not (bindir / t).exists():
            (bindir / t).symlink_to(p)
    return str(bindir)


def sandbox_env(tmp_path, with_gpg=True, **extra):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {
        "PATH": tool_path(tmp_path, with_gpg),
        "HOME": str(home),
        "GNUPGHOME": str(tmp_path / "gnupg-default"),
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": str(home / "gitconfig"),
    }
    env.update(extra)
    return env


def run_fn(tmp_path, repo, script, with_gpg=True, **env_extra):
    """Source update.sh (nothing runs) then execute `script` in the sandbox."""
    pre = f'set -euo pipefail; ROOT="{repo}"; cd "{repo}"; PY="{sys.executable}"; source "{UPDATE}"; set +e; '
    return subprocess.run(
        ["bash", "-c", pre + script],
        cwd=repo, env=sandbox_env(tmp_path, with_gpg, **env_extra),
        capture_output=True, text=True, timeout=120,
    )


def git(repo, *args, env=None, check=True):
    e = {"PATH": os.environ["PATH"], "HOME": str(repo.parent / "home"), "GIT_CONFIG_NOSYSTEM": "1",
         "GIT_CONFIG_GLOBAL": "/dev/null"}
    e.update(env or {})
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", *args],
        cwd=repo, env=e, capture_output=True, text=True, check=check,
    )


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    (tmp_path / "home").mkdir()
    git(r, "init", "-q")
    (r / "a.txt").write_text("a")
    git(r, "add", "a.txt")
    git(r, "commit", "-q", "-m", "unsigned")
    return r


# ------------------------------------------------------------------ H2a dynamic

def test_unsigned_commit_refused_without_keyring(tmp_path, repo):
    res = run_fn(tmp_path, repo, 'verify_target HEAD')
    assert res.returncode != 0
    assert "fail closed" in res.stdout


def test_unsigned_commit_refused_with_empty_keyring(tmp_path, repo):
    gh = tmp_path / "gh"
    gh.mkdir(mode=0o700)
    res = run_fn(tmp_path, repo, 'verify_target HEAD', UPDATE_GPG_HOME=str(gh))
    assert res.returncode != 0


def test_allow_unsigned_is_explicit_and_noisy(tmp_path, repo):
    res = run_fn(tmp_path, repo, 'verify_target HEAD', UPDATE_ALLOW_UNSIGNED="1")
    assert res.returncode == 0
    assert "WARNING" in res.stdout
    # but a configured keyring always wins over the opt-out
    gh = tmp_path / "gh"
    gh.mkdir(mode=0o700)
    res = run_fn(tmp_path, repo, 'verify_target HEAD', UPDATE_ALLOW_UNSIGNED="1", UPDATE_GPG_HOME=str(gh))
    assert res.returncode != 0


@pytest.mark.skipif(not HAVE_GPG, reason="gpg not installed")
def test_signed_commit_accepted_and_fingerprint_pinning(tmp_path, repo):
    gh = tmp_path / "g"
    gh.mkdir(mode=0o700)
    genv = {"GNUPGHOME": str(gh), "PATH": os.environ["PATH"], "HOME": str(tmp_path / "home")}
    try:
        subprocess.run(
            ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key",
             "Test <t@example.invalid>", "ed25519", "sign", "never"],
            env=genv, check=True, capture_output=True, timeout=60,
        )
        out = subprocess.run(["gpg", "--batch", "--with-colons", "--list-secret-keys"], env=genv,
                             capture_output=True, text=True, check=True).stdout
        fpr = next(ln.split(":")[9] for ln in out.splitlines() if ln.startswith("fpr:"))
        (repo / "b.txt").write_text("b")
        git(repo, "add", "b.txt")
        git(repo, "-c", f"user.signingkey={fpr}", "commit", "-q", "-S", "-m", "signed", env=genv)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, StopIteration) as exc:  # pragma: no cover
        subprocess.run(["gpgconf", "--kill", "all"], env=genv, capture_output=True)
        pytest.skip(f"cannot create a signed commit here: {exc}")
    try:
        ok = run_fn(tmp_path, repo, 'verify_target HEAD', UPDATE_GPG_HOME=str(gh))
        assert ok.returncode == 0, ok.stdout + ok.stderr
        pinned = run_fn(tmp_path, repo, 'verify_target HEAD', UPDATE_GPG_HOME=str(gh),
                        UPDATE_TRUSTED_FINGERPRINTS=f"AAAA {fpr.lower()}")
        assert pinned.returncode == 0, pinned.stdout
        wrong = run_fn(tmp_path, repo, 'verify_target HEAD', UPDATE_GPG_HOME=str(gh),
                       UPDATE_TRUSTED_FINGERPRINTS="0" * 40)
        assert wrong.returncode != 0
        # the previous (unsigned) commit is refused even with this keyring
        unsigned = run_fn(tmp_path, repo, 'verify_target HEAD~1', UPDATE_GPG_HOME=str(gh))
        assert unsigned.returncode != 0
    finally:
        subprocess.run(["gpgconf", "--kill", "all"], env=genv, capture_output=True)


# ------------------------------------------------------------------ H2b dynamic

def make_db(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE IF NOT EXISTS t (v TEXT)")
    con.execute("DELETE FROM t")
    con.execute("INSERT INTO t VALUES (?)", (value,))
    con.commit()
    con.close()


def read_db(path):
    con = sqlite3.connect(path)
    try:
        return con.execute("SELECT v FROM t").fetchone()[0]
    finally:
        con.close()


def test_restore_db_from_backup_puts_original_back(tmp_path, repo):
    make_db(repo / "instance" / "app.db", "original")
    (repo / "uploads").mkdir()
    (repo / "uploads" / "u.bin").write_bytes(b"upload-v1")
    archive = tmp_path / "update_backup_x.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(repo / "instance" / "app.db", arcname="instance/app.db")
        tf.add(repo / "uploads", arcname="uploads")
    # the "migration" and later writes change the DB; uploads changed after backup must stay as is
    make_db(repo / "instance" / "app.db", "migrated")
    (repo / "instance" / "app.db-wal").write_bytes(b"stale")
    (repo / "uploads" / "u.bin").write_bytes(b"upload-v2")
    res = run_fn(tmp_path, repo, f'BACKUP_DIR="{tmp_path}"; restore_db_from_backup "{archive}"')
    assert res.returncode == 0, res.stdout + res.stderr
    assert read_db(repo / "instance" / "app.db") == "original"
    assert not (repo / "instance" / "app.db-wal").exists()
    assert (repo / "uploads" / "u.bin").read_bytes() == b"upload-v2"  # uploads never restored
    assert not list((repo / "instance").glob(".restore.*"))


def test_restore_fails_cleanly_without_backup(tmp_path, repo):
    make_db(repo / "instance" / "app.db", "kept")
    res = run_fn(tmp_path, repo, 'restore_db_from_backup ""')
    assert res.returncode != 0
    assert read_db(repo / "instance" / "app.db") == "kept"


# ------------------------------------------------------------------ M8 / B11 dynamic

def prep_backup_tree(repo):
    make_db(repo / "instance" / "app.db", "data")
    q = repo / "instance" / "quarantine"
    q.mkdir()
    (q / "evil.bin").write_bytes(b"quarantined")
    (repo / "uploads").mkdir()
    (repo / "uploads" / "u.bin").write_bytes(b"u")


def names(archive_bytes_path):
    with tarfile.open(archive_bytes_path) as tf:
        return tf.getnames()


def test_backup_without_passphrase_excludes_quarantine(tmp_path, repo):
    prep_backup_tree(repo)
    res = run_fn(tmp_path, repo, 'STAMP=t1; BACKUP_DIR="$ROOT/backups"; KEEP_UPDATE_BACKUPS=3; make_backup; echo "F=$BACKUP_FILE"')
    assert res.returncode == 0, res.stdout + res.stderr
    f = repo / "backups" / "update_backup_t1.tar.gz"
    assert f.exists() and (f.stat().st_mode & 0o777) == 0o600
    got = names(f)
    assert "instance/app.db" in got and "uploads/u.bin" in got
    assert not any("quarantine" in n for n in got)
    assert "WARNING" in res.stdout


@pytest.mark.skipif(not HAVE_GPG, reason="gpg not installed")
def test_backup_with_passphrase_is_encrypted_gpg(tmp_path, repo):
    prep_backup_tree(repo)
    env = {"BACKUP_PASSPHRASE": "correct horse battery staple", "GNUPGHOME": str(tmp_path / "gpghome")}
    (tmp_path / "gpghome").mkdir(mode=0o700)
    res = run_fn(tmp_path, repo,
                 'STAMP=t2; BACKUP_DIR="$ROOT/backups"; make_backup; echo "F=$BACKUP_FILE"; '
                 'decrypt_stream "$BACKUP_FILE" > "$ROOT/dec.tar.gz"', **env)
    subprocess.run(["gpgconf", "--kill", "all"], env={"GNUPGHOME": str(tmp_path / "gpghome"),
                   "PATH": os.environ["PATH"]}, capture_output=True)
    assert res.returncode == 0, res.stdout + res.stderr
    f = repo / "backups" / "update_backup_t2.tar.gz.gpg"
    assert f.exists() and (f.stat().st_mode & 0o777) == 0o600
    assert not (repo / "backups" / "update_backup_t2.tar.gz").exists()
    assert b"quarantined" not in f.read_bytes()
    got = names(repo / "dec.tar.gz")
    assert "instance/quarantine/evil.bin" in got  # complete backup once encrypted


@pytest.mark.skipif(not HAVE_OPENSSL, reason="openssl not installed")
def test_backup_openssl_fallback_is_authenticated(tmp_path, repo):
    prep_backup_tree(repo)
    env = {"BACKUP_PASSPHRASE": "correct horse battery staple"}
    res = run_fn(tmp_path, repo,
                 'STAMP=t3; BACKUP_DIR="$ROOT/backups"; make_backup; '
                 'decrypt_stream "$BACKUP_FILE" > "$ROOT/dec.tar.gz"', with_gpg=False, **env)
    assert res.returncode == 0, res.stdout + res.stderr
    f = repo / "backups" / "update_backup_t3.tar.gz.enc"
    assert f.exists() and (repo / "backups" / "update_backup_t3.tar.gz.enc.hmac").exists()
    assert "instance/quarantine/evil.bin" in names(repo / "dec.tar.gz")
    # tampering is detected before decrypting
    blob = bytearray(f.read_bytes())
    blob[-1] ^= 1
    f.write_bytes(bytes(blob))
    bad = run_fn(tmp_path, repo, f'decrypt_stream "{f}" > "$ROOT/out.bin"', with_gpg=False, **env)
    assert bad.returncode != 0
    assert "HMAC" in bad.stderr


@pytest.mark.skipif(not HAVE_OPENSSL, reason="openssl not installed")
def test_backup_sh_restore_still_reads_legacy_enc(tmp_path):
    """Old *.enc backups (no sidecar) stay restorable by backup.sh's openssl command line."""
    src = BACKUP.read_text()
    assert "legacy" in src.lower()
    assert re.search(r"openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000", src)
