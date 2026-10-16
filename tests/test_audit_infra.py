"""Static infrastructure checks (no network): lockfiles, CI pinning, deploy files."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = ("socketio", "engineio", "simple-websocket", "simple_websocket")


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def _lock_entries(rel):
    """Return {requirement_line: [hash lines]} for a pip-compile style lockfile."""
    entries, current = {}, None
    for raw in _read(rel).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--hash=sha256:"):
            assert current is not None, f"orphan hash in {rel}"
            entries[current].append(line.rstrip(" \\"))
        else:
            current = line.rstrip(" \\")
            entries[current] = []
    return entries


def test_lockfiles_have_hashes_for_every_package():
    for rel in ("requirements.lock", "requirements-dev.lock"):
        entries = _lock_entries(rel)
        assert entries, rel
        for req, hashes in entries.items():
            assert "==" in req, f"{rel}: {req} is not pinned"
            assert hashes, f"{rel}: {req} has no --hash=sha256"
            for h in hashes:
                assert re.fullmatch(r"--hash=sha256:[0-9a-f]{64}", h), (rel, h)


def test_lockfile_contains_transitive_dnspython():
    names = {r.split("==")[0].lower() for r in _lock_entries("requirements.lock")}
    assert "dnspython" in names
    assert "email-validator" in names


def test_no_websocket_stack_in_requirements():
    for rel in ("requirements.in", "requirements.txt", "requirements.lock",
                "requirements-dev.in", "requirements-dev.txt", "requirements-dev.lock"):
        text = _read(rel).lower()
        for bad in FORBIDDEN:
            assert bad not in text, f"{bad} still in {rel}"


def test_lockfiles_have_no_local_paths():
    for rel in ("requirements.lock", "requirements-dev.lock", "requirements.txt"):
        text = _read(rel)
        assert "/home/" not in text and "/tmp/" not in text, rel


def test_workflow_actions_pinned_by_full_sha():
    text = _read(".github/workflows/security.yml")
    uses = re.findall(r"^\s*-?\s*uses:\s*(\S+)", text, re.M)
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", ref), f"not SHA-pinned: {ref}"
    assert "persist-credentials: false" in text
    assert "--require-hashes" in text


def test_torrc_example_enables_pow():
    assert re.search(r"^HiddenServicePoWDefensesEnabled 1$", _read("deploy/torrc.example"), re.M)
    assert "HiddenServicePoWDefensesEnabled 1" in _read("deploy/deploy-onion.sh")


def test_nginx_has_no_socketio():
    assert "socket.io" not in _read("deploy/nginx.conf").lower()
    assert "socket.io" not in _read("deploy/Caddyfile").lower()


def test_env_example_documents_operational_variables():
    text = _read(".env.example")
    for var in ("BACKUP_PASSPHRASE", "BACKUP_KEEP", "BACKUP_REMOTE",
                "UPDATE_RESTART_CMD", "HOST", "PORT", "FLASK_DEBUG",
                "MOBILE_API_ENABLED=false", "UPDATE_TRUSTED_KEYS_DIR"):
        assert re.search(rf"^#?\s*{re.escape(var)}", text, re.M), var


def test_stray_files_removed():
    assert not (ROOT / "icons-check.png").exists()
    assert "__pycache__/" in _read(".gitignore")
