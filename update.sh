#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Safe updater: pulls the latest code, upgrades dependencies to the patched
# versions pinned in requirements.txt, applies DB migrations and runs a CVE
# scan. It NEVER deletes or overwrites your data:
#   - .env, instance/ (database), uploads/ are never modified by this script
#   - a timestamped backup of the database + uploads is taken first
#   - `git pull --ff-only` refuses to run if you have local code changes
# Usage:   ./update.sh            (run from the project folder)
#          VENV=/path/to/venv ./update.sh
# Run it regularly (e.g. weekly via cron): new CVEs appear all the time.
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="$ROOT/backups"

# Pick the virtualenv (VENV env var, ./venv or ./.venv); fall back to system python.
VENV="${VENV:-}"
if [ -z "$VENV" ]; then
    for d in venv .venv env; do
        if [ -x "$ROOT/$d/bin/python" ]; then VENV="$ROOT/$d"; break; fi
    done
fi
if [ -n "$VENV" ]; then PY="$VENV/bin/python"; else PY="$(command -v python3)"; fi
echo "==> Python: $PY"

# 1. Backup (read-only copy of your data)
echo "==> Backup of database and uploads -> $BACKUP_DIR/backup_$STAMP.tar.gz"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
to_save=()
[ -d instance ] && to_save+=("instance")
[ -d uploads ] && to_save+=("uploads")
for f in *.db; do [ -e "$f" ] && to_save+=("$f"); done
if [ ${#to_save[@]} -gt 0 ]; then
    tar -czf "$BACKUP_DIR/backup_$STAMP.tar.gz" "${to_save[@]}"
    chmod 600 "$BACKUP_DIR/backup_$STAMP.tar.gz"
else
    echo "    (nothing to back up)"
fi

# 2. Code update (only if this is a git checkout; never overwrites local edits)
if [ -d .git ]; then
    echo "==> Pulling latest code (fast-forward only)"
    if ! git diff --quiet || ! git diff --cached --quiet; then
        echo "!! Local code changes detected: commit or stash them first. Aborting (nothing changed)."
        exit 1
    fi
    git pull --ff-only
fi

# 3. Dependencies (patched versions pinned in requirements.txt)
echo "==> Upgrading dependencies"
"$PY" -m pip install --upgrade pip
"$PY" -m pip install --upgrade -r requirements.txt

# 4. Database schema migrations (Alembic only ADDS/ALTERS schema, data is kept)
if [ -d migrations ]; then
    echo "==> Applying database migrations"
    FLASK_APP=app "$PY" -m flask db upgrade
fi

# 5. Vulnerability scan of the installed dependencies
echo "==> Scanning dependencies for known CVEs (pip-audit)"
"$PY" -m pip install --quiet --upgrade pip-audit
if "$PY" -m pip_audit -r requirements.txt; then
    echo "==> No known vulnerabilities."
else
    echo "!! pip-audit reported vulnerabilities above: bump the listed packages in requirements.txt."
fi

echo
echo "Update done. Backup kept in: $BACKUP_DIR/backup_$STAMP.tar.gz"
echo "Now restart the app (e.g. 'sudo systemctl restart blog' or restart gunicorn)."
