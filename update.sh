#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Safe updater: pulls the latest code, upgrades dependencies to the patched
# versions pinned in requirements.txt, applies DB migrations, checks that the
# app still starts (and runs the test suite when pytest is installed), then
# runs a CVE scan. It NEVER deletes or overwrites your data:
#   - .env, instance/ (database) and uploads/ are never modified by this script
#   - a timestamped backup of the database + uploads is taken first
#   - `git pull --ff-only` refuses to run if you have local code changes
#   - if the new version fails its checks, code + dependencies are rolled back
#
# Usage:
#   ./update.sh                 interactive run (from the project folder)
#   ./update.sh --auto          unattended run (used by auto-update.sh / cron):
#                               skips everything if there is nothing new,
#                               restarts the app with RESTART_CMD on success
#   VENV=/path/to/venv ./update.sh
#   RESTART_CMD="sudo systemctl restart blog" ./update.sh --auto
#
# Run it regularly: new CVEs are published every week. To schedule it, see
# ./auto-update.sh (daily / weekly / monthly / custom).
# ---------------------------------------------------------------------------
set -euo pipefail

AUTO=0
[ "${1:-}" = "--auto" ] && AUTO=1

cd "$(dirname "$0")"
ROOT="$(pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="$ROOT/backups"
LOCK_FILE="$ROOT/instance/.update.lock"
KEEP_UPDATE_BACKUPS="${KEEP_UPDATE_BACKUPS:-10}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# Read one KEY=value from .env without executing the file.
env_get() {
    [ -f "$ROOT/.env" ] || return 0
    { grep -E "^[[:space:]]*$1=" "$ROOT/.env" || true; } | tail -n1 | cut -d= -f2- | sed -e 's/^["'\'']//' -e 's/["'\'']$//'
}
[ -z "${RESTART_CMD:-}" ] && RESTART_CMD="$(env_get UPDATE_RESTART_CMD)"

# Pick the virtualenv (VENV env var, ./venv or ./.venv); fall back to system python.
VENV="${VENV:-}"
if [ -z "$VENV" ]; then
    for d in venv .venv env; do
        if [ -x "$ROOT/$d/bin/python" ]; then VENV="$ROOT/$d"; break; fi
    done
fi
if [ -n "$VENV" ]; then PY="$VENV/bin/python"; else PY="$(command -v python3)"; fi

# Optional Telegram notification (uses the bot configured in .env, if any).
notify() {
    "$PY" - "$1" <<'PYEOF' >/dev/null 2>&1 || true
import os, sys
from dotenv import load_dotenv
import requests
load_dotenv()
token = os.environ.get('TELEGRAM_BOT_TOKEN', '').strip()
chat = (os.environ.get('TELEGRAM_AUDIT_CHAT_ID') or os.environ.get('TELEGRAM_ADMIN_CHAT_ID') or '').strip()
if token and chat:
    requests.post(f'https://api.telegram.org/bot{token}/sendMessage',
                  data={'chat_id': chat, 'text': sys.argv[1], 'disable_notification': True}, timeout=10)
PYEOF
}

# Only one update at a time (cron + manual run).
mkdir -p "$ROOT/instance"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    log "Another update is already running. Exiting."
    exit 0
fi

log "Python: $PY"
PREV_COMMIT=""
IS_GIT=0
if [ -d .git ]; then
    IS_GIT=1
    PREV_COMMIT="$(git rev-parse HEAD)"
fi

# 0. In --auto mode, do nothing (no backup, no restart) when there is no new code.
if [ "$AUTO" = 1 ] && [ "$IS_GIT" = 1 ]; then
    if ! git rev-parse --abbrev-ref '@{u}' >/dev/null 2>&1; then
        log "!! The current branch has no upstream (git branch -u origin/main). Aborting."
        exit 1
    fi
    git fetch --quiet
    if [ "$(git rev-parse HEAD)" = "$(git rev-parse '@{u}')" ]; then
        log "Already up to date. Checking installed dependencies for new CVEs only."
        "$PY" -m pip install --quiet --upgrade pip-audit >/dev/null 2>&1 || true
        if ! "$PY" -m pip_audit -r requirements.txt >/tmp/blog-pip-audit.$$ 2>&1; then
            cat /tmp/blog-pip-audit.$$
            notify "blog-privacy: pip-audit found vulnerable dependencies and no fix has been published in the repository yet. Check update.log."
        fi
        rm -f /tmp/blog-pip-audit.$$
        exit 0
    fi
fi

# 1. Backup (read-only copy of your data)
log "Backup of database and uploads -> $BACKUP_DIR/update_backup_$STAMP.tar.gz"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
to_save=()
[ -d instance ] && to_save+=("instance")
[ -d uploads ] && to_save+=("uploads")
for f in *.db; do [ -e "$f" ] && to_save+=("$f"); done
if [ ${#to_save[@]} -gt 0 ]; then
    tar --exclude='instance/.update.lock' -czf "$BACKUP_DIR/update_backup_$STAMP.tar.gz" "${to_save[@]}"
    chmod 600 "$BACKUP_DIR/update_backup_$STAMP.tar.gz"
    # keep only the most recent update backups
    ls -1t "$BACKUP_DIR"/update_backup_*.tar.gz 2>/dev/null | tail -n +$((KEEP_UPDATE_BACKUPS + 1)) | xargs -r rm -f
else
    log "(nothing to back up)"
fi

rollback() {
    log "!! $1 -> rolling back code and dependencies (your data is untouched)."
    if [ "$IS_GIT" = 1 ] && [ -n "$PREV_COMMIT" ]; then
        git reset --quiet --hard "$PREV_COMMIT"
    fi
    "$PY" -m pip install --quiet -r requirements.txt || true
    notify "blog-privacy: automatic update FAILED ($1) and was rolled back. Check update.log."
    exit 1
}

# 2. Code update (only if this is a git checkout; never overwrites local edits)
if [ "$IS_GIT" = 1 ]; then
    log "Pulling latest code (fast-forward only)"
    if ! git diff --quiet || ! git diff --cached --quiet; then
        log "!! Local code changes detected: commit or stash them first. Aborting (nothing changed)."
        notify "blog-privacy: update skipped, the server has local code changes."
        exit 1
    fi
    git pull --ff-only --quiet || rollback "git pull failed"
fi

# 3. Dependencies (patched versions pinned in requirements.txt)
log "Upgrading dependencies"
"$PY" -m pip install --quiet --upgrade pip || true
"$PY" -m pip install --quiet --upgrade -r requirements.txt || rollback "dependency install failed"

# 4. Database schema migrations (Alembic only ADDS/ALTERS schema, data is kept)
if [ -d migrations ]; then
    log "Applying database migrations"
    FLASK_APP=app TELEGRAM_BOT_TOKEN="" "$PY" -m flask db upgrade || rollback "database migration failed"
fi

# 5. Health check: the new version must at least start (Telegram disabled so
#    the check does not consume bot updates).
log "Checking that the app starts"
TELEGRAM_BOT_TOKEN="" "$PY" -c "import app" || rollback "the new version does not start"
if "$PY" -c "import pytest" >/dev/null 2>&1 && [ -d tests ]; then
    log "Running the test suite"
    TELEGRAM_BOT_TOKEN="" "$PY" -m pytest -q -p no:cacheprovider tests/ || rollback "tests failed"
fi

# 6. Vulnerability scan of the installed dependencies
log "Scanning dependencies for known CVEs (pip-audit)"
"$PY" -m pip install --quiet --upgrade pip-audit || true
if "$PY" -m pip_audit -r requirements.txt; then
    log "No known vulnerabilities."
else
    log "!! pip-audit reported vulnerabilities above."
    notify "blog-privacy: pip-audit still reports vulnerable dependencies after the update. Check update.log."
fi

NEW_COMMIT="$( [ "$IS_GIT" = 1 ] && git rev-parse --short HEAD || echo n/a )"

# 7. Restart
if [ -n "${RESTART_CMD:-}" ]; then
    log "Restarting the app: $RESTART_CMD"
    if bash -c "$RESTART_CMD"; then
        notify "blog-privacy: updated to $NEW_COMMIT and restarted."
    else
        notify "blog-privacy: updated to $NEW_COMMIT but the restart command failed."
        exit 1
    fi
else
    log "Update done. Restart the app now (e.g. 'sudo systemctl restart blog')."
    [ "$AUTO" = 1 ] && notify "blog-privacy: updated to $NEW_COMMIT. Restart the app to apply it (UPDATE_RESTART_CMD is not set)."
fi
log "Backup kept in: $BACKUP_DIR/update_backup_$STAMP.tar.gz"
