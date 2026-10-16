#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Safe updater: fetches the latest code, VERIFIES ITS SIGNATURE, upgrades
# dependencies to the patched versions pinned in requirements.lock, applies DB
# migrations, checks that the app still starts (and runs the test suite when
# pytest is installed), then runs a CVE scan. It NEVER deletes or overwrites
# your data without a reason:
#   - .env, instance/ (database) and uploads/ are never modified by this script
#     (the only exception is the rollback, which restores the database)
#   - a timestamped backup of the database + uploads is taken first
#   - only a fast-forward to a commit signed by a trusted key is accepted;
#     the script refuses to run if you have local code changes
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
# Authenticity of the code (settings in the environment or in .env):
#   UPDATE_GPG_HOME=/path/to/gnupg-dir   dedicated GNUPGHOME holding ONLY the
#                           public keys allowed to sign releases. Required:
#                           without it the update is refused (fail closed).
#   UPDATE_TRUSTED_FINGERPRINTS="FPR1 FPR2"   optional: additionally pin the
#                           signing key (full fingerprints, primary or subkey).
#   UPDATE_ALLOW_UNSIGNED=1 explicit opt-out: update WITHOUT any signature
#                           check (noisy warning in the log). Not recommended.
#
# TODO(audit-2026-10-16): decision needed. The "Merge pull request" commits
# created by GitHub are signed by GitHub's web-flow key, and only if the merge
# is done in the web UI. Either (a) sign the release tips yourself and import
# only your key, or (b) import GitHub's web-flow key and pin it with
# UPDATE_TRUSTED_FINGERPRINTS. Until the maintainers choose, an unsigned tip
# is refused.
#
# Run it regularly: new CVEs are published every week. To schedule it, see
# ./auto-update.sh (daily / weekly / monthly / custom).
# ---------------------------------------------------------------------------
set -euo pipefail

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# Read one KEY=value from .env without executing the file.
env_get() {
    [ -f "$ROOT/.env" ] || return 0
    { grep -E "^[[:space:]]*$1=" "$ROOT/.env" || true; } | tail -n1 | cut -d= -f2- | sed -e 's/^["'\'']//' -e 's/["'\'']$//'
}

# Status messages only go to the log (logs/update.log). Nothing is sent to a
# third party: the former Telegram notification was removed on purpose.
notify() {
    log "$1" || true
}

encrypt_legacy() {
    # Idempotent: encrypts chat messages / uploads still stored in plaintext.
    FLASK_APP=app "$PY" -m flask encrypt-legacy \
        || log "!! flask encrypt-legacy failed (data untouched); run it again by hand."
}

# Authenticity check of the commit we are about to fast-forward to. Runs
# BEFORE any merge/checkout, so unverified code is never put in the work tree
# (let alone executed). Returns 0 only if the commit is acceptable.
#   - UPDATE_GPG_HOME unset: refuse, unless UPDATE_ALLOW_UNSIGNED=1
#   - otherwise `git verify-commit --raw` with GNUPGHOME=$UPDATE_GPG_HOME must
#     report a valid signature (VALIDSIG), and, when UPDATE_TRUSTED_FINGERPRINTS
#     is set, the signing key (or its primary key) must be listed there.
# The signature on the tip commit covers the whole history behind it (hash
# chain), so intermediate commits need not be signed individually.
verify_target() {
    local rev="$1" home allow fprs out line sig_fpr sig_primary want ok=0
    home="${UPDATE_GPG_HOME:-$(env_get UPDATE_GPG_HOME)}"
    allow="${UPDATE_ALLOW_UNSIGNED:-$(env_get UPDATE_ALLOW_UNSIGNED)}"
    fprs="${UPDATE_TRUSTED_FINGERPRINTS:-$(env_get UPDATE_TRUSTED_FINGERPRINTS)}"
    if [ -z "$home" ]; then
        if [ "$allow" = "1" ]; then
            log "!!!! WARNING: UPDATE_ALLOW_UNSIGNED=1 and no UPDATE_GPG_HOME: updating WITHOUT"
            log "!!!! verifying the authenticity of ${rev:0:12}. Anyone able to push to the"
            log "!!!! remote (or to impersonate it) gets code execution on this server."
            return 0
        fi
        log "!! No UPDATE_GPG_HOME configured: refusing to update (fail closed)."
        log "!! Create a dedicated keyring with the release signing key (see README) or,"
        log "!! at your own risk, set UPDATE_ALLOW_UNSIGNED=1."
        return 1
    fi
    if [ ! -d "$home" ]; then
        log "!! UPDATE_GPG_HOME '$home' is not a directory. Refusing to update."
        return 1
    fi
    if ! out="$(GNUPGHOME="$home" git verify-commit --raw "$rev" 2>&1)"; then
        log "!! The signature of ${rev:0:12} could not be verified. Refusing to update."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    if printf '%s\n' "$out" | grep -qE '^\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG) '; then
        log "!! ${rev:0:12} has a bad, expired or revoked signature. Refusing to update."
        return 1
    fi
    if [ -z "$fprs" ]; then
        if printf '%s\n' "$out" | grep -q '^\[GNUPG:\] VALIDSIG '; then
            log "Signature of ${rev:0:12} OK (any key of $home)."
            return 0
        fi
        log "!! No valid signature found for ${rev:0:12}. Refusing to update."
        return 1
    fi
    while read -r line; do
        sig_fpr="$(printf '%s' "$line" | awk '{print $3}')"
        sig_primary="$(printf '%s' "$line" | awk '{print $NF}')"
        for want in ${fprs//,/ }; do
            want="${want^^}"
            if [ "${sig_fpr^^}" = "$want" ] || [ "${sig_primary^^}" = "$want" ]; then ok=1; fi
        done
    done < <(printf '%s\n' "$out" | grep '^\[GNUPG:\] VALIDSIG ' || true)
    if [ "$ok" != 1 ]; then
        log "!! ${rev:0:12} is signed, but not by a key listed in UPDATE_TRUSTED_FINGERPRINTS. Refusing to update."
        return 1
    fi
    log "Signature of ${rev:0:12} OK (trusted fingerprint)."
}

# git fetch + resolve the upstream tip into TARGET. Never touches the work tree.
fetch_target() {
    if ! git rev-parse --abbrev-ref '@{u}' >/dev/null 2>&1; then
        log "!! The current branch has no upstream (git branch -u origin/main). Aborting."
        return 1
    fi
    git fetch --quiet || return 1
    TARGET="$(git rev-parse '@{u}')"
}

rollback() {
    log "!! $1 -> rolling back code and dependencies (your data is untouched)."
    if [ "$IS_GIT" = 1 ] && [ -n "$PREV_COMMIT" ]; then
        git reset --quiet --hard "$PREV_COMMIT"
    fi
    "$PY" -m pip install --quiet -r requirements.txt || true
    notify "blog-privacy: automatic update FAILED ($1) and was rolled back. Check update.log."
    exit 1
}

main() {
# Bash reads a script while running it, and step 2 (merge) rewrites this very
# file: always run from a private copy so the update can never execute a
# half-old, half-new script.
if [ "${BLOG_UPDATE_COPY:-}" != "1" ]; then
    root_dir="$(cd "$(dirname "$0")" && pwd)"
    tmp_copy="$(mktemp "${TMPDIR:-/tmp}/blog-update.XXXXXX")"
    cp "$0" "$tmp_copy"
    BLOG_UPDATE_COPY=1 BLOG_UPDATE_ROOT="$root_dir" BLOG_UPDATE_SELF="$tmp_copy" exec bash "$tmp_copy" "$@"
fi
trap 'rm -f "${BLOG_UPDATE_SELF:-}"' EXIT

AUTO=0
RESUME_FROM=""   # set when a new update.sh takes over right after the merge
while [ $# -gt 0 ]; do
    case "$1" in
        --auto) AUTO=1 ;;
        --resume-after-pull) RESUME_FROM="${2:-}"; shift ;;
    esac
    shift
done

cd "$BLOG_UPDATE_ROOT"
ROOT="$(pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="$ROOT/backups"
LOCK_FILE="$ROOT/instance/.update.lock"
KEEP_UPDATE_BACKUPS="${KEEP_UPDATE_BACKUPS:-10}"

[ -z "${RESTART_CMD:-}" ] && RESTART_CMD="$(env_get UPDATE_RESTART_CMD)"

# Pick the virtualenv (VENV env var, ./venv or ./.venv); fall back to system python.
VENV="${VENV:-}"
if [ -z "$VENV" ]; then
    for d in venv .venv env; do
        if [ -x "$ROOT/$d/bin/python" ]; then VENV="$ROOT/$d"; break; fi
    done
fi
if [ -n "$VENV" ]; then PY="$VENV/bin/python"; else PY="$(command -v python3)"; fi

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
    PREV_COMMIT="${RESUME_FROM:-$(git rev-parse HEAD)}"
fi

# 0. In --auto mode, do nothing (no backup, no restart) when there is no new code.
if [ "$AUTO" = 1 ] && [ "$IS_GIT" = 1 ]; then
    fetch_target || exit 1
    if [ -z "$RESUME_FROM" ] && [ "$(git rev-parse HEAD)" = "$TARGET" ]; then
        log "Already up to date."
        # The running version is the installed, known-good one: safe to run.
        encrypt_legacy
        log "Checking installed dependencies for new CVEs."
        "$PY" -m pip install --quiet --upgrade pip-audit >/dev/null 2>&1 || true
        if ! "$PY" -m pip_audit -r requirements.txt >/tmp/blog-pip-audit.$$ 2>&1; then
            cat /tmp/blog-pip-audit.$$
            notify "blog-privacy: pip-audit found vulnerable dependencies and no fix has been published in the repository yet. Check update.log."
        fi
        rm -f /tmp/blog-pip-audit.$$
        exit 0
    fi
fi

if [ -z "$RESUME_FROM" ]; then
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

# 2. Code update (only if this is a git checkout; never overwrites local edits).
#    fetch -> verify the signature of the target -> fast-forward. Nothing is
#    merged or checked out before the signature has been verified.
if [ "$IS_GIT" = 1 ]; then
    log "Fetching latest code"
    if ! git diff --quiet || ! git diff --cached --quiet; then
        log "!! Local code changes detected: commit or stash them first. Aborting (nothing changed)."
        notify "blog-privacy: update skipped, the server has local code changes."
        exit 1
    fi
    fetch_target || { notify "blog-privacy: update aborted, git fetch failed (nothing changed)."; exit 1; }
    if [ "$TARGET" != "$(git rev-parse HEAD)" ]; then
        if ! verify_target "$TARGET"; then
            notify "blog-privacy: update REFUSED, the new commit ${TARGET:0:12} has no valid trusted signature (nothing changed)."
            exit 1
        fi
        log "Fast-forwarding to ${TARGET:0:12}"
        git merge --ff-only --quiet "$TARGET" || rollback "fast-forward failed"
    fi
    # If the updater itself changed, let the NEW version run the next steps
    # (it knows about the new release: migrations, data conversions...).
    if ! git diff --quiet "$PREV_COMMIT" HEAD -- update.sh; then
        log "update.sh changed: continuing with the new version"
        resume_args=(--resume-after-pull "$PREV_COMMIT")
        [ "$AUTO" = 1 ] && resume_args+=(--auto)
        rm -f "${BLOG_UPDATE_SELF:-}"   # exec skips the EXIT trap
        exec env -u BLOG_UPDATE_COPY -u BLOG_UPDATE_SELF bash "$ROOT/update.sh" "${resume_args[@]}"
    fi
fi
else
    log "Resuming after the code update (previous version: ${RESUME_FROM:0:12})"
fi

# 3. Dependencies (patched versions pinned in requirements.txt)
log "Upgrading dependencies"
"$PY" -m pip install --quiet --upgrade pip || true
"$PY" -m pip install --quiet --upgrade -r requirements.txt || rollback "dependency install failed"

# 4. Database schema migrations (Alembic only ADDS/ALTERS schema, data is kept)
if [ -d migrations ]; then
    log "Applying database migrations"
    FLASK_APP=app "$PY" -m flask db upgrade || rollback "database migration failed"
fi

# 5. Health check: the new version must at least start.
log "Checking that the app starts"
"$PY" -c "import app" || rollback "the new version does not start"
if "$PY" -c "import pytest" >/dev/null 2>&1 && [ -d tests ]; then
    log "Running the test suite"
    "$PY" -m pytest -q -p no:cacheprovider tests/ || rollback "tests failed"
fi

# 6. Encrypt legacy plaintext messages / uploads (idempotent). Done only once
#    the new version is known to work: from here on there is no rollback,
#    because the previous version could not read encrypted uploads.
log "Encrypting any legacy plaintext messages / uploads"
encrypt_legacy

# 7. Vulnerability scan of the installed dependencies
log "Scanning dependencies for known CVEs (pip-audit)"
"$PY" -m pip install --quiet --upgrade pip-audit || true
if "$PY" -m pip_audit -r requirements.txt; then
    log "No known vulnerabilities."
else
    log "!! pip-audit reported vulnerabilities above."
    notify "blog-privacy: pip-audit still reports vulnerable dependencies after the update. Check update.log."
fi

NEW_COMMIT="$( [ "$IS_GIT" = 1 ] && git rev-parse --short HEAD || echo n/a )"

# 8. Restart
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
log "Backups of your data before the update are in: $BACKUP_DIR"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
