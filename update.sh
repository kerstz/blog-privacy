#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Safe updater: fetches the latest code, VERIFIES ITS SIGNATURE, upgrades
# dependencies to the patched versions pinned in requirements.lock (hashes enforced), applies DB
# migrations, checks that the app still starts (and runs the test suite when
# pytest is installed), then runs a CVE scan. It NEVER deletes or overwrites
# your data without a reason:
#   - .env, instance/ (database) and uploads/ are never modified by this script
#     (the only exception is the rollback, which restores the database)
#   - a timestamped backup of the database + uploads is taken first, encrypted
#     with BACKUP_PASSPHRASE (same as backup.sh); without a passphrase the
#     backup is left in clear text but WITHOUT instance/quarantine
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
umask 077

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

# ---- encrypted update backups ---------------------------------------------
# The crypto below mirrors backup.sh (same BACKUP_PASSPHRASE, same formats):
# gpg --symmetric AES256 when gpg exists (authenticated), otherwise openssl
# AES-256-CBC + PBKDF2 (600000 it.) plus an HMAC-SHA256 sidecar (<file>.hmac,
# encrypt-then-MAC) that is verified before anything is decrypted.
# Without a passphrase no clear-text archive containing instance/quarantine
# is ever written: the quarantine is left out and a warning is logged.

# Prints the passphrase (BACKUP_PASSPHRASE env or .env, >= 16 chars) or fails.
backup_passphrase() {
    local p="${BACKUP_PASSPHRASE:-$(env_get BACKUP_PASSPHRASE)}"
    [ -n "$p" ] && [ "${#p}" -ge 16 ] || return 1
    printf '%s' "$p"
}

# HMAC-SHA256 (hex) of a file, key derived from the passphrase with PBKDF2.
mac_file() {  # $1 = file, $2 = passphrase
    BACKUP_PASS="$2" "$PY" -I -c '
import hashlib, hmac, os, sys
k = hashlib.pbkdf2_hmac("sha256", os.environ["BACKUP_PASS"].encode(), b"blog-privacy-backup-mac-v1", 600000)
h = hmac.new(k, digestmod="sha256")
with open(sys.argv[1], "rb") as f:
    for b in iter(lambda: f.read(1 << 20), b""):
        h.update(b)
print(h.hexdigest())' "$1"
}

encrypt_stream() {  # stdin -> $1.gpg|$1.enc ; prints the output path
    local pass; pass="$(backup_passphrase)" || return 1
    if command -v gpg >/dev/null 2>&1; then
        gpg --batch --yes --quiet --pinentry-mode loopback --passphrase-fd 3 \
            --symmetric --cipher-algo AES256 -o "$1.gpg" 3<<<"$pass" || return 1
        echo "$1.gpg"
    else
        BACKUP_PASS="$pass" openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
            -pass env:BACKUP_PASS -out "$1.enc" || return 1
        mac_file "$1.enc" "$pass" > "$1.enc.hmac" || return 1
        echo "$1.enc"
    fi
}

decrypt_stream() {  # $1 = backup file -> tar.gz stream on stdout
    local file="$1" pass
    case "$file" in
        *.tar.gz) cat "$file" ;;
        *.gpg)
            pass="$(backup_passphrase)" || { log "!! BACKUP_PASSPHRASE is needed to read $file"; return 1; }
            gpg --batch --quiet --pinentry-mode loopback --passphrase-fd 3 -d "$file" 3<<<"$pass" ;;
        *.enc)
            pass="$(backup_passphrase)" || { log "!! BACKUP_PASSPHRASE is needed to read $file"; return 1; }
            if [ ! -f "$file.hmac" ] || [ "$(cat "$file.hmac")" != "$(mac_file "$file" "$pass")" ]; then
                log "!! Missing or invalid HMAC for $file: refusing to decrypt."
                return 1
            fi
            BACKUP_PASS="$pass" openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass env:BACKUP_PASS -in "$file" ;;
        *) log "!! Unknown backup format: $file"; return 1 ;;
    esac
}

# Backup of instance/ (database, quarantine), uploads/ and root *.db files.
# Sets BACKUP_FILE (empty when there was nothing to save). The archive is
# created with umask 077 and chmod 600.
make_backup() {
    BACKUP_FILE=""
    local base="$BACKUP_DIR/update_backup_$STAMP.tar.gz" f out
    local to_save=() excl=(--exclude='instance/.update.lock')
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    [ -d instance ] && to_save+=("instance")
    [ -d uploads ] && to_save+=("uploads")
    for f in *.db; do [ -e "$f" ] && to_save+=("$f"); done
    if [ ${#to_save[@]} -eq 0 ]; then
        log "(nothing to back up)"
        return 0
    fi
    if backup_passphrase >/dev/null; then
        log "Encrypted backup of database and uploads -> $base.gpg|.enc"
        if ! out="$(tar "${excl[@]}" -czf - "${to_save[@]}" | encrypt_stream "$base")"; then
            rm -f "$base.gpg" "$base.enc" "$base.enc.hmac"
            log "!! Encrypting the backup failed. Aborting (nothing changed)."
            return 1
        fi
        BACKUP_FILE="$out"
    else
        log "!! WARNING: BACKUP_PASSPHRASE is missing or shorter than 16 characters: the backup"
        log "!! is NOT encrypted, so instance/quarantine is EXCLUDED from it. Set BACKUP_PASSPHRASE"
        log "!! in .env (same value as for backup.sh) to get complete encrypted backups."
        log "Backup of database and uploads -> $base"
        tar "${excl[@]}" --exclude='instance/quarantine' -czf "$base" "${to_save[@]}" || return 1
        BACKUP_FILE="$base"
    fi
    chmod 600 "$BACKUP_FILE"
    # keep only the most recent update backups
    ls -1t "$BACKUP_DIR"/update_backup_*.tar.gz "$BACKUP_DIR"/update_backup_*.tar.gz.gpg \
        "$BACKUP_DIR"/update_backup_*.tar.gz.enc 2>/dev/null \
        | tail -n +$((KEEP_UPDATE_BACKUPS + 1)) | while read -r f; do rm -f "$f" "$f.hmac"; done
}

# Installs the dependencies of the code that is currently checked out, from
# the hash-pinned requirements.lock (--require-hashes: every artifact must
# match a known sha256). No `pip install --upgrade pip`, no unpinned tool in
# the production venv. Only an old checkout without a lock falls back to
# requirements.txt (with a warning).
install_deps() {
    if [ -f requirements.lock ]; then
        "$PY" -m pip install --quiet --require-hashes -r requirements.lock
    else
        log "!! requirements.lock is missing: falling back to UNHASHED requirements.txt."
        "$PY" -m pip install --quiet -r requirements.txt
    fi
}

# CVE scan of the dependencies. pip-audit is NEVER installed in the production
# venv: it runs from an isolated, version-pinned environment (uvx or pipx).
# Without one of them the scan is skipped. Returns non-zero only when
# vulnerabilities are reported.
run_pip_audit() {
    local spec="${UPDATE_PIP_AUDIT_SPEC:-pip-audit==2.9.0}" req=requirements.txt
    local extra=()
    if [ -f requirements.lock ]; then req=requirements.lock; extra=(--no-deps --disable-pip); fi
    if command -v uvx >/dev/null 2>&1; then
        uvx --from "$spec" pip-audit -r "$req" ${extra[@]+"${extra[@]}"}
    elif command -v pipx >/dev/null 2>&1; then
        pipx run --spec "$spec" pip-audit -r "$req" ${extra[@]+"${extra[@]}"}
    else
        log "pip-audit skipped: neither uvx nor pipx is installed (it must not be installed in the production venv)."
        return 0
    fi
}

# Current Alembic revision (informational, logged before the update so that
# an operator can see exactly which schema the backup corresponds to).
db_current_revision() {
    FLASK_APP=app "$PY" -m flask db current 2>/dev/null \
        | awk '/^[0-9A-Za-z_]+([[:space:]]|$)/ && $1 != "INFO" {print $1; exit}' || true
}

# Put the database files back from the backup taken just before the update.
# Only *.db files (instance/*.db and root *.db) are restored: uploads/, .env
# and instance/quarantine are NOT touched (a migration never changes them).
# We restore the snapshot instead of running `flask db downgrade` because a
# downgrade needs the downgrade() code of the NEW migrations (often missing,
# and frequently lossy: dropped columns/tables), whereas the snapshot is an
# exact, tested copy. Data written between the backup and the rollback (the
# app keeps serving during the update) is lost; it is the price of an exact
# return to the previous schema. Replacement is atomic (copy + mv), WAL/journal
# leftovers of the live file are removed.
restore_db_from_backup() {  # $1 = archive made by make_backup
    local archive="${1:-}" tmp f rel dest restored=0
    if [ -z "$archive" ] || [ ! -f "$archive" ]; then
        log "!! No backup archive available: cannot restore the database."
        return 1
    fi
    tmp="$(mktemp -d "$ROOT/instance/.restore.XXXXXX")"
    if ! decrypt_stream "$archive" | tar -C "$tmp" -xzf - --no-wildcards-match-slash \
            --wildcards 'instance/*.db' '*.db' 2>/dev/null; then
        log "!! Could not read the database out of $archive"
        rm -rf "$tmp"; return 1
    fi
    while IFS= read -r f; do
        rel="${f#"$tmp"/}"
        if ! "$PY" -I -c 'import sqlite3, sys; c = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True); sys.exit(0 if c.execute("PRAGMA integrity_check").fetchone()[0] == "ok" else 1)' "$f"; then
            log "!! The backed-up database $rel is corrupted: not restoring it."
            rm -rf "$tmp"; return 1
        fi
        dest="$ROOT/$rel"
        cp -p "$f" "$dest.restore.$$" && mv -f "$dest.restore.$$" "$dest" || { rm -rf "$tmp"; return 1; }
        rm -f "$dest-wal" "$dest-shm" "$dest-journal"
        log "Database restored from backup: $rel"
        restored=$((restored + 1))
    done < <(find "$tmp" -type f -name '*.db' | sort)
    rm -rf "$tmp"
    if [ "$restored" -eq 0 ]; then
        log "!! The backup contains no database file: nothing restored."
        return 1
    fi
}

# Roll back code, dependencies and (when a migration may have run) the
# database. Order: code first, then dependencies of the old code, then DB.
rollback() {
    local db_state="the database was not modified (no migration had started)"
    log "!! $1 -> rolling back code, dependencies and, if needed, the database."
    if [ "$IS_GIT" = 1 ] && [ -n "$PREV_COMMIT" ]; then
        git reset --quiet --hard "$PREV_COMMIT"
    fi
    install_deps || true
    if [ "${DB_TOUCHED:-0}" = 1 ]; then
        if restore_db_from_backup "${BACKUP_FILE:-}"; then
            db_state="the database was restored from ${BACKUP_FILE##*/} (taken just before the update, schema ${PREV_DB_REV:-unknown}); writes made since that backup are lost"
            if [ -n "${RESTART_CMD:-}" ]; then
                log "Restarting the app on the restored database: $RESTART_CMD"
                bash -c "$RESTART_CMD" || log "!! restart failed, restart the app by hand."
            else
                log "!! Restart the app now: it may still hold the pre-restore database file open."
            fi
        else
            db_state="the DATABASE COULD NOT BE RESTORED, it may be on a newer schema than the code: restore it by hand from ${BACKUP_FILE:-backups/}"
            log "!! $db_state"
        fi
    fi
    log "Rollback result: code back to ${PREV_COMMIT:0:12}; $db_state. uploads/ and .env were not touched."
    notify "blog-privacy: automatic update FAILED ($1) and was rolled back ($db_state). Check update.log."
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
# State handed over by the previous process when update.sh changed itself
BACKUP_FILE="${BLOG_UPDATE_BACKUP_FILE:-}"
PREV_DB_REV="${BLOG_UPDATE_PREV_DB_REV:-}"
DB_TOUCHED=0   # set to 1 right before the first migration is attempted
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
        if ! run_pip_audit; then
            notify "blog-privacy: pip-audit found vulnerable dependencies and no fix has been published in the repository yet. Check update.log."
        fi
        exit 0
    fi
fi

if [ -z "$RESUME_FROM" ]; then
# 1. Backup (read-only copy of your data) + schema revision before the update
make_backup || exit 1
if [ -d migrations ]; then
    PREV_DB_REV="$(db_current_revision)"
    log "Alembic revision before the update: ${PREV_DB_REV:-unknown}"
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
        exec env -u BLOG_UPDATE_COPY -u BLOG_UPDATE_SELF \
            BLOG_UPDATE_BACKUP_FILE="$BACKUP_FILE" BLOG_UPDATE_PREV_DB_REV="${PREV_DB_REV:-}" bash "$ROOT/update.sh" "${resume_args[@]}"
    fi
fi
else
    log "Resuming after the code update (previous version: ${RESUME_FROM:0:12})"
fi

# 3. Dependencies (hash-pinned in requirements.lock)
log "Installing dependencies"
install_deps || rollback "dependency install failed"

# 4. Database schema migrations (Alembic only ADDS/ALTERS schema, data is kept)
if [ -d migrations ]; then
    log "Applying database migrations"
    DB_TOUCHED=1
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
if run_pip_audit; then
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
