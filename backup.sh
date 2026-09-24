#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Encrypted backups of everything you cannot re-download:
#   - the SQLite databases (consistent snapshot via the SQLite backup API)
#   - uploads/
#   - .env  (contains ENCRYPTION_KEY / ENCRYPTION_SALT: without them the chat
#            history can never be decrypted again)
#
#   ./backup.sh run                          make one encrypted backup now
#   ./backup.sh enable daily|weekly|"<cron>" schedule it (cron)
#   ./backup.sh disable                      remove the schedule
#   ./backup.sh status                       show schedule + latest backups
#   ./backup.sh restore <file> <empty-dir>   decrypt a backup INTO a new folder
#                                            (never overwrites the live data)
#
# Settings (in .env):
#   BACKUP_PASSPHRASE=...   required. Keep a copy OUTSIDE the server (password
#                           manager): the backups are useless without it.
#   BACKUP_KEEP=14          number of backups kept locally (default 14)
#   BACKUP_REMOTE=user@host:/path/   optional rsync target for an off-site copy
#
# Encryption: gpg (AES-256, authenticated) when available, otherwise
# openssl AES-256-CBC + PBKDF2.
# ---------------------------------------------------------------------------
set -euo pipefail
umask 077

cd "$(dirname "$0")"
ROOT="$(pwd)"
BACKUP_DIR="$ROOT/backups"
MARKER="# blog-privacy backup ($ROOT)"

env_get() {
    [ -f "$ROOT/.env" ] || return 0
    { grep -E "^[[:space:]]*$1=" "$ROOT/.env" || true; } | tail -n1 | cut -d= -f2- | sed -e 's/^["'\'']//' -e 's/["'\'']$//'
}
usage() { sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

PY=python3
for d in venv .venv env; do [ -x "$ROOT/$d/bin/python" ] && PY="$ROOT/$d/bin/python" && break; done

passphrase() {
    local p="${BACKUP_PASSPHRASE:-$(env_get BACKUP_PASSPHRASE)}"
    if [ -z "$p" ] || [ "${#p}" -lt 16 ]; then
        echo "BACKUP_PASSPHRASE is missing or shorter than 16 characters in .env." >&2
        echo "Generate one: python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"" >&2
        echo "and keep a copy outside the server." >&2
        exit 1
    fi
    printf '%s' "$p"
}

encrypt() {  # stdin -> $1
    local pass; pass="$(passphrase)"
    if command -v gpg >/dev/null 2>&1; then
        gpg --batch --yes --quiet --pinentry-mode loopback --passphrase-fd 3 \
            --symmetric --cipher-algo AES256 -o "$1.gpg" 3<<<"$pass"
        echo "$1.gpg"
    else
        BACKUP_PASS="$pass" openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
            -pass env:BACKUP_PASS -out "$1.enc"
        echo "$1.enc"
    fi
}

do_run() {
    passphrase >/dev/null
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    local stamp staging out
    stamp="$(date +%Y%m%d_%H%M%S)"
    staging="$(mktemp -d)"
    trap 'rm -rf "$staging"' RETURN

    # Consistent copies of every SQLite database (safe while the app runs).
    mkdir -p "$staging/instance"
    "$PY" - "$ROOT" "$staging/instance" <<'PYEOF'
import glob, os, sqlite3, sys
root, dest = sys.argv[1], sys.argv[2]
for path in glob.glob(os.path.join(root, 'instance', '*.db')) + glob.glob(os.path.join(root, '*.db')):
    src = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
    dst = sqlite3.connect(os.path.join(dest, os.path.basename(path)))
    src.backup(dst)
    dst.close(); src.close()
PYEOF
    [ -d uploads ] && cp -a uploads "$staging/uploads"
    [ -f .env ] && cp -a .env "$staging/.env"

    out="$(tar -C "$staging" -czf - . | encrypt "$BACKUP_DIR/backup_$stamp.tar.gz")"
    chmod 600 "$out"
    echo "Encrypted backup: $out"

    local keep; keep="${BACKUP_KEEP:-$(env_get BACKUP_KEEP)}"; keep="${keep:-14}"
    ls -1t "$BACKUP_DIR"/backup_*.tar.gz.* 2>/dev/null | tail -n +$((keep + 1)) | xargs -r rm -f

    local remote; remote="${BACKUP_REMOTE:-$(env_get BACKUP_REMOTE)}"
    if [ -n "$remote" ]; then
        rsync -a "$out" "$remote" && echo "Copied off-site to $remote"
    fi
}

do_restore() {
    local file="${1:-}" dest="${2:-}"
    [ -f "$file" ] && [ -n "$dest" ] || usage
    if [ -e "$dest" ] && [ -n "$(ls -A "$dest" 2>/dev/null)" ]; then
        echo "Destination '$dest' is not empty. Choose a new folder (live data is never overwritten)."
        exit 1
    fi
    mkdir -p "$dest"
    local pass; pass="$(passphrase)"
    case "$file" in
        *.gpg) gpg --batch --quiet --pinentry-mode loopback --passphrase-fd 3 -d "$file" 3<<<"$pass" | tar -C "$dest" -xzf - ;;
        *.enc) BACKUP_PASS="$pass" openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass env:BACKUP_PASS -in "$file" | tar -C "$dest" -xzf - ;;
        *) echo "Unknown backup format: $file"; exit 1 ;;
    esac
    echo "Restored into $dest. Stop the app, then copy back what you need (instance/, uploads/, .env)."
}

schedule() {
    command -v crontab >/dev/null 2>&1 || { echo "crontab is not installed (apt install cron)."; exit 1; }
    local cur; cur="$(crontab -l 2>/dev/null || true)"
    case "$1" in
        disable)
            printf '%s\n' "$cur" | grep -vF "$MARKER" | crontab - ; echo "Scheduled backups disabled." ;;
        status)
            if printf '%s\n' "$cur" | grep -qF "$MARKER"; then
                echo "Scheduled backups: ENABLED"
                printf '%s\n' "$cur" | grep -F "$MARKER" | awk '{print "Schedule (cron): "$1" "$2" "$3" "$4" "$5}'
            else
                echo "Scheduled backups: disabled (enable with: ./backup.sh enable daily)"
            fi
            echo "Latest backups:"; ls -1t "$BACKUP_DIR"/backup_*.tar.gz.* 2>/dev/null | head -5 || true ;;
        *)
            local cron
            case "$1" in
                daily)  cron="43 3 * * *" ;;
                weekly) cron="43 3 * * 1" ;;
                *)
                    if [[ "$1" =~ ^[0-9*/,-]+[[:space:]]+[0-9*/,-]+[[:space:]]+[0-9*/,-]+[[:space:]]+[0-9*/,-]+[[:space:]]+[0-9*/,A-Za-z-]+$ ]]; then
                        cron="$1"
                    else
                        echo "Invalid frequency: '$1'"; exit 1
                    fi ;;
            esac
            passphrase >/dev/null
            mkdir -p "$ROOT/logs"
            { printf '%s\n' "$cur" | grep -vF "$MARKER" | sed '/^$/d'; echo "$cron cd '$ROOT' && ./backup.sh run >> '$ROOT/logs/backup.log' 2>&1 $MARKER"; } | crontab -
            echo "Scheduled backups enabled: $cron (log: logs/backup.log)" ;;
    esac
}

case "${1:-}" in
    run) do_run ;;
    restore) do_restore "${2:-}" "${3:-}" ;;
    enable) [ -n "${2:-}" ] || usage; schedule "$2" ;;
    disable) schedule disable ;;
    status) schedule status ;;
    *) usage ;;
esac
