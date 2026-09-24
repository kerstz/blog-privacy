#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Optional automatic updates, at the frequency YOU choose (cron based).
#
#   ./auto-update.sh enable daily                 every day at 04:17
#   ./auto-update.sh enable weekly                every Monday at 04:17
#   ./auto-update.sh enable monthly               the 1st of each month at 04:17
#   ./auto-update.sh enable "30 3 * * 2,5"        any cron expression
#   ./auto-update.sh disable                      turn automatic updates off
#   ./auto-update.sh status                       show the current schedule
#
# Each run calls `./update.sh --auto`: nothing happens if there is no new
# version; otherwise it backs up the data, updates, checks the app starts
# (rolls back if not) and restarts it with UPDATE_RESTART_CMD from .env, e.g.
#   UPDATE_RESTART_CMD=sudo systemctl restart blog
# (the cron user then needs a sudoers rule for exactly that command, see
# SECURITY.md). Output goes to logs/update.log. If the Telegram bot is
# configured, the admin gets a message after each update or failure.
#
# Automatic updates are OFF by default: you decide.
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"
MARKER="# blog-privacy auto-update ($ROOT)"

usage() { sed -n '3,22p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

command -v crontab >/dev/null 2>&1 || { echo "crontab is not installed (apt install cron)."; exit 1; }

current_crontab() { crontab -l 2>/dev/null || true; }

without_ours() { current_crontab | grep -vF "$MARKER" || true; }

case "${1:-}" in
    enable)
        freq="${2:-}"
        case "$freq" in
            daily)   cron="17 4 * * *" ;;
            weekly)  cron="17 4 * * 1" ;;
            monthly) cron="17 4 1 * *" ;;
            "")      usage ;;
            *)
                # custom cron expression: exactly 5 fields of cron characters
                if [[ "$freq" =~ ^[0-9*/,-]+[[:space:]]+[0-9*/,-]+[[:space:]]+[0-9*/,-]+[[:space:]]+[0-9*/,-]+[[:space:]]+[0-9*/,A-Za-z-]+$ ]]; then
                    cron="$freq"
                else
                    echo "Invalid frequency: '$freq' (use daily, weekly, monthly or a 5-field cron expression)."
                    exit 1
                fi
                ;;
        esac
        chmod +x "$ROOT/update.sh"
        mkdir -p "$ROOT/logs"
        line="$cron cd '$ROOT' && ./update.sh --auto >> '$ROOT/logs/update.log' 2>&1 $MARKER"
        { without_ours; echo "$line"; } | crontab -
        echo "Automatic updates enabled: $cron"
        echo "Log: $ROOT/logs/update.log"
        if ! grep -qE '^[[:space:]]*UPDATE_RESTART_CMD=' "$ROOT/.env" 2>/dev/null; then
            echo "Tip: set UPDATE_RESTART_CMD in .env (e.g. 'sudo systemctl restart blog') so the app restarts after an update."
        fi
        ;;
    disable)
        without_ours | crontab -
        echo "Automatic updates disabled."
        ;;
    status)
        if current_crontab | grep -qF "$MARKER"; then
            echo "Automatic updates: ENABLED"
            current_crontab | grep -F "$MARKER" | awk '{print "Schedule (cron): "$1" "$2" "$3" "$4" "$5}'
            [ -f "$ROOT/logs/update.log" ] && { echo "Last log lines:"; tail -n 5 "$ROOT/logs/update.log"; }
        else
            echo "Automatic updates: disabled (enable with: ./auto-update.sh enable weekly)"
        fi
        ;;
    *) usage ;;
esac
