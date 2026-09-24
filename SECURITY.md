# Security

🇬🇧 English · [🇫🇷 Français](SECURITY.fr.md)

## Privacy & hardening release — September 2026 (2)

Follow-up to the security update below. **Update with `./update.sh`.**

### Privacy
- **No more third-party requests**: Google Fonts replaced by self-hosted fonts
  (every visitor's IP was sent to Google on every page); Bootstrap / Font
  Awesome CDN links removed; the Trocador donation iframe is now a plain link;
  CKEditor (loaded from `cdn.ckeditor.com`) removed.
- **External images are never loaded** (comments and posts): they are shown as
  links, so readers' IPs are not leaked to other sites. CSP `img-src 'self' data:`.
- **Tor**: optional `ONION_ADDRESS` adds an `Onion-Location` header; onion
  service config in `deploy/` (goes through the reverse proxy so Tor clients
  cannot spoof `X-Forwarded-For`).

### No JavaScript
- Every inline script and `onclick` handler removed (chat auto-scroll, delete
  confirmations, comment filter, admin menu, donation "copy" button, editor).
  Replacements use HTML/CSS only (`<details>` confirmations, `column-reverse`
  scrolling, server-side filtering, `user-select: all`).
- CSP is now `script-src 'none'`: even if an XSS bug appeared, no script could run.
- Flask-CKEditor removed: it also served CKEditor 4.14 files (known CVEs) at `/ckeditor/static`.
- UI demo pages (with scripts) moved from `app/static/` to `docs/` (no longer served).

### Security fixes
- **2FA codes could be rejected on servers not running in UTC** (naive
  datetime read as local time): fixed, codes are checked against Unix time.
- **Delete post button always failed** (missing CSRF token): fixed.
- **Rate limits and 2FA replay protection are now persistent** (SQLite,
  `instance/security_state.db`): they survive restarts and are shared by all
  worker processes.
- `gunicorn` pinned (production server).

### Operations
- `./auto-update.sh enable daily|weekly|monthly|"<cron>"`: **optional**
  automatic updates at the frequency you choose (off by default).
- `update.sh`: lock (no concurrent runs), "nothing new" fast path, health check
  + test suite, **automatic rollback** of code and dependencies on failure,
  optional restart (`UPDATE_RESTART_CMD`) and Telegram notification.
- `./backup.sh`: encrypted backups (gpg AES-256) of databases, uploads and
  `.env`, scheduling, retention, optional off-site copy, safe restore.
- GitHub Actions: tests + `pip-audit` on every push, pull request and every
  Monday; a check that templates contain no JavaScript / third-party resource.
  Dependabot for pip and GitHub Actions.
- `deploy/`: sandboxed systemd unit, Caddy and nginx configs without access
  logs, Tor onion service.

### Code
- `routes.py` (3,600 lines) split into `routes.py`, `services.py`,
  `telegram_bot.py` and `mobile_api.py`.
- Unused templates removed (they referenced routes that did not exist).
- Everything is in English (code, comments, UI); French documentation in `*.fr.md`.
- Default badges renamed to English (existing badges are renamed in place when
  an admin opens `/init_badges`; nobody loses or re-earns a badge).
- The editor help page now documents only the BBCode tags that exist; `[list=1]`
  and `[center]`/`[left]`/`[right]`/`[justify]` were added.

### Upgrade notes
- Posts written with the old editor (HTML) are still displayed (sanitized).
- External images in existing posts/comments now appear as links.
- If you run behind a proxy, re-read `deploy/` (Tor must go through the proxy).

## ⚠️ Security update — September 2026 (1)

**This release is a security update. Everyone running this blog should update now**
(`./update.sh`, see below). It fixes critical vulnerabilities in the code and
upgrades every dependency past its published CVEs.

### Critical / high fixes in the application code

| # | Issue | Impact before the fix | Fix |
|---|-------|-----------------------|-----|
| 1 | **Private chat readable by every user** — `/chat` listed *all* messages of *all* users | Any registered account could read every private conversation with the admin | `/chat` now only shows the current user's own conversation |
| 2 | **Unauthenticated SocketIO handler** (`app/chat.py`) trusting client-supplied `sender_id` | Anyone, without an account, could forge messages as any user | Handler removed; sockets require login; sender is always the logged-in user |
| 3 | **Real-time events broadcast to every socket** (chat content, usernames, notifications) | Any socket client received other users' private data | Events go to a private per-user room only; no content is sent |
| 4 | **Stored XSS in comments / replies** — BBCode parser did not escape HTML, replies were stored raw, rendered with `|safe` | Account takeover (including admins) by posting a comment | Input escaped before BBCode, output sanitized with `nh3` allow-list (`comment_html` filter) |
| 5 | **Stored XSS in chat** (`|safe` on messages) | A user could run script in the admin's browser | Messages are auto-escaped |
| 6 | **XSS in admin "Manage users"** — usernames injected into `onclick` JS | Username `x');…//` ran script in the admin panel | `|tojson` in JS context + strict username charset at registration |
| 7 | **Uploaded files public & guessable** (`/uploads/<name>`, predictable names, user filename kept, files could overwrite each other) | Anyone could download private chat attachments | Random names, access control (sender / receiver / admin only), forced download for non-images, sandbox CSP |
| 8 | **EXIF/GPS not fully removed** from user uploads (only GPS removed, camera data kept) | Location / device leak | All metadata removed (re-encode to WebP, orientation preserved) |
| 9 | **2FA brute-force** (unlimited attempts on `/login/totp`) and **code replay** | 2FA could be brute-forced | 5 attempts / 5 min, 5-minute pending window, a code can only be used once |
| 10 | **Mobile admin API bypassed 2FA** and had no brute-force protection | Password alone gave full admin API access | `X-TOTP-Code` header required for 2FA accounts, lockout after 10 failures |
| 11 | **Drafts publicly visible** (home page, post list, direct URL) and Telegram drafts **auto-published** | Unpublished content leaked | Drafts visible to admins only; scheduler publishes only explicitly scheduled posts |
| 12 | **Chat messages from users stored in plaintext** (flagged as encrypted); encryption silently fell back to plaintext on error; some ciphertexts were never decrypted (base64 alphabet bug) | Messages readable in the DB | Every message encrypted with Fernet; no plaintext fallback; decrypt bug fixed |
| 13 | **Telegram admin PIN brute-force** (unlimited, non constant-time compare) | Bot takeover if the Telegram account was accessed | Constant-time compare, 5 tries / 15 min, audit log |
| 14 | **Open redirect** via `Referer` in the rate limiter | Phishing | Same-host redirects only |
| 15 | **Forged donations** (anyone could POST any amount, incl. `inf`) shown as "top donor" | Spoofing | Admin-only, validated amount |
| 16 | **Session fixation / weak sessions** | — | Session cleared on login/logout, `__Host-` cookie in HTTPS, hardened remember-me cookie, CSRF token expiry |
| 17 | Weak `SECRET_KEY` / `ENCRYPTION_KEY` example values accepted | Forgeable sessions / decryptable messages | App refuses to start with example or short keys |

Other hardening: login rate limit per account (credential stuffing) + dummy
bcrypt for unknown users (no username enumeration by timing), password
12–72 characters, `svg`/`xml` uploads refused, `'unsafe-eval'` and `ws:`
wildcard removed from the CSP, HSTS in HTTPS, `Cache-Control: no-store` on
logged-in pages, COOP/CORP headers, `javascript:` URLs refused in banners,
last admin can no longer be demoted/deleted, socket message size limit,
bounded in-memory rate-limit store, per-request outbound Telegram calls
removed (latency/DoS), unused third-party CDN scripts removed from the admin
dashboard (Bootstrap 4.5.2 CVE-2024-6531, IP leak).

### Functional bugs fixed on the way

- Deleting a user with posts/messages crashed (500) — now handled (private data erased, posts reassigned, comments anonymized).
- "Create page" crashed (missing slug) — slug generated automatically; static pages are now viewable at `/page/<slug>`.
- *Manage pages* / *Manage banners* crashed (500) as soon as one page/banner existed (routes `edit_page`, `delete_page`, `edit_banner`, `delete_banner` did not exist).
- Edit page form had no CSRF token (always rejected).
- Contact form crashed (`email-validator` missing from requirements).
- Deleting a comment with replies broke the thread (now soft-deleted).
- Post excerpts displayed raw HTML tags.
- The donation iframe was blocked by the CSP.
- `create_admin.py` could not run (imported a non-existent `create_app`).
- `python wsgi.py` did not start anything.

### Dependency CVEs fixed (all pins bumped)

| Package | Old | New | CVEs |
|---------|-----|-----|------|
| cryptography | 45.0.7 | 50.0.1 | CVE-2026-26007, CVE-2026-34073, CVE-2026-39892, CVE-2026-69247/69248/69249, GHSA-537c-gmf6-5ccf (bundled OpenSSL) |
| Flask | 3.1.0 | 3.1.3 | CVE-2025-47278 (fallback key used to sign), CVE-2026-27205 (missing `Vary: Cookie`) |
| Werkzeug | 3.1.3 | 3.1.8 | CVE-2025-66221, CVE-2026-21860, CVE-2026-27199 |
| Jinja2 | 3.1.5 | 3.1.6 | CVE-2025-27516 (sandbox escape) |
| python-socketio | 5.12.1 | 5.17.0 | CVE-2025-61765 (pickle RCE), CVE-2026-48804 (memory DoS) |
| python-engineio | 4.11.2 | 4.14.0 | CVE-2026-48802, CVE-2026-48809 (DoS) |
| urllib3 | 2.3.0 | 2.8.0 | CVE-2025-50181, CVE-2025-50182, CVE-2025-66418, CVE-2025-66471, CVE-2026-21441, CVE-2026-44431 |
| requests | 2.32.3 | 2.34.2 | CVE-2024-47081, CVE-2026-25645 |
| h11 | 0.14.0 | 0.16.0 | CVE-2025-43859 (request smuggling) |
| idna | 3.10 | 3.20 | CVE-2026-45409 (DoS) |
| Mako | 1.3.8 | 1.4.3 | CVE-2026-44307 |
| click | 8.1.8 | 8.5.0 | CVE-2026-7246 |
| ecdsa | 0.19.0 | *removed* | CVE-2024-23342 (no fix upstream), CVE-2026-33936 — was unused |
| btcpay | 1.0.3 | *removed* | unused, pulled `ecdsa` |

New dependencies: `nh3` (HTML sanitizer), `email-validator` (was missing).
`pip-audit -r requirements.txt` → **No known vulnerabilities found** (2026-09-24).

### Upgrade notes

- Everybody is logged out once (the session cookie is renamed in HTTPS mode).
- Existing users keep their username/password; the new username/password rules apply to new registrations.
- Mobile API: accounts with 2FA must send the current code in the `X-TOTP-Code` header.
- Chat messages written before this update by users were stored in plaintext; they remain readable, new ones are encrypted.
- Old comments that contained HTML are still displayed, but sanitized.
- Unpublished posts that were never explicitly scheduled are no longer auto-published.

## Keep it up to date — regularly

New vulnerabilities are published every week. A site that was secure last
month can be vulnerable today. **Update at least once a month, and
immediately when a security release is announced**, or let it happen
automatically:

```bash
./update.sh                          # update now
./auto-update.sh enable weekly       # daily | weekly | monthly | "<cron expression>"
./auto-update.sh status
./auto-update.sh disable
```

`update.sh` backs up your database and uploads to `backups/`, pulls the code
(fast-forward only, it refuses to overwrite local changes), upgrades the
pinned dependencies, applies database migrations, checks the app still starts
(and runs the tests when pytest is installed) and **rolls back** code and
dependencies if anything fails. It never modifies `.env`, the database content
or `uploads/`.

For unattended updates set `UPDATE_RESTART_CMD` in `.env`, e.g.
`UPDATE_RESTART_CMD=sudo systemctl restart blog`, and allow exactly that
command for the user that owns the cron job:

```
# /etc/sudoers.d/blog  (edit with: sudo visudo -f /etc/sudoers.d/blog)
blog ALL=(root) NOPASSWD: /usr/bin/systemctl restart blog
```

Logs go to `logs/update.log`; with the Telegram bot configured, the admin is
notified after each update, failure or rollback.

Check for new CVEs at any time without changing anything:

```bash
pip install pip-audit && pip-audit -r requirements.txt
```

Run the security regression tests:

```bash
pip install -r requirements-dev.txt && pytest -q tests/
```

## Backups

```bash
./backup.sh run                     # encrypted: databases + uploads + .env
./backup.sh enable daily            # daily | weekly | "<cron expression>"
./backup.sh restore <file> <dir>    # decrypt into a NEW folder
```

`BACKUP_PASSPHRASE` (in `.env`) is required: keep a copy outside the server.
`BACKUP_KEEP` sets the retention (default 14), `BACKUP_REMOTE` an optional
rsync target for an off-site copy.

## Production checklist

- `SESSION_COOKIE_SECURE=true` and serve **only over HTTPS** (enables HSTS + `__Host-` cookie).
- Strong random `SECRET_KEY`, `ENCRYPTION_KEY`, `ENCRYPTION_SALT` (never the example values). **Back up** `ENCRYPTION_KEY`/`ENCRYPTION_SALT` (`./backup.sh` includes `.env`).
- Behind Caddy/nginx set `TRUSTED_PROXY_COUNT=1`, otherwise rate limiting sees only the proxy IP. Route Tor through the proxy too (see `deploy/torrc.example`).
- Run with the provided systemd unit (`deploy/blog.service`): dedicated user, sandboxing, one gunicorn worker with threads (the Telegram poller and the SSE stream live in the process).
- Enable 2FA on every admin account; set `TELEGRAM_ADMIN_USER_ID` and `TELEGRAM_ADMIN_PIN` if you use the bot.
- Enable scheduled encrypted backups and, ideally, automatic updates.
- Never run with Flask debug mode.

## Known limitations

- `style-src 'unsafe-inline'` is still needed (inline `<style>` blocks and `style` attributes in templates). Scripts are fully blocked (`script-src 'none'`).
- The in-process Telegram poller means one gunicorn worker (use threads to scale).
- `[img]` for images hosted on the blog only; there is no image library UI yet.

## Reporting a vulnerability

Please open a private security advisory on GitHub rather than a public issue.
