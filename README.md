# depressedyoungmanblog

A personal blog that keeps its readers anonymous. Flask, SQLite, no JavaScript
required, no third-party requests, built to run as a Tor onion service.

## What it does

- **Blog** — posts with a rich editor, drafts, scheduled publishing, revisions
- **Comments** — nested, BBCode, parsed server-side so they work without JavaScript
- **Encrypted chat** with the site owner — Fernet at rest, real-time over WebSocket
- **Bilingual** — every fixed text in English and French, switchable, and editable
  from the admin panel without touching code
- **Moderation** — flag an image and it is fingerprinted, blocked for good, and its
  sender banned; re-encoded copies are caught too
- **2FA** — TOTP, per account
- **Gamification** — XP, levels, badges

## What it deliberately does not do

- **No third-party requests.** No CDN, no web fonts, no analytics. A reader's IP
  address never reaches anyone but you. The type falls back to system faces on
  purpose.
- **No IP addresses in the logs.** They are scrubbed before anything is written.
  The rate limiter keys on a salted hash that is regenerated at every restart.
- **No tracking of any kind.** No view counters tied to a person, no cookies
  beyond the session.

## Honest limits

Messages are **encrypted at rest**, not end to end. The key lives on the server
next to the database. That protects against the theft of `blog.db` alone — not
against someone with access to the server, and not against a legal demand. Say
"encrypted at rest" to your readers, not "encrypted".

## Running it locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env          # then fill in the three required secrets
python -c "import secrets; print(secrets.token_urlsafe(48))"   # ×3

flask db upgrade
python create_admin.py        # first time only
python wsgi.py                # http://127.0.0.1:5000
```

For development, `SESSION_COOKIE_SECURE=false` and `TEMPLATE_AUTO_RELOAD=true`
in your `.env` save a lot of restarts.

## Deploying it as an onion service

```bash
bash deploy/package.sh 192.168.1.42           # clean archive + the scp commands
# then, on the server:
sudo bash deploy/deploy-onion.sh --dry-run    # see what it will do
sudo bash deploy/deploy-onion.sh
```

The script installs what is missing, generates the secrets, creates the onion
service, hardens the systemd unit, closes the firewall, and checks that nothing
leaks to the clearnet. See [deploy/README.md](deploy/README.md) for what it
covers and what it leaves to you.

## Layout

```
app/
  routes.py        all routes (web, mobile admin API, SSE)
  models.py        16 models
  site_text.py     bilingual copy, admin-editable
  image_safety.py  perceptual hashing + upload block list
  encryption.py    Fernet message encryption
  utils.py         BBCode, image pipeline, roles, rate limiting
deploy/            onion deployment
archive/telegram/  removed Telegram bridge, kept read-only
docs/ANONYMAT.md   privacy audit: what was found, fixed, and still open
```

## Licence

See [LICENSE](LICENSE).
