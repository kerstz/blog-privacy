# Deploying as an onion service

## Getting the code onto the server

Do not `scp -r` the whole directory: it would send `.venv` (a hundred megabytes
of binaries built for *your* machine), the git history, the local database, and
`.env` with your development secrets.

```bash
bash deploy/package.sh                 # builds a clean archive
bash deploy/package.sh 192.168.1.42    # ... and prints the scp commands
```

The archive holds the code and nothing else — the script refuses to finish if a
`.env`, a database or a `.git` slipped in. The server generates its own secrets
and its own database.

## Running it

```bash
sudo bash deploy/deploy-onion.sh --dry-run   # prints every action, changes nothing
sudo bash deploy/deploy-onion.sh
```

Debian/Ubuntu. The script is idempotent — run it again to update the code
without touching the database or the onion address.

## What it sets up

| | |
|---|---|
| Packages | python3, tor, ufw, fail2ban, unattended-upgrades — only what is missing |
| Account | `dymblog`, system user, no shell, no password |
| Code | `/opt/depressedyoungmanblog`, owned by root, not writable by the service |
| Data | `/var/lib/depressedyoungmanblog`, the only writable path |
| Secrets | `/etc/depressedyoungmanblog.env`, chmod 600, root only |
| Service | systemd, one gunicorn worker, bound to `127.0.0.1` only |
| Onion | `/var/lib/tor/depressedyoungmanblog` |
| Firewall | all inbound denied; your SSH source is allowed automatically if you are on SSH |

The admin account `depressedyoungman` is created with a 24-character random
password, printed once and written to `/root/depressedyoungmanblog-credentials.txt`.
**Change it at first login, then `shred -u` that file.**

## The leak checks it runs

1. The app listens on `127.0.0.1` and nowhere else — anything on `0.0.0.0` would
   be reachable outside Tor, and the script refuses to finish.
2. The served page contains no remote `src`/`href`. A single remote font or icon
   would hand a reader's real IP to a third party, straight past Tor.
3. `Content-Security-Policy`, `X-Frame-Options` and `Referrer-Policy` are present.
4. HSTS is **absent** — it means nothing on `.onion` and can lock you out.
5. The secrets file is `600 root`.

## Why one gunicorn worker

The rate limiter lives in process memory. With four workers each would keep its
own counter and every published limit would be four times looser than it says.

## What it does not do

**Disk encryption.** The script protects the service, not the machine. Without
LUKS, anyone with physical access reads the database, the keys and the
quarantine. Do this when you install the OS.

**Swap.** An encryption key can end up written to swap in the clear.
`swapoff -a`, remove the swap line from `/etc/fstab`, or encrypt it with a
random key at boot.

**Your ISP.** They see the machine talking to Tor, not what it does there. If
that alone is a problem, use obfs4 bridges — see *Hardening Tor further* below.

**Guard discovery.** A long-lived onion service is exposed to guard discovery
attacks. [vanguards](https://github.com/mikeperry-tor/vanguards) is the answer
if the service is meant to last — same section.

## Hardening Tor further

`deploy/deploy-onion.sh` leaves two things alone because both are choices, not
defaults. `deploy/harden-tor.sh` does them, separately and idempotently.

```bash
sudo bash deploy/harden-tor.sh --status
sudo bash deploy/harden-tor.sh --bridges /root/bridges.txt   # obfs4 bridges
sudo bash deploy/harden-tor.sh --no-bridges                  # roll them back
sudo bash deploy/harden-tor.sh --vanguards                   # guard protection
```

**Bridges** hide from your ISP that the machine speaks Tor at all. Get lines
from <https://bridges.torproject.org>, or email `bridges@torproject.org` with
`get transport obfs4` in the body, one per line in a file. The script validates
every line, runs `tor --verify-config` before restarting anything, and if Tor
does not reach *Bootstrapped 100%* within the timeout it **restores the previous
torrc and restarts** — a bad bridge line takes the onion service offline, so the
rollback is the point. Use two or three bridges from different operators.

**vanguards** defends against guard discovery. Tor ≥ 0.4.7 already runs
vanguards-lite in core; the addon adds layer-3 guards, bandguards and rendguard,
and is worth it for a service meant to last. It is installed under a dedicated
`vanguards` system user, talks to Tor over a unix control socket (nothing new
listens on the network, not even on localhost), and runs under a hardened
systemd unit. Pin a reviewed version rather than tracking the default branch:

```bash
VANGUARDS_REF=<tag> sudo -E bash deploy/harden-tor.sh --vanguards
git -C /opt/vanguards verify-tag <tag>
```

## Back up the onion key

`/var/lib/tor/depressedyoungmanblog` **is** your address. Lose it and the
address is gone for good — there is no recovery.

```bash
sudo tar czf - /var/lib/tor/depressedyoungmanblog | age -p > onion-key.tar.gz.age
```

Back up `/var/lib/depressedyoungmanblog` too — that is the database and every
attachment. Encrypt both before they leave the machine.

## Day to day

```bash
systemctl status depressedyoungmanblog
journalctl -u depressedyoungmanblog -f
cat /var/lib/tor/depressedyoungmanblog/hostname
```
