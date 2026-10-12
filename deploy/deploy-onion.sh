#!/usr/bin/env bash
#
# deploy-onion.sh — installe depressedyoungmanblog en service onion sur un
# serveur Debian/Ubuntu, sans aucune exposition sur le clearnet.
#
# CE QUE FAIT CE SCRIPT
#   1. installe ce qui manque (python, tor, ufw, fail2ban...)
#   2. cree un utilisateur systeme dedie, sans shell ni mot de passe
#   3. installe l'application dans /opt, avec un venv isole
#   4. genere SECRET_KEY / ENCRYPTION_KEY / ENCRYPTION_SALT
#   5. cree le service onion Tor et affiche l'adresse .onion
#   6. cree le compte admin depressedyoungman avec un mot de passe aleatoire
#   7. installe une unite systemd durcie qui n'ecoute que sur 127.0.0.1
#   8. ferme le pare-feu en entree et verifie qu'aucun port n'est expose
#
# CE QU'IL NE FAIT PAS
#   Il ne rend pas anonyme la machine elle-meme. Votre fournisseur d'acces voit
#   que vous utilisez Tor (pas ce que vous y faites). Si ce seul fait pose
#   probleme, il faut un pont (bridge) — voir la section BRIDGES en fin de
#   fichier. Le script ne protege pas non plus contre un acces physique a la
#   machine : chiffrez le disque.
#
# USAGE
#   sudo bash deploy/deploy-onion.sh
#   sudo bash deploy/deploy-onion.sh --dry-run     # montre sans rien changer
#
set -Eeuo pipefail

# ---------------------------------------------------------------- reglages

APP_NAME="depressedyoungmanblog"
APP_USER="dymblog"                  # utilisateur systeme dedie, sans shell
APP_DIR="/opt/${APP_NAME}"
DATA_DIR="/var/lib/${APP_NAME}"     # base, uploads, quarantaine
VENV_DIR="${APP_DIR}/.venv"
BIND_ADDR="127.0.0.1"               # jamais 0.0.0.0 : voir VERIFICATIONS
# Port non privilegie, obligatoire : le service tourne en utilisateur ordinaire
# et l'unite systemd vide CapabilityBoundingSet. Sans CAP_NET_BIND_SERVICE, un
# port inferieur a 1024 donne « [Errno 13] Permission denied » au bind, et
# gunicorn boucle sur des redemarrages. Le port ne sort pas de la machine : tor
# publie le port 80 de l'adresse onion et le renvoie ici.
BIND_PORT="8877"
TOR_HS_DIR="/var/lib/tor/${APP_NAME}"
ADMIN_USERNAME="depressedyoungman"
ENV_FILE="/etc/${APP_NAME}.env"
UNIT_FILE="/etc/systemd/system/${APP_NAME}.service"
CREDENTIALS_FILE="/root/${APP_NAME}-credentials.txt"

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

# Mis a 1 par les verifications finales. Le script continue jusqu'au bout
# malgre tout — sinon le mot de passe admin genere serait perdu — mais il
# se termine sur un echec explicite et un code de sortie non nul.
HEALTH_FAIL=0
HEALTH_REASONS=()

# ------------------------------------------------------------------ sortie

C_OK=$'\e[38;5;110m'; C_WARN=$'\e[38;5;180m'; C_ERR=$'\e[38;5;167m'
C_DIM=$'\e[38;5;245m'; C_OFF=$'\e[0m'

step()  { printf '\n%s──%s %s\n' "$C_DIM" "$C_OFF" "$1"; }
ok()    { printf '   %s✓%s %s\n' "$C_OK" "$C_OFF" "$1"; }
warn()  { printf '   %s!%s %s\n' "$C_WARN" "$C_OFF" "$1"; }
die()   { printf '\n   %s✗ %s%s\n\n' "$C_ERR" "$1" "$C_OFF" >&2; exit 1; }
info()  { printf '   %s%s%s\n' "$C_DIM" "$1" "$C_OFF"; }

run() {
    if (( DRY_RUN )); then
        printf '   %s[dry-run]%s %s\n' "$C_DIM" "$C_OFF" "$*"
    else
        "$@"
    fi
}

trap 'die "Interrompu ligne $LINENO. Rien n'\''est laisse a moitie installe : relancez le script, il est idempotent."' ERR

# ------------------------------------------------------------- pre-requis

step "Verifications prealables"

[[ $EUID -eq 0 ]] || die "A lancer avec sudo."

command -v apt-get >/dev/null 2>&1 \
    || die "Ce script vise Debian/Ubuntu (apt). Sur une autre distribution, adaptez la section « Paquets »."

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${SRC_DIR}/wsgi.py" ]] \
    || die "Lancez le script depuis le depot : sudo bash deploy/deploy-onion.sh"
ok "Sources trouvees dans ${SRC_DIR}"

# La version de Python du serveur decide des paquets installables : une roue
# (wheel) manquante pour cette version force pip a compiler, et la compilation
# echoue sur les paquets a extension C trop anciens. Si l'installation des
# dependances casse, c'est presque toujours ici qu'il faut regarder.
PY_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
ok "Python ${PY_VERSION}"

if (( DRY_RUN )); then
    warn "Mode simulation : aucune modification ne sera ecrite."
fi

# L'horloge doit etre juste, Tor refuse de fonctionner avec une derive.
if command -v timedatectl >/dev/null 2>&1; then
    if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q 'yes'; then
        ok "Horloge synchronisee"
    else
        warn "Horloge non synchronisee — Tor peut refuser de se connecter."
        run systemctl enable --now systemd-timesyncd 2>/dev/null || true
    fi
fi

# ---------------------------------------------------------------- paquets

step "Paquets"

PACKAGES=(
    python3 python3-venv python3-pip
    tor
    ufw
    fail2ban
    ca-certificates
)
MISSING=()
for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        info "deja installe : ${pkg}"
    else
        MISSING+=("$pkg")
    fi
done

if (( ${#MISSING[@]} )); then
    info "a installer : ${MISSING[*]}"
    run apt-get update -qq
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${MISSING[@]}"
    ok "${#MISSING[@]} paquet(s) installe(s)"
else
    ok "Tout est deja present"
fi

# ------------------------------------------------------------- fail2ban

step "fail2ban"

# Debian active la prison sshd des l'installation du paquet, avec une action
# qui rejette par ICMP port unreachable — ce que le client traduit par
# « Connection refused ». Sans liste blanche, l'administrateur qui se trompe
# de mot de passe quelques fois se bannit lui-meme de sa propre machine, et le
# ping continue de repondre, ce qui rend le diagnostic penible.
#
# On met donc le reseau local en ignoreip. C'est un choix delibere : sur un
# service onion, le SSH n'a aucune raison d'etre joignable depuis Internet, et
# les tentatives distantes restent bannies normalement.
F2B_LOCAL="/etc/fail2ban/jail.local"
F2B_IGNORE="127.0.0.1/8 ::1"
F2B_IF="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
if [[ -n "$F2B_IF" ]]; then
    F2B_LAN="$(ip -4 route show dev "$F2B_IF" proto kernel scope link 2>/dev/null \
        | awk '{print $1}' \
        | grep -E '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' | tr '\n' ' ' || true)"
    [[ -n "$F2B_LAN" ]] && F2B_IGNORE="${F2B_IGNORE} ${F2B_LAN}"
fi

if [[ -f "$F2B_LOCAL" ]] && grep -q "ignoreip" "$F2B_LOCAL"; then
    ok "jail.local deja configure (conserve)"
else
    if (( DRY_RUN )); then
        info "[dry-run] ecriture de ${F2B_LOCAL} avec ignoreip = ${F2B_IGNORE}"
    else
        cat > "$F2B_LOCAL" <<EOF
# Genere par deploy-onion.sh. Modifiable : le script ne le reecrit pas s'il
# contient deja une ligne ignoreip.
[DEFAULT]
ignoreip = ${F2B_IGNORE}
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
EOF
        chmod 644 "$F2B_LOCAL"
    fi
    ok "Reseau local en liste blanche : ${F2B_IGNORE}"
fi
run systemctl enable --quiet fail2ban 2>/dev/null || true
run systemctl restart fail2ban 2>/dev/null || warn "fail2ban n'a pas redemarre — verifiez : journalctl -u fail2ban -n 20"

# Mises a jour de securite automatiques : une machine chez soi ne se met pas a
# jour toute seule, et un blog onion reste joignable des mois sans qu'on y pense.
if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades
    run dpkg-reconfigure -f noninteractive unattended-upgrades
    ok "Mises a jour de securite automatiques activees"
fi

# ------------------------------------------------------------ utilisateur

step "Utilisateur systeme"

if id "$APP_USER" >/dev/null 2>&1; then
    ok "L'utilisateur ${APP_USER} existe deja"
else
    # Sans shell et sans mot de passe : ce compte ne sert qu'a faire tourner
    # le processus, on ne s'y connecte jamais.
    run useradd --system --no-create-home --shell /usr/sbin/nologin "$APP_USER"
    ok "Utilisateur ${APP_USER} cree (nologin, sans mot de passe)"
fi

# ------------------------------------------------------------ application

step "Application"

run mkdir -p "$APP_DIR" "$DATA_DIR"

# rsync si dispo (plus propre), cp sinon.
if command -v rsync >/dev/null 2>&1; then
    run rsync -a --delete \
        --exclude '.git' --exclude '.venv' --exclude '__pycache__' \
        --exclude 'instance' --exclude 'uploads' --exclude '.env' \
        --exclude 'archive' --exclude 'docs' --exclude 'tools' \
        "${SRC_DIR}/" "${APP_DIR}/"
else
    run cp -r "${SRC_DIR}/app" "${SRC_DIR}/migrations" "${SRC_DIR}/wsgi.py" \
              "${SRC_DIR}/requirements.txt" "${SRC_DIR}/create_admin.py" "${APP_DIR}/"
fi
ok "Sources copiees dans ${APP_DIR}"

if [[ ! -d "$VENV_DIR" ]]; then
    run python3 -m venv "$VENV_DIR"
    ok "Environnement virtuel cree"
fi
run "${VENV_DIR}/bin/python" -m pip install --quiet --upgrade pip
run "${VENV_DIR}/bin/python" -m pip install --quiet -r "${APP_DIR}/requirements.txt"
run "${VENV_DIR}/bin/python" -m pip install --quiet gunicorn
ok "Dependances installees"

# Les donnees vivent hors de l'arborescence applicative : une reinstallation
# ne doit jamais pouvoir ecraser la base ou les pieces jointes.
run mkdir -p "${DATA_DIR}/instance" "${DATA_DIR}/uploads" "${DATA_DIR}/instance/quarantine"
run ln -sfn "${DATA_DIR}/instance" "${APP_DIR}/instance"
run ln -sfn "${DATA_DIR}/uploads"  "${APP_DIR}/uploads"
ok "Donnees isolees dans ${DATA_DIR}"

# ------------------------------------------------------------------ secrets

step "Secrets"

gen_secret() { "${VENV_DIR}/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))'; }

if [[ -f "$ENV_FILE" ]]; then
    ok "Secrets deja generes, conserves (${ENV_FILE})"
    warn "Ne les regenerez pas : les messages chiffres deviendraient illisibles."
else
    if (( DRY_RUN )); then
        info "[dry-run] generation de SECRET_KEY / ENCRYPTION_KEY / ENCRYPTION_SALT"
    else
        umask 077
        cat > "$ENV_FILE" <<EOF
# Genere par deploy-onion.sh le $(date -u +%Y-%m-%dT%H:%M:%SZ)
# NE JAMAIS partager ni versionner ce fichier.
# Changer ENCRYPTION_KEY ou ENCRYPTION_SALT rend illisibles tous les messages
# deja chiffres en base.

SECRET_KEY=$(gen_secret)
ENCRYPTION_KEY=$(gen_secret)
ENCRYPTION_SALT=$(gen_secret)

# 600000 iterations PBKDF2 : recommandation OWASP. Possible ici parce que la
# base est neuve — a ne jamais changer ensuite.
ENCRYPTION_ITERATIONS=600000

DATABASE_URL=sqlite:///${DATA_DIR}/instance/blog.db

# Tor Browser considere une origine .onion comme sure : le cookie Secure et le
# prefixe __Host- fonctionnent, et protegent si le site est un jour aussi servi
# en HTTPS.
SESSION_COOKIE_SECURE=true

# Le service ecoute derriere Tor sur la boucle locale. Sans ProxyFix,
# request.remote_addr vaut 127.0.0.1 pour tout le monde — ce qui est
# exactement ce qu'on veut ici : Tor ne transmet aucune adresse client, il n'y
# a rien a recuperer. On laisse donc TRUST_PROXY absent.

# Jamais de HSTS sur une adresse .onion : l'en-tete n'a pas de sens hors TLS et
# peut rendre le service inaccessible si vous changez de configuration.
FORCE_HSTS=false

# Les adresses IP sont retirees des journaux. Ne pas activer.
LOG_CLIENT_IP=false

MAX_UPLOAD_BYTES=10485760
MAX_CONTENT_LENGTH=12582912
EOF
        chmod 600 "$ENV_FILE"
        chown root:root "$ENV_FILE"
    fi
    ok "Secrets generes dans ${ENV_FILE} (chmod 600, root uniquement)"
fi

# --------------------------------------------------------- base de donnees

step "Base de donnees"

if (( ! DRY_RUN )); then
    # `source` plutot que `env $(xargs ...)` : le second casse des qu'une
    # valeur contient une espace ou un caractere special.
    ( set -a; . "$ENV_FILE"; set +a
      cd "$APP_DIR"
      FLASK_APP=wsgi.py "${VENV_DIR}/bin/python" -m flask db upgrade >/dev/null 2>&1 ) \
      || die "La migration a echoue. Verifiez ${ENV_FILE}."
fi
ok "Migrations appliquees"

# ------------------------------------------------------------ compte admin

step "Compte administrateur"

ADMIN_PASSWORD=""
if (( ! DRY_RUN )); then
    ADMIN_PASSWORD="$("${VENV_DIR}/bin/python" - <<'PY'
import secrets, string
# 24 caracteres d'un alphabet sans ambiguite visuelle (ni O/0 ni l/1/I) :
# ce mot de passe sera lu a l'ecran puis retape une seule fois.
alphabet = ''.join(c for c in string.ascii_letters + string.digits if c not in 'O0lI1')
print(''.join(secrets.choice(alphabet) for _ in range(24)))
PY
)"

    ( set -a; . "$ENV_FILE"; set +a
      cd "$APP_DIR"
      ADMIN_USERNAME="$ADMIN_USERNAME" ADMIN_PASSWORD="$ADMIN_PASSWORD" \
      "${VENV_DIR}/bin/python" - <<'PY'
import os, sys
from app import app, db, bcrypt
from app.models import User

username = os.environ['ADMIN_USERNAME']
password = os.environ['ADMIN_PASSWORD']

with app.app_context():
    db.create_all()
    user = User.query.filter_by(username=username).first()
    if user:
        print('EXISTS', file=sys.stderr)
    else:
        db.session.add(User(
            username=username,
            password=bcrypt.generate_password_hash(password).decode(),
            is_admin=True,
            # Tant que ce drapeau est pose, toute navigation est renvoyee vers
            # le changement de mot de passe. La consigne devient une contrainte.
            must_change_password=True,
        ))
        db.session.commit()
        print('CREATED', file=sys.stderr)
PY
    ) 2>/tmp/.dym_admin_status || die "Creation du compte admin impossible."

    if grep -q EXISTS /tmp/.dym_admin_status; then
        ADMIN_PASSWORD=""
        warn "Le compte ${ADMIN_USERNAME} existe deja : mot de passe inchange."
    else
        ok "Compte ${ADMIN_USERNAME} cree"
    fi
    rm -f /tmp/.dym_admin_status
else
    info "[dry-run] creation du compte ${ADMIN_USERNAME}"
fi

# ------------------------------------------------------------ permissions

step "Permissions"

run chown -R root:root "$APP_DIR"
run chown -R "${APP_USER}:${APP_USER}" "$DATA_DIR"
# Le code appartient a root et n'est pas modifiable par le service : une faille
# d'ecriture dans l'application ne peut pas reecrire l'application elle-meme.
run chmod -R go-w "$APP_DIR"
run chmod 700 "$DATA_DIR"
ok "Code en lecture seule pour le service, donnees en ${APP_USER}:${APP_USER}"

# ------------------------------------------------------------------- systemd

step "Service systemd"

if (( ! DRY_RUN )); then
    cat > "$UNIT_FILE" <<EOF
[Unit]
Description=${APP_NAME} (onion)
After=network.target tor.service
Wants=tor.service

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
# dymblog n'a pas de repertoire personnel (--no-create-home, volontaire). Sans
# HOME explicite, systemd le fixe a /home/dymblog d'apres /etc/passwd, et le
# serveur de controle de gunicorn echoue a y ecrire : « Control server error:
# [Errno 13] Permission denied: '/home/dymblog' ». Le pointer vers le seul
# chemin inscriptible du service suffit.
Environment=HOME=${DATA_DIR}

# -w 1 : le limiteur de debit de l'application vit en memoire du processus.
# Avec plusieurs workers, chacun aurait son compteur et les limites seraient
# multipliees d'autant. Un worker unique les rend exactes.
# --access-logfile /dev/null : aucun journal d'acces. Tor ne transmet pas
# d'adresse client, mais on n'ecrit meme pas les URL consultees.
ExecStart=${VENV_DIR}/bin/gunicorn \\
    --bind ${BIND_ADDR}:${BIND_PORT} \\
    --workers 1 \\
    --threads 4 \\
    --timeout 60 \\
    --access-logfile /dev/null \\
    --error-logfile - \\
    --log-level warning \\
    wsgi:application

Restart=on-failure
RestartSec=5

# --- Durcissement -----------------------------------------------------
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RemoveIPC=true
# Le service n'a besoin d'ecrire que dans ses donnees.
ReadWritePaths=${DATA_DIR}
# Aucune raison d'ouvrir une socket vers l'exterieur : l'application ne
# contacte aucun service tiers. AF_UNIX/AF_INET suffisent pour ecouter en local.
RestrictAddressFamilies=AF_UNIX AF_INET
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$UNIT_FILE"
fi
run systemctl daemon-reload
run systemctl enable --quiet "${APP_NAME}.service"
run systemctl restart "${APP_NAME}.service"
ok "Service installe et demarre (durci, un seul worker)"

# ----------------------------------------------------------------- tor

step "Service onion"

TORRC="/etc/tor/torrc"
HS_MARK="# --- ${APP_NAME} ---"

append_hs_block() {
    cp "$TORRC" "${TORRC}.bak.$(date +%s)"
    cat >> "$TORRC" <<EOF

${HS_MARK}
HiddenServiceDir ${TOR_HS_DIR}
HiddenServicePort 80 ${BIND_ADDR}:${BIND_PORT}
# Pas de HiddenServiceVersion : v3 est la seule version depuis Tor 0.4.6 et la
# directive a ete retiree — l'ecrire ferait refuser le fichier de configuration.
# Ne journalise que l'essentiel, sans adresses.
Log notice syslog
# Le relais ne sert pas de trafic pour les autres : moins d'exposition.
SocksPort 0
${HS_MARK} fin
EOF
}

if grep -qF "$HS_MARK" "$TORRC" 2>/dev/null; then
    if grep -qF "HiddenServicePort 80 ${BIND_ADDR}:${BIND_PORT}" "$TORRC"; then
        ok "Service onion deja declare dans ${TORRC}"
    else
        # Le port d'ecoute a change depuis la derniere installation. Sans cette
        # mise a jour, tor renverrait les visiteurs vers un port ou plus rien
        # n'ecoute : l'adresse onion repondrait « connexion refusee », alors que
        # tout le reste aurait l'air correct.
        warn "Le port d'ecoute a change — mise a jour du bloc dans ${TORRC}"
        if (( ! DRY_RUN )); then
            sed -i "\|^${HS_MARK}$|,\|^${HS_MARK} fin$|d" "$TORRC"
            append_hs_block
        fi
        ok "Bloc onion reecrit sur ${BIND_ADDR}:${BIND_PORT}"
    fi
else
    if (( ! DRY_RUN )); then
        append_hs_block
    fi
    ok "Service onion declare (sauvegarde de torrc conservee)"
fi

run systemctl enable --quiet tor
run systemctl restart tor

ONION_ADDR="(indisponible en simulation)"
if (( ! DRY_RUN )); then
    for _ in $(seq 1 30); do
        [[ -f "${TOR_HS_DIR}/hostname" ]] && break
        sleep 1
    done
    if [[ -f "${TOR_HS_DIR}/hostname" ]]; then
        ONION_ADDR="$(cat "${TOR_HS_DIR}/hostname")"
        ok "Adresse : ${ONION_ADDR}"
    else
        die "Tor n'a pas cree ${TOR_HS_DIR}/hostname. Voir : journalctl -u tor -n 50"
    fi
fi

# ------------------------------------------------------------- pare-feu

step "Pare-feu"

# Refuser toutes les entrees coupe la session SSH en cours. On autorise donc
# l'adresse du client AVANT d'activer le pare-feu.
#
# NE PAS SE FIER A $SSH_CONNECTION : sudo applique env_reset et les variables
# SSH_* n'y survivent pas. Comme ce script se lance toujours avec sudo, la
# variable etait systematiquement vide, aucune regle n'etait posee, et `ufw
# enable` fermait le port 22 sur l'administrateur lui-meme. On lit donc les
# connexions TCP etablies vers le port 22, ce qui ne depend d'aucune variable.
SSH_PEERS=""
if command -v ss >/dev/null 2>&1; then
    # Le nombre de colonnes de `ss` varie selon la version et les filtres ; la
    # derniere est toujours l'adresse distante. On retire le port et, en IPv6,
    # les crochets.
    SSH_PEERS="$(ss -tn state established '( sport = :22 )' 2>/dev/null \
        | awk 'NF > 2 {print $NF}' \
        | sed -e 's/:[0-9]\+$//' -e 's/^\[//' -e 's/\]$//' \
        | grep -E '^[0-9a-fA-F.:]+$' | sort -u || true)"
fi
# Filets de securite si `ss` manque ou si le script tourne autrement.
if [[ -z "$SSH_PEERS" && -n "${SSH_CONNECTION:-}" ]]; then
    SSH_PEERS="$(awk '{print $1}' <<<"$SSH_CONNECTION")"
fi
if [[ -z "$SSH_PEERS" && -n "${SSH_CLIENT:-}" ]]; then
    SSH_PEERS="$(awk '{print $1}' <<<"$SSH_CLIENT")"
fi

# Aucun client SSH connecte : soit la machine est administree au clavier, soit
# la detection a echoue. Dans le doute on ouvre le port 22 aux reseaux prives
# auxquels la machine appartient — jamais a Internet. Se verrouiller dehors
# d'une machine sans ecran coute bien plus cher que ce port ouvert sur le LAN.
LAN_SUBNETS=""
if [[ -z "$SSH_PEERS" ]]; then
    # Uniquement l'interface qui porte la route par defaut. Prendre toutes les
    # interfaces ferait apparaitre les ponts Docker (172.17.0.0/16 et voisins),
    # qui ne sont pas le reseau depuis lequel on administre la machine.
    DEFAULT_IF="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
    if [[ -n "$DEFAULT_IF" ]]; then
        LAN_SUBNETS="$(ip -4 route show dev "$DEFAULT_IF" proto kernel scope link 2>/dev/null \
            | awk '{print $1}' \
            | grep -E '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' | sort -u || true)"
    fi
fi

if (( ! DRY_RUN )); then
    ufw --force default deny incoming >/dev/null
    ufw --force default allow outgoing >/dev/null

    if [[ -n "$SSH_PEERS" ]]; then
        while read -r peer; do
            [[ -z "$peer" ]] && continue
            ufw allow from "$peer" to any port 22 proto tcp >/dev/null
            ok "SSH autorise depuis ${peer}"
        done <<<"$SSH_PEERS"
    elif [[ -n "$LAN_SUBNETS" ]]; then
        while read -r subnet; do
            [[ -z "$subnet" ]] && continue
            ufw allow from "$subnet" to any port 22 proto tcp >/dev/null
            warn "Aucun client SSH detecte : port 22 ouvert depuis ${subnet} (reseau local)"
        done <<<"$LAN_SUBNETS"
        info "  Pour restreindre ensuite : sudo ufw status numbered puis sudo ufw delete <n>"
    else
        warn "Aucun client SSH ni reseau prive detecte : aucune regle SSH posee."
        info "  Si vous administrez cette machine a distance, AVANT DE FERMER CETTE SESSION :"
        info "  sudo ufw allow from <votre-adresse> to any port 22 proto tcp"
    fi

    # Aucune autre regle d'entree : le service onion n'ouvre aucun port, c'est
    # Tor qui etablit les connexions sortantes.
    ufw --force enable >/dev/null

    # Dernier controle : une machine distante sans regle SSH est une machine
    # perdue. On le dit au lieu de le laisser decouvrir a la reconnexion.
    if ! ufw status | grep -q '22'; then
        warn "AUCUNE REGLE SSH ACTIVE. Acces distant impossible apres deconnexion."
        info "  Ouvrez le port maintenant : sudo ufw allow from 192.168.0.0/16 to any port 22 proto tcp"
    fi
fi
ok "Entrees refusees par defaut, aucun port publie"

# ------------------------------------------------------------ verifications

step "Verifications anti-fuite"

if (( ! DRY_RUN )); then
    sleep 2

    # 1. L'application ne doit ecouter QUE sur la boucle locale.
    if ss -ltn 2>/dev/null | grep -q "0.0.0.0:${BIND_PORT}\|\[::\]:${BIND_PORT}"; then
        die "L'application ecoute sur toutes les interfaces. Elle serait joignable hors de Tor."
    fi
    if ss -ltn 2>/dev/null | grep -q "${BIND_ADDR}:${BIND_PORT}"; then
        ok "Ecoute uniquement sur ${BIND_ADDR}:${BIND_PORT}"
    else
        HEALTH_FAIL=1
        HEALTH_REASONS+=("Rien n'ecoute sur ${BIND_ADDR}:${BIND_PORT} — le service ne demarre pas.")
        warn "Aucun processus n'ecoute sur ${BIND_PORT}"
        journalctl -u "${APP_NAME}" -n 15 --no-pager 2>/dev/null | sed 's/^/     /'
    fi

    # 2. Le site repond.
    if curl -sf -o /dev/null --max-time 10 "http://${BIND_ADDR}:${BIND_PORT}/"; then
        ok "L'application repond"
    else
        HEALTH_FAIL=1
        HEALTH_REASONS+=("L'application n'a pas repondu sur http://${BIND_ADDR}:${BIND_PORT}/")
        warn "L'application ne repond pas"
    fi

    # 3. Aucun domaine tiers dans la page servie. C'est la fuite la plus
    #    banale : une police, une icone ou un script distant revelerait
    #    l'adresse IP reelle du lecteur a un tiers, en contournant Tor.
    THIRD_PARTY="$(curl -s --max-time 10 "http://${BIND_ADDR}:${BIND_PORT}/" \
        | grep -oE '(src|href)="https?://[^"]+' | grep -v '\.onion' || true)"
    if [[ -n "$THIRD_PARTY" ]]; then
        warn "Ressources distantes trouvees dans la page — a corriger :"
        printf '%s\n' "$THIRD_PARTY" | sed 's/^/     /'
    else
        ok "Aucune ressource distante dans la page servie"
    fi

    # 3 bis. Le controle ci-dessus ne voit que la page d'accueil. Les pages
    #        d'administration et l'editeur demandent une session : impossible
    #        de les recuperer avec curl. On lit donc leur source. Seuls `src=`
    #        et `<link href=` comptent : ils declenchent une requete tout seuls.
    #        Un simple lien <a href="https://..."> n'en declenche aucune.
    TPL_REMOTE="$(grep -rhoE '(<link[^>]+href|src)="https?://[^"]+' "${APP_DIR}/app/templates/" 2>/dev/null \
        | grep -v '\.onion' || true)"
    if [[ -n "$TPL_REMOTE" ]]; then
        HEALTH_FAIL=1
        HEALTH_REASONS+=("Des gabarits chargent des ressources distantes — fuite d'adresse IP pour le lecteur.")
        warn "Ressources distantes dans les gabarits :"
        printf '%s\n' "$TPL_REMOTE" | sort -u | sed 's/^/     /'
    else
        ok "Aucune ressource distante dans les gabarits (pages authentifiees comprises)"
    fi

    # 4. Les en-tetes de securite sont bien la.
    HDRS="$(curl -sI --max-time 10 "http://${BIND_ADDR}:${BIND_PORT}/" || true)"
    for h in "Content-Security-Policy" "X-Frame-Options" "Referrer-Policy"; do
        grep -qi "^${h}:" <<<"$HDRS" && ok "En-tete ${h}" || warn "En-tete ${h} absent"
    done
    if grep -qi "^Strict-Transport-Security:" <<<"$HDRS"; then
        warn "HSTS present : a eviter sur une adresse .onion (FORCE_HSTS doit rester false)."
    fi

    # 5. Le fichier de secrets ne doit etre lisible que par root.
    PERMS="$(stat -c '%a %U' "$ENV_FILE")"
    [[ "$PERMS" == "600 root" ]] && ok "Secrets en ${PERMS}" || warn "Secrets en ${PERMS} — attendu 600 root"
fi

# ------------------------------------------------------------ identifiants

step "Identifiants"

if (( ! DRY_RUN )) && [[ -n "$ADMIN_PASSWORD" ]]; then
    umask 077
    cat > "$CREDENTIALS_FILE" <<EOF
${APP_NAME} — premiere connexion
Genere le $(date -u +%Y-%m-%dT%H:%M:%SZ)

  Adresse      http://${ONION_ADDR}
  Utilisateur  ${ADMIN_USERNAME}
  Mot de passe ${ADMIN_PASSWORD}

Le site vous obligera a le changer avant toute autre action : aucune page
n'est accessible tant que ce n'est pas fait. Supprimez ensuite ce fichier :
  shred -u ${CREDENTIALS_FILE}

Activez ensuite la double authentification depuis /totp/setup.
EOF
    chmod 600 "$CREDENTIALS_FILE"
    ok "Ecrits dans ${CREDENTIALS_FILE} (chmod 600)"
fi

# ------------------------------------------------------------------- bilan

printf '\n%s%s%s\n' "$C_DIM" "$(printf '─%.0s' {1..64})" "$C_OFF"
printf '\n  %s%s%s\n\n' "$C_OK" "Installe." "$C_OFF"

if (( ! DRY_RUN )); then
    printf '  Adresse       http://%s\n' "$ONION_ADDR"
    if [[ -n "$ADMIN_PASSWORD" ]]; then
        printf '  Utilisateur   %s\n' "$ADMIN_USERNAME"
        printf '  Mot de passe  %s%s%s\n' "$C_WARN" "$ADMIN_PASSWORD" "$C_OFF"
        printf '\n  %sLe site vous obligera a le changer des la connexion.%s\n' "$C_WARN" "$C_OFF"
        printf '  %sEnsuite : shred -u %s%s\n' "$C_DIM" "$CREDENTIALS_FILE" "$C_OFF"
    fi
fi

cat <<EOF

  ${C_DIM}Commandes utiles${C_OFF}
    systemctl status ${APP_NAME}
    journalctl -u ${APP_NAME} -f
    systemctl restart ${APP_NAME}
    cat ${TOR_HS_DIR}/hostname

  ${C_DIM}A faire ensuite, dans cet ordre${C_OFF}
    1. Se connecter depuis Tor Browser. Le changement de mot de passe est
       impose avant tout le reste.
    2. Activer la 2FA (/totp/setup).
    3. shred -u ${CREDENTIALS_FILE}
    4. Sauvegarder ${TOR_HS_DIR} : c'est la cle privee de votre adresse.
       Sans elle, l'adresse .onion est perdue definitivement.
       ${C_DIM}sudo tar czf - ${TOR_HS_DIR} | age -p > onion-key.tar.gz.age${C_OFF}

EOF

cat <<'EOF'
  ── Ce qui reste hors de portee de ce script ──────────────────────

  CHIFFREMENT DU DISQUE
    Le script protege le service, pas la machine. Sans chiffrement integral
    (LUKS), quiconque a un acces physique lit la base, les cles et la
    quarantaine. A faire a l'installation du systeme.

  SWAP
    Une cle de chiffrement peut se retrouver ecrite en clair dans la swap.
      sudo swapoff -a          # puis retirer la ligne swap de /etc/fstab
    ou chiffrer la swap avec une cle aleatoire au demarrage.

  VOTRE FOURNISSEUR D'ACCES
    Il voit que la machine parle a Tor, pas ce qu'elle y fait. Si ce seul fait
    est un probleme, passez par des ponts obfs4. Recuperez des lignes de ponts
    sur https://bridges.torproject.org (ou par courriel a bridges@torproject.org,
    corps « get transport obfs4 »), mettez-les dans un fichier, puis :
      sudo bash deploy/harden-tor.sh --bridges /root/ponts.txt

  PROTECTION DES GARDES (vanguards)
    Un service onion durable est expose aux attaques de decouverte de garde.
    Depuis Tor 0.4.7 le coeur de tor fait deja tourner « vanguards-lite » ;
    l'addon complet ajoute la couche 3, bandguards et rendguard, et se
    justifie si le service doit vivre longtemps :
      sudo bash deploy/harden-tor.sh --vanguards

  SAUVEGARDES
    ${DATA_DIR} (base + pieces jointes) et le repertoire de service onion.
    Chiffrez-les avant de les sortir de la machine.

  CE QUE LE SITE NE PROTEGE PAS
    Les messages sont chiffres au repos, avec une cle qui vit sur ce serveur.
    Cela protege du vol du fichier de base seul — pas d'un acces au serveur.
    Ne promettez pas plus que cela a vos lecteurs.

EOF

# Une adresse onion affichee au-dessus d'un service mort est le pire des
# resultats : tout a l'air installe, et le site repond « connexion refusee ».
if (( HEALTH_FAIL )); then
    printf "\n%s  ✗ L'INSTALLATION N'EST PAS FONCTIONNELLE%s\n\n" "$C_ERR" "$C_OFF"
    for reason in "${HEALTH_REASONS[@]}"; do
        printf '     %s\n' "$reason"
    done
    cat <<EOF

     Le service et l'adresse onion existent, mais le site ne repond pas.
     Diagnostic :
       systemctl status ${APP_NAME} --no-pager -l
       journalctl -u ${APP_NAME} -n 60 --no-pager
       ss -ltnp | grep ${BIND_PORT}

     Les identifiants admin restent valables : ${CREDENTIALS_FILE}
     Corrigez, puis relancez ce script — il est idempotent.

EOF
    exit 1
fi
