#!/usr/bin/env bash
#
# harden-tor.sh — les deux durcissements que deploy-onion.sh laisse de cote.
#
#   --bridges FICHIER   fait passer le tor de cette machine par des ponts
#                       obfs4. Le fournisseur d'acces ne voit plus « cette
#                       machine parle a Tor », seulement un flux chiffre sans
#                       signature reconnaissable. Cout : latence en plus, et
#                       une dependance a des ponts qui peuvent disparaitre.
#
#   --vanguards         installe l'addon vanguards, qui defend le service
#                       onion contre la decouverte de garde. Depuis Tor 0.4.7
#                       le coeur de tor fait deja tourner « vanguards-lite »
#                       (gardes de couche 2 a rotation lente). L'addon ajoute
#                       la couche 3, bandguards (canal auxiliaire par volume)
#                       et rendguard. Utile pour un service destine a durer.
#
# LES DEUX SONT INDEPENDANTS. Chacun peut etre lance seul, plusieurs fois : le
# script est idempotent. Les ponts se retirent avec --no-bridges.
#
# PRUDENCE
#   --bridges reecrit /etc/tor/torrc et redemarre tor. Pendant le redemarrage,
#   le service onion est injoignable. Si tor n'atteint pas « Bootstrapped 100% »
#   dans le delai imparti, le script restaure la sauvegarde de torrc et
#   redemarre : l'adresse .onion revient. Gardez malgre tout la session SSH
#   ouverte jusqu'a la fin.
#
# USAGE
#   sudo bash deploy/harden-tor.sh --status
#   sudo bash deploy/harden-tor.sh --bridges /root/ponts.txt --dry-run
#   sudo bash deploy/harden-tor.sh --bridges /root/ponts.txt
#   sudo bash deploy/harden-tor.sh --no-bridges
#   sudo bash deploy/harden-tor.sh --vanguards
#
# OU TROUVER DES PONTS
#   1. https://bridges.torproject.org  (captcha, transport obfs4)
#   2. par courriel, depuis une adresse Gmail ou Riseup :
#        a : bridges@torproject.org      corps : get transport obfs4
#   3. Tor Browser > Parametres > Connexion > « Demander un pont »
#   Collez les lignes obtenues dans un fichier, une par ligne. Le mot-cle
#   « Bridge » en tete est optionnel, le script l'accepte dans les deux formes.
#
set -Eeuo pipefail

# ---------------------------------------------------------------- reglages

APP_NAME="depressedyoungmanblog"
TOR_HS_DIR="/var/lib/tor/${APP_NAME}"
TORRC="/etc/tor/torrc"

CONTROL_SOCKET="/run/tor/control"
BOOTSTRAP_TIMEOUT="${BOOTSTRAP_TIMEOUT:-180}"   # secondes ; les ponts sont lents

VG_DIR="/opt/vanguards"
VG_USER="vanguards"
VG_STATE_DIR="/var/lib/vanguards"
VG_UNIT="/etc/systemd/system/vanguards.service"
VG_REPO="${VANGUARDS_REPO:-https://github.com/mikeperry-tor/vanguards}"
# Par defaut la branche par defaut du depot. Pour epingler une version revue :
#   VANGUARDS_REF=v0.3.1 sudo -E bash deploy/harden-tor.sh --vanguards
# et verifiez la signature de l'etiquette avant, avec la cle de l'auteur :
#   git -C /opt/vanguards verify-tag v0.3.1
VG_REF="${VANGUARDS_REF:-}"

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

usage() {
    sed -n '3,45p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# ------------------------------------------------------------- arguments

DRY_RUN=0; DO_BRIDGES=0; DO_NO_BRIDGES=0; DO_VANGUARDS=0; DO_STATUS=0
BRIDGE_FILE=""

while (( $# )); do
    case "$1" in
        --bridges)
            BRIDGE_FILE="${2:-}"
            [[ -n "$BRIDGE_FILE" ]] || die "--bridges attend un fichier de lignes obfs4."
            DO_BRIDGES=1; shift 2 ;;
        --no-bridges)   DO_NO_BRIDGES=1; shift ;;
        --vanguards)    DO_VANGUARDS=1;  shift ;;
        --status)       DO_STATUS=1;     shift ;;
        --dry-run)      DRY_RUN=1;       shift ;;
        -h|--help)      usage; exit 0 ;;
        *)              die "Option inconnue : $1  (--help pour la liste)" ;;
    esac
done

if (( ! DO_BRIDGES && ! DO_NO_BRIDGES && ! DO_VANGUARDS && ! DO_STATUS )); then
    usage; exit 0
fi
if (( DO_BRIDGES && DO_NO_BRIDGES )); then
    die "--bridges et --no-bridges sont contradictoires."
fi

[[ $EUID -eq 0 ]] || die "A lancer avec sudo."
[[ -f "$TORRC" ]]  || die "$TORRC introuvable. Lancez d'abord deploy/deploy-onion.sh."
command -v apt-get >/dev/null 2>&1 \
    || die "Ce script vise Debian/Ubuntu (apt). Adaptez la section « Paquets » ailleurs."

if (( DRY_RUN )); then
    warn "Mode simulation : aucune modification ne sera ecrite."
fi

# Sur Debian, tor.service n'est qu'une enveloppe ; l'instance qui tourne
# vraiment est tor@default.service. Les journaux sont a chercher dans les deux,
# et sous l'identifiant syslog « Tor » puisque torrc ecrit « Log notice syslog ».
TOR_UNIT="tor.service"
if systemctl list-unit-files 'tor@*' 2>/dev/null | grep -q '^tor@default'; then
    TOR_UNIT="tor@default.service"
fi

# Le groupe du demon tor : debian-tor sur Debian/Ubuntu, tor ailleurs.
TOR_GROUP=""
for g in debian-tor tor; do
    if getent group "$g" >/dev/null; then TOR_GROUP="$g"; break; fi
done

# ------------------------------------------------------- torrc : outillage

TORRC_BACKUP=""

backup_torrc() {
    [[ -n "$TORRC_BACKUP" ]] && return 0
    TORRC_BACKUP="${TORRC}.bak.$(date +%s)"
    run cp -a "$TORRC" "$TORRC_BACKUP"
    ok "Sauvegarde : ${TORRC_BACKUP}"
}

mark_begin() { printf '# --- harden-tor: %s ---' "$1"; }
mark_end()   { printf '# --- harden-tor: %s fin ---' "$1"; }

torrc_has_block() { grep -qF "$(mark_begin "$1")" "$TORRC" 2>/dev/null; }

torrc_drop_block() {
    local name="$1"
    torrc_has_block "$name" || return 0
    if (( DRY_RUN )); then
        info "[dry-run] retrait du bloc « ${name} » de ${TORRC}"
        return 0
    fi
    sed -i "\|^$(mark_begin "$name")$|,\|^$(mark_end "$name")$|d" "$TORRC"
}

# Remplace le bloc s'il existe deja, l'ajoute sinon. Le contenu arrive sur
# l'entree standard.
torrc_set_block() {
    local name="$1" content
    content="$(cat)"
    backup_torrc
    torrc_drop_block "$name"
    if (( DRY_RUN )); then
        info "[dry-run] ajout dans ${TORRC} :"
        printf '%s\n' "$content" | sed 's/^/       /'
        return 0
    fi
    {
        printf '\n%s\n' "$(mark_begin "$name")"
        printf '%s\n'   "$content"
        printf '%s\n'   "$(mark_end "$name")"
    } >> "$TORRC"
}

# Une erreur de syntaxe dans torrc empeche tor de demarrer — donc coupe le
# service onion. On la detecte avant de redemarrer quoi que ce soit.
torrc_verify() {
    local out
    if (( DRY_RUN )); then
        info "[dry-run] tor --verify-config -f ${TORRC}"
        return 0
    fi
    if out="$(tor --verify-config -f "$TORRC" 2>&1)"; then
        ok "torrc valide"
        return 0
    fi
    printf '%s\n' "$out" | sed 's/^/     /' >&2
    return 1
}

wait_bootstrap() {
    local since="$1" i
    for (( i = 0; i < BOOTSTRAP_TIMEOUT; i++ )); do
        if journalctl --no-pager --since "$since" -t Tor -u "$TOR_UNIT" -u tor.service 2>/dev/null \
                | grep -q 'Bootstrapped 100%'; then
            return 0
        fi
        if systemctl is-failed --quiet "$TOR_UNIT"; then
            return 1
        fi
        sleep 1
        (( i % 15 == 0 && i > 0 )) && info "  ... ${i}s, tor bootstrappe toujours"
    done
    return 1
}

# Redemarre tor. Si le bootstrap n'aboutit pas, restaure la sauvegarde et
# redemarre a nouveau : mieux vaut revenir sans ponts qu'un onion hors ligne.
tor_restart_or_rollback() {
    local since
    since="$(date '+%Y-%m-%d %H:%M:%S')"
    run systemctl restart tor
    if (( DRY_RUN )); then return 0; fi

    info "Attente du bootstrap (jusqu'a ${BOOTSTRAP_TIMEOUT}s ; les ponts sont lents)"
    if wait_bootstrap "$since"; then
        ok "Tor a rebootstrappe (100%)"
        [[ -f "${TOR_HS_DIR}/hostname" ]] \
            && ok "Adresse toujours en place : $(cat "${TOR_HS_DIR}/hostname")"
        return 0
    fi

    warn "Pas de « Bootstrapped 100% » en ${BOOTSTRAP_TIMEOUT}s — retour en arriere"
    if [[ -n "$TORRC_BACKUP" && -f "$TORRC_BACKUP" ]]; then
        cp -a "$TORRC_BACKUP" "$TORRC"
        since="$(date '+%Y-%m-%d %H:%M:%S')"
        systemctl restart tor
        if wait_bootstrap "$since"; then
            die "Configuration precedente restauree, le service onion est revenu.
   Les ponts fournis ne fonctionnent pas ou sont bloques depuis ce reseau.
   Journal : journalctl -t Tor -u ${TOR_UNIT} -n 80"
        fi
    fi
    die "Tor ne bootstrappe plus, meme apres restauration. A traiter tout de suite :
   journalctl -t Tor -u ${TOR_UNIT} -n 80
   Sauvegarde de torrc : ${TORRC_BACKUP:-aucune}"
}

apt_install() {
    local missing=() p
    for p in "$@"; do
        dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
    done
    if [[ ${#missing[@]} -eq 0 ]]; then
        ok "Deja installe : $*"
        return 0
    fi
    run apt-get update -qq
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}"
    ok "Installe : ${missing[*]}"
}

# ==================================================================== PONTS

configure_bridges() {
    step "Ponts obfs4"

    [[ -f "$BRIDGE_FILE" ]] || die "Fichier introuvable : ${BRIDGE_FILE}"

    # -- lecture et controle des lignes -----------------------------------
    local line lines="" count=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"     # espaces en tete
        line="${line%"${line##*[![:space:]]}"}"     # espaces en queue
        [[ -z "$line" || "$line" == \#* ]] && continue
        line="${line#Bridge }"; line="${line#bridge }"

        [[ "$line" == obfs4\ * ]] \
            || die "Seul le transport obfs4 est gere ici. Ligne refusee :
     ${line}"
        # obfs4 ADRESSE:PORT EMPREINTE(40 hex) cert=... iat-mode=...
        [[ "$line" =~ ^obfs4[[:space:]]+[^[:space:]]+:[0-9]+[[:space:]]+[0-9A-Fa-f]{40}([[:space:]]|$) ]] \
            || die "Ligne obfs4 mal formee (attendu : obfs4 ADRESSE:PORT EMPREINTE cert=...) :
     ${line}"
        grep -q 'cert=' <<<"$line" \
            || warn "Pas de « cert= » sur une ligne : le pont sera probablement refuse par tor"

        lines+="Bridge ${line}"$'\n'
        count=$(( count + 1 ))
    done < "$BRIDGE_FILE"

    [[ $count -gt 0 ]] || die "Aucune ligne de pont exploitable dans ${BRIDGE_FILE}"
    ok "${count} pont(s) lu(s)"
    if [[ $count -lt 2 ]]; then
        warn "Un seul pont : s'il tombe ou est bloque, le service onion disparait.
     Deux ou trois ponts d'operateurs differents valent mieux."
    fi

    # -- greffon de transport ---------------------------------------------
    # obfs4proxy a ete remplace par lyrebird dans les versions recentes de
    # Debian ; l'un ou l'autre fait l'affaire, le nom du transport ne change pas.
    apt_install obfs4proxy || apt_install lyrebird
    local pt_bin=""
    for b in obfs4proxy lyrebird; do
        if command -v "$b" >/dev/null 2>&1; then pt_bin="$(command -v "$b")"; break; fi
    done
    [[ -n "$pt_bin" ]] || die "Ni obfs4proxy ni lyrebird trouve apres installation."
    ok "Greffon obfs4 : ${pt_bin}"

    # -- torrc -------------------------------------------------------------
    torrc_set_block "bridges" <<EOF
# Ne pas passer par les gardes publics : tout le trafic sort par les ponts
# ci-dessous. Le fournisseur d'acces voit un flux chiffre sans signature Tor.
UseBridges 1
ClientTransportPlugin obfs4 exec ${pt_bin}
${lines}
EOF

    torrc_verify || {
        if [[ -n "$TORRC_BACKUP" && -f "$TORRC_BACKUP" ]]; then
            cp -a "$TORRC_BACKUP" "$TORRC"
            warn "torrc restaure, rien n'a ete redemarre"
        fi
        die "torrc refuse par tor (voir ci-dessus). Verifiez les lignes de ponts."
    }

    tor_restart_or_rollback

    if (( ! DRY_RUN )); then
        info "Verifiez que le trafic sort bien par les ponts :"
        info "  journalctl -t Tor -u ${TOR_UNIT} -n 40 | grep -i bridge"
    fi
}

remove_bridges() {
    step "Retrait des ponts"

    if ! torrc_has_block "bridges"; then
        ok "Aucun bloc de ponts dans ${TORRC}"
        return 0
    fi
    backup_torrc
    torrc_drop_block "bridges"
    torrc_verify || die "torrc invalide apres retrait — restaurez ${TORRC_BACKUP}"
    tor_restart_or_rollback
    ok "Ponts retires, tor repasse par les gardes publics"
}

# =============================================================== VANGUARDS

configure_vanguards() {
    step "vanguards"

    [[ -n "$TOR_GROUP" ]] || die "Groupe du demon tor introuvable (ni debian-tor ni tor)."

    apt_install git python3-venv python3-pip

    # -- compte dedie ------------------------------------------------------
    if id "$VG_USER" >/dev/null 2>&1; then
        ok "Utilisateur ${VG_USER} deja present"
    else
        run useradd --system --no-create-home --shell /usr/sbin/nologin "$VG_USER"
        ok "Utilisateur systeme ${VG_USER} cree (sans shell)"
    fi
    # L'acces au socket de controle et au cookie passe par le groupe de tor.
    run usermod -aG "$TOR_GROUP" "$VG_USER"
    ok "${VG_USER} ajoute au groupe ${TOR_GROUP}"

    run install -d -o "$VG_USER" -g "$VG_USER" -m 750 "$VG_STATE_DIR"

    # -- code --------------------------------------------------------------
    if [[ -d "${VG_DIR}/.git" ]]; then
        run git -C "$VG_DIR" fetch --quiet --tags origin
        ok "Depot vanguards deja present, mis a jour"
    else
        run git clone --quiet "$VG_REPO" "$VG_DIR"
        ok "vanguards clone dans ${VG_DIR}"
    fi
    if [[ -n "$VG_REF" ]]; then
        run git -C "$VG_DIR" checkout --quiet "$VG_REF"
        ok "Version epinglee : ${VG_REF}"
        info "Verifiez la signature avant de faire confiance : git -C ${VG_DIR} verify-tag ${VG_REF}"
    else
        run git -C "$VG_DIR" pull --quiet --ff-only || true
        warn "Branche par defaut, non epinglee. Pour epingler une version revue :
     VANGUARDS_REF=<etiquette> sudo -E bash deploy/harden-tor.sh --vanguards"
    fi

    # -- venv --------------------------------------------------------------
    if [[ ! -x "${VG_DIR}/.venv/bin/python" ]]; then
        run python3 -m venv "${VG_DIR}/.venv"
    fi
    run "${VG_DIR}/.venv/bin/pip" install --quiet --upgrade pip
    if [[ -f "${VG_DIR}/requirements.txt" ]]; then
        run "${VG_DIR}/.venv/bin/pip" install --quiet -r "${VG_DIR}/requirements.txt"
    else
        run "${VG_DIR}/.venv/bin/pip" install --quiet stem
    fi
    ok "Environnement Python pret"

    local vg_py="${VG_DIR}/.venv/bin/python"
    local vg_main="${VG_DIR}/src/vanguards.py"
    if (( ! DRY_RUN )) && [[ ! -f "$vg_main" ]]; then
        die "${vg_main} absent — la disposition du depot a change, adaptez le script."
    fi

    # -- socket de controle -------------------------------------------------
    # Socket unix plutot que ControlPort TCP : rien de nouveau n'ecoute sur le
    # reseau, meme en local. L'authentification se fait par cookie, lisible par
    # le groupe de tor, dont vanguards fait partie.
    torrc_set_block "controle" <<EOF
ControlSocket ${CONTROL_SOCKET}
ControlSocketsGroupWritable 1
CookieAuthentication 1
CookieAuthFileGroupReadable 1
EOF
    torrc_verify || die "torrc refuse par tor apres ajout du socket de controle."
    tor_restart_or_rollback

    if (( ! DRY_RUN )); then
        local i
        for (( i = 0; i < 30; i++ )); do
            [[ -S "$CONTROL_SOCKET" ]] && break
            sleep 1
        done
        [[ -S "$CONTROL_SOCKET" ]] \
            || die "${CONTROL_SOCKET} n'existe pas. Voir : journalctl -t Tor -u ${TOR_UNIT} -n 50"
        ok "Socket de controle : ${CONTROL_SOCKET}"
    fi

    # -- arguments reellement acceptes par cette version --------------------
    # Plutot que de deviner les options, on lit l'aide de la version installee.
    local args="" vg_help=""
    if (( ! DRY_RUN )); then
        vg_help="$("$vg_py" "$vg_main" --help 2>&1 || true)"
        grep -q -- '--control_socket' <<<"$vg_help" \
            && args="--control_socket ${CONTROL_SOCKET}" \
            || warn "--control_socket absent de l'aide : vanguards utilisera ses valeurs par defaut"
        if grep -q -- '--state' <<<"$vg_help"; then
            args="${args} --state ${VG_STATE_DIR}/vanguards.state"
        fi
    else
        args="--control_socket ${CONTROL_SOCKET}"
    fi

    # -- unite systemd ------------------------------------------------------
    if (( DRY_RUN )); then
        info "[dry-run] ecriture de ${VG_UNIT}"
    else
        cat > "$VG_UNIT" <<EOF
[Unit]
Description=vanguards — protection des gardes du service onion
After=${TOR_UNIT}
Wants=${TOR_UNIT}

[Service]
Type=simple
User=${VG_USER}
Group=${TOR_GROUP}
WorkingDirectory=${VG_STATE_DIR}
ExecStart=${vg_py} ${vg_main} ${args}
Restart=on-failure
RestartSec=10

# Durcissement : vanguards ne parle qu'au socket unix de tor et n'ecrit que
# son fichier d'etat. Rien d'autre ne lui est necessaire.
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
# AF_UNIX seul : si vous repassez un jour a un ControlPort TCP, ajoutez AF_INET.
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
ReadWritePaths=${VG_STATE_DIR}

[Install]
WantedBy=multi-user.target
EOF
        chmod 644 "$VG_UNIT"
        ok "Unite ${VG_UNIT} ecrite"
    fi

    run systemctl daemon-reload
    run systemctl enable --quiet vanguards.service
    run systemctl restart vanguards.service

    if (( ! DRY_RUN )); then
        sleep 5
        if systemctl is-active --quiet vanguards.service; then
            ok "vanguards tourne"
            info "Journal : journalctl -u vanguards -f"
        else
            warn "vanguards n'a pas demarre. Le service onion, lui, n'est pas affecte."
            journalctl -u vanguards -n 30 --no-pager | sed 's/^/     /'
            warn "Corrigez ou desactivez : systemctl disable --now vanguards"
        fi
    fi
}

# ================================================================== ETAT

show_status() {
    step "Etat"

    printf '   %-22s %s\n' "unite tor" "$TOR_UNIT"
    printf '   %-22s %s\n' "tor" "$(systemctl is-active "$TOR_UNIT" 2>/dev/null || echo inactif)"
    printf '   %-22s %s\n' "version" "$(tor --version 2>/dev/null | head -1 || echo '?')"

    if [[ -f "${TOR_HS_DIR}/hostname" ]]; then
        printf '   %-22s %s\n' "adresse onion" "$(cat "${TOR_HS_DIR}/hostname")"
    else
        printf '   %-22s %s\n' "adresse onion" "absente (${TOR_HS_DIR}/hostname)"
    fi

    if torrc_has_block "bridges"; then
        local n
        n="$(grep -c '^Bridge ' "$TORRC" || true)"
        printf '   %-22s %s\n' "ponts" "actifs — ${n} ligne(s)"
    else
        printf '   %-22s %s\n' "ponts" "aucun (gardes publics)"
    fi

    if torrc_has_block "controle"; then
        printf '   %-22s %s\n' "socket de controle" \
            "$( [[ -S "$CONTROL_SOCKET" ]] && echo "${CONTROL_SOCKET} present" || echo "declare, socket absent" )"
    else
        printf '   %-22s %s\n' "socket de controle" "non configure"
    fi

    if [[ -f "$VG_UNIT" ]]; then
        printf '   %-22s %s\n' "vanguards" "$(systemctl is-active vanguards.service 2>/dev/null || echo inactif)"
    else
        printf '   %-22s %s\n' "vanguards" "non installe"
    fi

    local boot
    boot="$(journalctl --no-pager -t Tor -u "$TOR_UNIT" -u tor.service -n 400 2>/dev/null \
            | grep -o 'Bootstrapped [0-9]*%' | tail -1 || true)"
    printf '   %-22s %s\n' "dernier bootstrap" "${boot:-inconnu}"

    printf '\n'
}

# ================================================================= actions

(( DO_STATUS ))     && show_status
(( DO_NO_BRIDGES )) && remove_bridges
(( DO_BRIDGES ))    && configure_bridges
(( DO_VANGUARDS ))  && configure_vanguards

if (( DO_BRIDGES || DO_NO_BRIDGES || DO_VANGUARDS )); then
    cat <<EOF

  ${C_DIM}Verifications${C_OFF}
    systemctl status ${TOR_UNIT}
    journalctl -t Tor -u ${TOR_UNIT} -n 60
    sudo bash deploy/harden-tor.sh --status
    ${C_DIM}puis ouvrir l'adresse .onion dans Tor Browser${C_OFF}

EOF
fi

cat <<'EOF'
  ── Ce que ces deux mesures ne font pas ───────────────────────────

  LES PONTS
    Ils cachent a votre fournisseur d'acces que la machine parle a Tor. Ils ne
    cachent rien a l'operateur du pont, qui voit une adresse IP se connecter —
    sans savoir ce qu'elle publie. Ils n'ajoutent aucune protection au service
    onion lui-meme.

  VANGUARDS
    Il rend la decouverte de garde beaucoup plus couteuse, pas impossible. Il
    ne protege ni du vol de la cle onion, ni d'un acces au serveur, ni d'une
    faille applicative.

  CE QUI COMPTE AUTANT
    Le chiffrement du disque et la desactivation de la swap. Sans eux, tout ce
    qui precede tombe des que quelqu'un ouvre la machine.

EOF
