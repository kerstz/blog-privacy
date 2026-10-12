#!/usr/bin/env bash
#
# package.sh — fabrique une archive propre du blog, prete a etre envoyee au
# serveur, et affiche la commande scp correspondante.
#
# POURQUOI PASSER PAR UNE ARCHIVE
#   Un `scp -r` du dossier entier enverrait .venv (une centaine de mega-octets
#   de binaires compiles pour VOTRE machine, inutilisables ailleurs), tout
#   l'historique git, la base de donnees locale, et surtout le fichier .env
#   avec vos secrets de developpement. L'archive ne contient que le code.
#
#   Le serveur genere ses propres secrets et sa propre base. Rien de ce qui
#   contient des donnees ne doit voyager.
#
# USAGE
#   bash deploy/package.sh                 # cree l'archive et affiche la suite
#   bash deploy/package.sh 192.168.1.42    # ... avec l'adresse du serveur
#
set -Eeuo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
ARCHIVE="/tmp/depressedyoungmanblog-${STAMP}.tar.gz"
SERVER_IP="${1:-}"

C_OK=$'\e[38;5;110m'; C_WARN=$'\e[38;5;180m'; C_DIM=$'\e[38;5;245m'; C_OFF=$'\e[0m'
ok()   { printf '   %s✓%s %s\n' "$C_OK" "$C_OFF" "$1"; }
warn() { printf '   %s!%s %s\n' "$C_WARN" "$C_OFF" "$1"; }
step() { printf '\n%s──%s %s\n' "$C_DIM" "$C_OFF" "$1"; }

step "Verification"

# Un .env dans l'archive serait la fuite la plus betement evitable : il
# contient la cle qui dechiffre les messages.
EXCLUDES=(
    --exclude='.git'
    --exclude='.venv'
    --exclude='venv'
    --exclude='__pycache__'
    --exclude='*.pyc'
    --exclude='.env'
    --exclude='.env.local'
    --exclude='instance'
    --exclude='uploads/*'
    --exclude='.playwright-mcp'
    --exclude='*.db'
    --exclude='*.sqlite*'
    --exclude='node_modules'
)
ok "Exclus : .env, .git, .venv, instance/, uploads/, bases de donnees"

step "Archive"

tar czf "$ARCHIVE" -C "$(dirname "$SRC_DIR")" "${EXCLUDES[@]}" "$(basename "$SRC_DIR")"
ok "$ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"

# Controle : rien de sensible ne doit avoir echappe aux exclusions.
LEAKS="$(tar tzf "$ARCHIVE" | grep -E '(^|/)\.env$|\.db$|\.sqlite|(^|/)\.git/' || true)"
if [[ -n "$LEAKS" ]]; then
    warn "Fichiers sensibles dans l'archive — NE PAS L'ENVOYER :"
    printf '%s\n' "$LEAKS" | sed 's/^/     /'
    exit 1
fi
ok "Aucun secret ni base de donnees dans l'archive"

printf '\n   %sContenu (%s fichiers)%s\n' "$C_DIM" "$(tar tzf "$ARCHIVE" | wc -l)" "$C_OFF"
tar tzf "$ARCHIVE" | sed "s|^$(basename "$SRC_DIR")/||" | awk -F/ 'NF>1 {print $1"/"} NF==1 && $1!="" {print $1}' \
    | sort -u | head -20 | sed 's/^/     /'

step "Envoi vers le serveur"

if [[ -z "$SERVER_IP" ]]; then
    cat <<EOF

   Trouvez l'adresse locale du serveur :
     ${C_DIM}# sur le serveur${C_OFF}
     hostname -I
     ${C_DIM}# ou depuis cette machine, si vous ne la connaissez pas${C_OFF}
     ip -4 route | awk '/default/ {print \$3}'   # votre passerelle
     nmap -sn 192.168.1.0/24                     # machines du reseau

   Puis relancez avec l'adresse :
     bash deploy/package.sh 192.168.1.42

EOF
    exit 0
fi

cat <<EOF

   ${C_DIM}1. Envoyer l'archive${C_OFF}
     scp ${ARCHIVE} utilisateur@${SERVER_IP}:~/

   ${C_DIM}2. Se connecter au serveur${C_OFF}
     ssh utilisateur@${SERVER_IP}

   ${C_DIM}3. Sur le serveur : extraire et deployer${C_OFF}
     tar xzf $(basename "$ARCHIVE")
     cd $(basename "$SRC_DIR")
     sudo bash deploy/deploy-onion.sh --dry-run
     sudo bash deploy/deploy-onion.sh

   ${C_DIM}4. Effacer l'archive des deux cotes${C_OFF}
     ${C_DIM}# sur le serveur${C_OFF}
     shred -u ~/$(basename "$ARCHIVE")
     ${C_DIM}# ici${C_OFF}
     shred -u ${ARCHIVE}

EOF

cat <<'EOF'
   ── Sur le reseau local ───────────────────────────────────────────

   scp passe par SSH, donc c'est chiffre de bout en bout — y compris sur
   votre propre reseau. La premiere connexion affiche l'empreinte de la
   cle du serveur :

     The authenticity of host '192.168.1.42' can't be established.
     ED25519 key fingerprint is SHA256:xxxxxxxx...

   Comparez-la avec ce que le serveur affiche localement, une seule fois :

     ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub

   Si les deux empreintes different, quelqu'un s'interpose. C'est la seule
   verification qui compte et elle ne prend que trente secondes.

   ── Renforcer SSH pendant que vous y etes ─────────────────────────

   Authentification par cle plutot que par mot de passe :

     ssh-keygen -t ed25519                       # ici, si pas deja fait
     ssh-copy-id utilisateur@192.168.1.42

   Puis sur le serveur, dans /etc/ssh/sshd_config :

     PasswordAuthentication no
     PermitRootLogin no
     KbdInteractiveAuthentication no

     sudo systemctl restart ssh

   Gardez une session ouverte pendant le test : une erreur de configuration
   SSH sur une machine sans ecran se paie en clavier et en cable.

EOF
