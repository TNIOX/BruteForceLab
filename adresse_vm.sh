#!/usr/bin/env bash
# Affiche l'adresse IP actuelle de la VM d'atelier.
#
# L'IP est attribuée par DHCP et peut changer : elle n'est donc jamais
# écrite en dur dans la documentation. On retrouve la VM par son adresse MAC,
# seule chose stable — mais cette MAC n'est pas figée non plus : à
# l'import d'un .ova, VirtualBox en attribue une nouvelle. On la demande donc
# directement à VirtualBox, qui est la seule source de vérité.
#
# Sortie : l'IP sur stdout, rien d'autre. Code de retour 0 si la VM a été
# trouvée, 1 sinon. En cas d'échec on ne renvoie aucune adresse de repli :
# viser l'IP d'une autre machine serait pire que ne rien lancer.

set -euo pipefail

PORT_SONDE="${PORT_SONDE:-8180}"
VBOX="${VBOX:-VBoxManage}"
NOM_HOTE="${NOM_HOTE:-metasploitable}"

# --publier : enregistre aussi le nom dans /etc/hosts, pour que les
# applications qui figent une URL dans leur base (WordPress) restent
# joignables apres un changement d'IP. Necessite les droits root.
PUBLIER=0
if [ "${1:-}" = "--publier" ]; then
    PUBLIER=1
    shift
fi

# Ecrit "<IP> <NOM_HOTE>" dans /etc/hosts, en remplacant l'ancienne entree.
publier_dans_hosts() {
    local tmp
    [ "$(id -u)" -eq 0 ] || {
        echo "adresse_vm.sh : --publier exige les droits root." >&2
        echo "  Utiliser : sudo $0 --publier" >&2
        exit 1
    }
    tmp=$(mktemp)
    grep -vE "[[:space:]]${NOM_HOTE}([[:space:]]|\$)" /etc/hosts > "$tmp" || true
    printf '%s %s\n' "$1" "$NOM_HOTE" >> "$tmp"
    cat "$tmp" > /etc/hosts
    rm -f "$tmp"
}

# Liste des MAC à chercher. Surcharge possible par MAC_VM, une ou plusieurs
# séparées par des espaces (utile si VirtualBox n'est pas sur le PATH).
macs_candidates() {
    if [ -n "${MAC_VM:-}" ]; then
        printf '%s\n' ${MAC_VM}
        return 0
    fi
    command -v "$VBOX" >/dev/null 2>&1 || return 0
    local nom mac
    while read -r nom; do
        [ -n "$nom" ] || continue
        mac=$("$VBOX" showvminfo "$nom" 2>/dev/null \
              | awk -F'MAC: ' '/^NIC [0-9]+:/ {split($2, m, ","); print tolower(m[1])}')
        [ -n "$mac" ] && printf '%s\n' "$mac"
    done < <("$VBOX" list runningvms 2>/dev/null | sed 's/^"\(.*\)".*/\1/')
}

# L'IP est-elle dans la table ARP ? (rapide, mais peut être absente)
# VirtualBox écrit les MAC sans deux-points ("0800270770b5"), le noyau avec
# ("08:00:27:07:70:b5") : on normalise les deux côtés avant de comparer.
ip_depuis_arp() {
    local mac trouve=""
    for mac in "$@"; do
        trouve=$(ip neigh show | awk -v m="$mac" '
            { cle = $5; gsub(":", "", cle); cible = m; gsub(":", "", cible)
              if (cle == cible) { print $1; exit } }')
        [ -n "$trouve" ] && break
    done
    printf '%s' "$trouve"
}

# Le réseau à balayer est déduit de la route par défaut, pas supposé.
reseau_de_defaut() {
    local iface prefix route
    iface=$(ip -4 route show default | awk '/default/ {print $5; exit}')
    [ -n "$iface" ] || return 1
    prefix=$(ip -o -4 addr show dev "$iface" scope global | awk '{split($4,a,"/"); print a[2]; exit}')
    [ -n "$prefix" ] || return 1
    route=$(ip -4 route show default | awk '/default/ {print $3; exit}')
    [ -n "$route" ] || return 1
    printf '%s/%s' "$route" "$prefix"
}

# Un balayage du sous-réseau remplit la table ARP et révèle la VM.
balayer() {
    local hote
    hote=$(reseau_de_defaut) || return 1
    hote=${hote%/*}
    for h in $(seq 1 254); do
        ping -c1 -W1 "$hote.$h" >/dev/null 2>&1 &
    done
    wait
}

# Le port sentinelle confirme qu'on tient bien la VM et pas un doublon.
sonde_ouverte() {
    timeout 3 bash -c "echo > /dev/tcp/$1/$PORT_SONDE" 2>/dev/null
}

CANDIDATS=$(macs_candidates)

if [ -z "$CANDIDATS" ]; then
    echo "adresse_vm.sh : aucune VM VirtualBox en marche, ou VBoxManage absent." >&2
    echo "  Démarrer la VM, ou renseigner MAC_VM=\"aa:bb:cc:dd:ee:ff\"." >&2
    exit 1
fi

# shellcheck disable=SC2086
IP=$(ip_depuis_arp $CANDIDATS)
if [ -z "$IP" ]; then
    balayer || true
    # shellcheck disable=SC2086
    IP=$(ip_depuis_arp $CANDIDATS)
fi

if [ -z "$IP" ]; then
    echo "adresse_vm.sh : VM introuvable sur le réseau." >&2
    echo "  MAC cherchées : $(echo $CANDIDATS | tr '\n' ' ')" >&2
    echo "  Vérifier que la VM est démarrée et branchée sur le même réseau," >&2
    echo "  ou renseigner MAC_VM si elle est une autre machine." >&2
    exit 1
fi

if ! sonde_ouverte "$IP"; then
    echo "adresse_vm.sh : $IP répond mais le port $PORT_SONDE est fermé." >&2
    echo "  La VM est peut-être encore en cours de démarrage, réessayer dans un instant." >&2
    exit 1
fi

if [ "$PUBLIER" -eq 1 ]; then
    publier_dans_hosts "$IP"
    echo "$IP  (/etc/hosts mis a jour pour $NOM_HOTE)" >&2
fi

echo "$IP"