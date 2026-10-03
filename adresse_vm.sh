#!/usr/bin/env bash
# Affiche l'adresse IP actuelle de la VM d'atelier.
#
# L'IP est attribuée par DHCP et peut changer : elle n'est donc jamais
# écrite en dur dans la documentation. On retrouve la VM par sa adresse MAC,
# qui elle est figée dans la configuration VirtualBox.
#
# Sortie : l'IP sur stdout, rien d'autre. Code de retour 0 si la VM a été
# trouvée, 1 sinon. En cas d'échec on ne renvoie aucune adresse de repli :
# viser l'IP d'une autre machine serait pire que ne rien lancer.

set -euo pipefail

MAC_VM="${MAC_VM:-08:00:27:72:74:31}"
PORT_SONDE="${PORT_SONDE:-8180}"

# Le réseau à balayer est déduit de la route par défaut, pas supposé.
reseau() {
    local iface route prefix
    iface=$(ip -4 route show default | awk '/default/ {print $5; exit}')
    [ -n "$iface" ] || return 1
    prefix=$(ip -o -4 addr show dev "$iface" scope global | awk '{split($4,a,"/"); print a[2]; exit}')
    [ -n "$prefix" ] || return 1
    route=$(ip -4 route show default | awk '/default/ {print $3; exit}')
    [ -n "$route" ] || return 1
    echo "$route/$prefix"
}

# L'IP est-elle dans la table ARP ? (rapide, mais peut être absente)
depuis_arp() {
    ip neigh show | awk -v mac="$MAC_VM" 'tolower($5) == mac {print $1; exit}'
}

# Un balayage du sous-réseau remplit la table ARP et révèle la VM.
depuis_balayage() {
    local reseau_loc hosts
    reseau_loc=$(reseau) || return 1
    hosts=${reseau_loc%/*}
    for h in $(seq 1 254); do
        ping -c1 -W1 "$hosts.$h" >/dev/null 2>&1 &
    done
    wait
    depuis_arp
}

# Le port sentinelle confirme qu'on tient bien la VM et pas un doublon.
confirmer() {
    timeout 3 bash -c "echo > /dev/tcp/$1/$PORT_SONDE" 2>/dev/null
}

IP=$(depuis_arp || true)
if [ -z "$IP" ]; then
    IP=$(depuis_balayage || true)
fi

if [ -z "$IP" ]; then
    echo "adresse_vm.sh : VM introuvable (MAC $MAC_VM)." >&2
    echo "  Vérifier que la VM est démarrée et branchée sur le même réseau." >&2
    echo "  Adapter MAC_VM si la carte a changé, ou PORT_SONDE si le port $PORT_SONDE est fermé." >&2
    exit 1
fi

if ! confirmer "$IP"; then
    echo "adresse_vm.sh : $IP répond mais le port $PORT_SONDE est fermé." >&2
    echo "  La VM est peut-être encore en cours de démarrage, réessayer dans un instant." >&2
    exit 1
fi

echo "$IP"