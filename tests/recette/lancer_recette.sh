#!/usr/bin/env bash
# Recette complète du projet : compile, suite de tests, puis les pilotes
# de vérification qui demandent une cible réelle (localhost uniquement).
#
#   ./tests/recette/lancer_recette.sh
#
# Aucun accès réseau externe : tout passe par 127.0.0.1.

set -u
cd "$(dirname "$0")/../.." || exit 1
RACINE="$PWD"
echec=0

titre() { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }
verdict() {
    if [ "$1" -eq 0 ]; then printf '  \033[32mOK\033[0m   %s\n' "$2"
    else printf '  \033[31mECHEC\033[0m %s\n' "$2"; echec=1; fi
}

titre "Compilation"
python3 -m py_compile bruteforce.py lab_server.py test.py bruteforcessh.py \
    tests/test_outils.py tests/recette/*.py
verdict $? "tous les modules compilent"

titre "Suite de tests (67 tests, ~40 s)"
python3 tests/test_outils.py
verdict $? "tests/test_outils.py"

for pilote in tests/recette/verif_profils.py tests/recette/verif_profils2.py \
              tests/recette/test_bruteforce.py tests/recette/test_gaps.py \
              tests/recette/test_get.py tests/recette/test_interactive.py \
              tests/recette/test_docs.py; do
    titre "$(basename "$pilote")"
    python3 "$pilote"
    code=$?
    # les pilotes affichent eux-mêmes leur bilan ; le code retour tranche
    verdict $code "$pilote"
done

titre "Nettoyage"
rm -rf resultats __pycache__ tests/__pycache__ tests/recette/__pycache__
verdict $? "artefacts supprimés"

titre "Largeur du readme (80 colonnes)"
trop_long=$(awk 'length>80 {print NR": "length" caracteres"}' readme.txt)
if [ -z "$trop_long" ]; then verdict 0 "readme.txt respecte 80 colonnes"
else printf '  %s\n' "$trop_long"; verdict 1 "readme.txt"; fi

titre "Bilan"
if [ "$echec" -eq 0 ]; then printf '\033[32mRecette complète : tout est conforme.\033[0m\n'
else printf '\033[31mRecette incomplète : voir les lignes ECHEC ci-dessus.\033[0m\n'; fi
exit $echec