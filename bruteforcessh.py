#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Version corrigée du script d'origine, réduite au strict nécessaire.

Ce fichier sert d'exercice de lecture : il montre les six défauts du script
initial et la correction associée, puis fonctionne réellement. Pour un outil
complet, utilisez bruteforce.py.

Corrections appliquées par rapport à la version initiale :
  1. URL, identifiant et message d'échec paramétrables au lieu d'écrit en dur.
  2. Filtrage des lignes vides du dictionnaire (sinon des essais « vides »).
  3. Délai entre les requêtes : le serveur n'est pas submergé.
  4. Délai d'attente réseau (timeout) et gestion des erreurs de connexion.
  5. Détection de réussite fondée sur un motif de réponse explicite, au lieu
     du « si ce n'est pas le message d'erreur alors c'est réussi », qui
     détecte à tort toute panne réseau ou page d'erreur du serveur.
  6. Arrêt propre (break) et conservation du résultat, au lieu de exit() qui
     interrompt brutalement et perd les informations.

Utilisation :
    python3 bruteforcessh.py -u http://127.0.0.1:8080/login -U admin \
        -l login -p pass -d 0.2 -k 200
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import requests

DICTIONARY_DEFAUT = "dico.txt"
MESSAGE_ECHEC_DEFAUT = "Mot de passe invalide"


def charger_dictionnaire(chemin: str, limite: int | None) -> list[str]:
    """Une ligne = un mot de passe. Les lignes vides sont ignorées."""
    fichier = Path(chemin)
    if not fichier.is_file():
        raise FileNotFoundError(f"Dictionnaire introuvable : {chemin}")
    mots: list[str] = []
    with fichier.open(encoding="utf-8", errors="replace") as f:
        for ligne in f:
            mot = ligne.strip()
            if not mot:
                continue
            mots.append(mot)
            if limite and len(mots) >= limite:
                break
    return mots


def main() -> int:
    analyseur = argparse.ArgumentParser(description="Essai de mots de passe, version simplifiée.")
    analyseur.add_argument("-u", "--url", required=True, help="URL de la page de connexion")
    analyseur.add_argument("-U", "--user", required=True, help="identifiant à tester")
    analyseur.add_argument("-l", "--login-field", default="login", help="nom du champ identifiant")
    analyseur.add_argument("-p", "--password-field", default="pass", help="nom du champ mot de passe")
    analyseur.add_argument("-w", "--dictionary", default=DICTIONARY_DEFAUT, help="fichier de mots de passe")
    analyseur.add_argument("-d", "--delay", type=float, default=0.5, help="délai entre deux essais (s)")
    analyseur.add_argument("-k", "--max-attempts", type=int, default=None, help="nombre maximum d'essais")
    analyseur.add_argument("-t", "--timeout", type=float, default=10.0, help="délai d'attente réseau (s)")
    analyseur.add_argument("-m", "--method", choices=["GET", "POST"], default="POST", help="méthode HTTP")
    analyseur.add_argument("-f", "--failure-text", default=MESSAGE_ECHEC_DEFAUT,
                          help="texte présent dans la page quand le mot de passe est faux")
    analyseur.add_argument("-s", "--success-text", default=None,
                          help="texte présent dans la page quand la connexion réussit "
                               "(recommandé : sinon le script ne peut pas conclure)")
    args = analyseur.parse_args()

    if not args.success_text:
        print("Avertissement : sans --success-text, ce script ne peut pas distinguer une\n"
              "réussite d'une erreur du serveur. Utilisez bruteforce.py pour une détection fiable.",
              file=sys.stderr)

    try:
        mots = charger_dictionnaire(args.dictionary, args.max_attempts)
    except FileNotFoundError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1
    if not mots:
        print("Erreur : le dictionnaire ne contient aucun mot de passe.", file=sys.stderr)
        return 1

    session = requests.Session()
    donnees_fixes = {args.login_field: args.user}
    trouve = None
    debut = time.time()
    total = len(mots)
    echecs_reseau = 0

    print(f"Cible   : {args.url}")
    print(f"Compte  : {args.user}")
    print(f"Essais  : {total}\n")

    for numero, mot in enumerate(mots, start=1):
        donnees = dict(donnees_fixes)
        donnees[args.password_field] = mot

        try:
            if args.method == "GET":
                reponse = session.get(args.url, params=donnees, timeout=args.timeout)
            else:
                reponse = session.post(args.url, data=donnees, timeout=args.timeout)
        except requests.RequestException as exc:
            echecs_reseau += 1
            print(f"[{numero}/{total}] Erreur réseau ignorée : {exc}")
            if echecs_reseau >= 10:
                print("Trop d'erreurs réseau : la cible est probablement inaccessible. Arrêt.")
                return 1
            continue

        corps = reponse.text

        if args.success_text and args.success_text in corps:
            trouve = mot
            print(f"[{numero}/{total}] TROUVE : {args.user} : {mot}")
            break

        if args.failure_text and args.failure_text in corps:
            print(f"[{numero}/{total}] ECHEC : {mot}")

        if reponse.status_code == 429:
            print(f"\nBlocage de la cible après {numero} essais (HTTP 429). "
                  "C'est une protection efficace : arrêt immédiat.")
            break

        if args.delay > 0 and numero < total:
            time.sleep(args.delay)

    duree = time.time() - debut
    print("\n" + "-" * 52)
    print(f"Durée : {duree:.1f} s")
    if trouve:
        print(f"Mot de passe trouvé : {args.user} : {trouve}")
        return 0
    if args.success_text:
        print("Aucun mot de passe trouvé dans le dictionnaire fourni.")
        return 2
    print("Résultat indéterminé : le motif de réussite n'a pas été fourni.")
    return 3


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrompu par l'utilisateur.")
        raise SystemExit(130)
