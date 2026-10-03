#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Inspecteur de formulaire — l'outil à utiliser avant tout essai de mots de passe.

La version initiale de ce fichier était inutilisable : les variables `user` et
`passwd` étaient définies dans une boucle et nConservaient que la DERNIÈRE
valeur lue, puis étaient réutilisées hors de la boucle. Le dictionnaire était
chargé deux fois (`passwdlist = loginlist`). Ce fichier remet le principe en
place et ajoute ce qui manque pour comprendre une page de connexion :

  - le code HTTP, l'URL finale après redirection et la taille de la réponse ;
  - la liste des formulaires et de leurs champs ;
  - la comparaison entre la réponse d'un mot de passe FAUX et celle d'un mot de
    passe VALIDE, qui est la question centrale de toute détection de succès.

Utilisation :
    python3 test.py -u http://127.0.0.1:8080/login -U admin
    python3 test.py -u http://127.0.0.1:8080/login -U admin -P 'LeBonMotDePasse'
"""

from __future__ import annotations

import argparse
import re
import sys
from html.parser import HTMLParser
from typing import List, Optional, Tuple
from urllib.parse import urljoin

import requests

CHAMPS_IGNORE = ("submit", "button", "image", "reset", "file", "checkbox", "radio")
JETONS = ("csrf", "xsrf", "token", "nonce", "authenticity", "captcha", "g-recaptcha")
INDICES_LOGIN = ("login", "user", "utilisateur", "mail", "email", "account", "compte",
                 "ident", "auth", "pseudo", "name")
INDICES_MDP = ("pass", "pwd", "mdp", "motdepasse", "secret")


class LecteurFormulaire(HTMLParser):
    """Extrait les formulaires et leurs champs sans dépendance externe."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.formulaires: List[Tuple[str, str, List[Tuple[str, str, str]]]] = []
        self._actuel: Optional[Tuple[str, str, List[Tuple[str, str, str]]]] = None

    def handle_starttag(self, balise: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        donnees = {cle.lower(): (valeur or "") for cle, valeur in attrs}
        if balise == "form":
            self._actuel = (donnees.get("action", ""), donnees.get("method", "get").upper(), [])
        elif self._actuel is not None and balise in ("input", "button", "textarea", "select"):
            nom = donnees.get("name", "")
            if nom:
                self._actuel[2].append((nom, donnees.get("type", balise).lower(),
                                        donnees.get("value", "")))

    def handle_endtag(self, balise: str) -> None:
        if balise == "form" and self._actuel is not None:
            self.formulaires.append(self._actuel)
            self._actuel = None

    def close(self) -> None:
        super().close()
        if self._actuel is not None:
            self.formulaires.append(self._actuel)
            self._actuel = None


def noter_champ(nom: str, indices: tuple[str, ...]) -> int:
    """Attribue un score à un nom de champ pour un rôle donné."""
    minuscule = nom.lower()
    score = 0
    for position, indice in enumerate(indices):
        if indice in minuscule:
            score += len(indices) - position
    return score


def deviner_champs(champs: list[tuple[str, str, str]]) -> tuple[str, str]:
    """Retrouve le champ identifiant et le champ mot de passe.

    Les champs cachés et les jetons (CSRF, CAPTCHA) sont écartés : ce ne sont
    pas des identifiants, les confondre revient à renvoyer un jeton à la place
    du nom d'utilisateur.
    """
    candidats = [(nom, type_champ) for nom, type_champ, _ in champs
                 if type_champ not in CHAMPS_IGNORE
                 and not any(jeton in nom.lower() for jeton in JETONS)]
    if not candidats:
        return "login", "pass"

    mot_de_passe = [nom for nom, type_champ in candidats if type_champ == "password"]
    if not mot_de_passe:
        scores = [(noter_champ(nom, INDICES_MDP), nom) for nom, _ in candidats]
        scores.sort(reverse=True)
        return (max(((noter_champ(n, INDICES_LOGIN), n) for n, _ in candidats))[1],
                scores[0][1] if scores[0][0] else "pass")

    champ_mdp = mot_de_passe[0]
    reste = [(nom, type_champ) for nom, type_champ in candidats
             if type_champ != "password"]
    if not reste:
        return "login", champ_mdp
    champ_login = max(reste, key=lambda c: noter_champ(c[0], INDICES_LOGIN))[0]
    return champ_login, champ_mdp


def decrire_reponse(etiquette: str, reponse: requests.Response) -> None:
    print(f"\n{etiquette}")
    print("-" * len(etiquette))
    print(f"  Code HTTP      : {reponse.status_code} {reponse.reason}")
    print(f"  URL finale     : {reponse.url}")
    print(f"  Redirections   : {len(reponse.history)}")
    print(f"  Type de contenu: {reponse.headers.get('Content-Type', 'inconnu')}")
    print(f"  Taille         : {len(reponse.text)} caractères")
    if reponse.history:
        for saut in reponse.history:
            print(f"    {saut.status_code} -> {saut.headers.get('Location', '(aucune)')}")
    if reponse.cookies:
        print(f"  Cookies        : {', '.join(reponse.cookies.keys())}")


def main() -> int:
    analyseur = argparse.ArgumentParser(
        description="Inspecte un formulaire de connexion et compare deux réponses.")
    analyseur.add_argument("-u", "--url", required=True, help="URL de la page de connexion")
    analyseur.add_argument("-U", "--user", required=True, help="identifiant à tester")
    analyseur.add_argument("-P", "--password", default=None,
                          help="mot de passe que l'on suppose valide (pour comparaison)")
    analyseur.add_argument("-l", "--login-field", default=None, help="forcer le nom du champ identifiant")
    analyseur.add_argument("-p", "--password-field", default=None, help="forcer le nom du champ mot de passe")
    analyseur.add_argument("-t", "--timeout", type=float, default=10.0, help="délai d'attente réseau")
    analyseur.add_argument("-m", "--method", choices=["GET", "POST"], default=None,
                          help="méthode HTTP (défaut : celle du formulaire)")
    args = analyseur.parse_args()

    session = requests.Session()
    session.headers["User-Agent"] = "FormInspector/1.0 (outil pédagogique)"

    print("=" * 60)
    print("  Inspecteur de formulaire — BruteForceLab")
    print("=" * 60)
    print(f"  URL : {args.url}")

    try:
        page = session.get(args.url, timeout=args.timeout)
    except requests.RequestException as exc:
        print(f"\nErreur : impossible de joindre {args.url}\n  {exc}")
        return 1

    decrire_reponse("1. Page de connexion", page)

    lecteur = LecteurFormulaire()
    try:
        lecteur.feed(page.text)
        lecteur.close()
    except Exception:
        pass

    formulaire = next((f for f in lecteur.formulaires
                       if any(t == "password" for _, t, _ in f[2])), None)
    devine_login, devine_mdp = ("login", "pass")
    if formulaire is not None:
        devine_login, devine_mdp = deviner_champs(formulaire[2])

    if not lecteur.formulaires:
        print("\nAucun formulaire <form> détecté : la connexion passe probablement par "
              "JavaScript. Ouvrez les outils de développement du navigateur pour le vérifier.")
    else:
        print(f"\n2. {len(lecteur.formulaires)} formulaire(s) détecté(s)")
        for index, (action, methode, champs) in enumerate(lecteur.formulaires, start=1):
            est_cible = formulaire is not None and index - 1 == lecteur.formulaires.index(formulaire)
            marque = " <-- formulaire de connexion" if est_cible else (
                " <-- contient un mot de passe" if any(t == "password" for _, t, _ in champs) else "")
            print(f"\n  Formulaire {index}{marque}")
            print(f"    action : {urljoin(page.url, action) if action else '(page courante)'}")
            print(f"    method : {methode}")
            for nom, type_champ, valeur in champs:
                if type_champ in CHAMPS_IGNORE:
                    continue
                if any(jeton in nom.lower() for jeton in JETONS):
                    role = "jeton technique"
                elif nom == devine_login:
                    role = "IDENTIFIANT"
                elif nom == devine_mdp:
                    role = "MOT DE PASSE"
                else:
                    role = "?"
                print(f"    name={nom:<20} type={type_champ:<10} rôle={role:<15} "
                      f"value={valeur[:16]}{'…' if len(valeur) > 16 else ''}")
        print("\n  Les rôles sont déduits des noms de champs : vérifiez-les toujours dans "
              "le code source de la page.")

    if formulaire is None:
        print("\nAucun formulaire de connexion exploitable automatiquement.")
        return 1

    action, methode, champs = formulaire
    cible = urljoin(page.url, action) if action else page.url
    champ_login = args.login_field or devine_login
    champ_mdp = args.password_field or devine_mdp
    methode = args.method or ("POST" if methode == "POST" else "GET")
    if methode == "GET":
        print("\n  ATTENTION : formulaire en GET, les identifiants circulent dans l'URL "
              "et restent dans les journaux du serveur et les proxys.")

    cacher = {nom: valeur for nom, type_champ, valeur in champs if type_champ == "hidden"}
    print(f"\n3. Requêtes que l'outil enverrait")
    print(f"  cible        : {cible}")
    print(f"  méthode      : {methode}")
    print(f"  champ login  : {champ_login}")
    print(f"  champ mdp    : {champ_mdp}")
    if cacher:
        print(f"  champs cachés : {', '.join(cacher)}  (à renvoyer, sinon le serveur les refuse)")

    def envoyer(mot_de_passe: str) -> Optional[requests.Response]:
        donnees = dict(cacher)
        donnees[champ_login] = args.user
        donnees[champ_mdp] = mot_de_passe
        try:
            if methode == "GET":
                return session.get(cible, params=donnees, timeout=args.timeout)
            return session.post(cible, data=donnees, timeout=args.timeout)
        except requests.RequestException as exc:
            print(f"\nErreur réseau pour le mot de passe « {mot_de_passe} » : {exc}")
            return None

    faux = envoyer("MotDePasseVolontairementFaux123")
    if faux is not None:
        decrire_reponse("4. Réponse avec un mot de passe FAUX (référence d'échec)", faux)

    if args.password:
        vrai = envoyer(args.password)
        if vrai is not None:
            decrire_reponse("5. Réponse avec le mot de passe fourni", vrai)
            print("\n6. Comparaison des deux réponses")
            print("-" * 30)
            print(f"  Code HTTP   : échec={faux.status_code}  réussite={vrai.status_code}"
                  f"   {'DIFFERENT' if faux.status_code != vrai.status_code else 'identique'}")
            print(f"  Taille      : échec={len(faux.text)}  réussite={len(vrai.text)}"
                  f"   {'DIFFERENT' if len(faux.text) != len(vrai.text) else 'identique'}")
            redirection = bool(vrai.history) or 300 <= vrai.status_code < 400
            print(f"  Redirection : échec={bool(faux.history) or 300 <= faux.status_code < 400}"
                  f"  réussite={redirection}")
            if redirection:
                print("  => La réussite se signale par une redirection : chez vous, ajoutez")
                print("     --success-on-redirect à bruteforce.py.")
            print("\n  Indices à retenir pour la détection automatique :")
            if faux.status_code != vrai.status_code:
                print("    - le code HTTP suffit à distinguer les deux cas")
            elif len(faux.text) != len(vrai.text):
                print("    - la taille de la page diffère (détection fragile, à confirmer)")
            else:
                print("    - aucun indice automatique : passez par --success-pattern")
    else:
        print("\nRelancez avec -P 'votre_mot_de_passe' pour voir la différence entre un "
              "échec et une réussite : c'est ce qui permet de régler la détection.")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrompu.")
        raise SystemExit(130)
