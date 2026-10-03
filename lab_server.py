#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Serveur de laboratoire — formulaire de connexion volontairement vulnérable.

But pédagogique : fournir une cible hors ligne et sans risque pour s'entraîner
sur bruteforce.py. Ne dépend que de la bibliothèque standard.

    python3 lab_server.py --port 8080
    python3 lab_server.py --port 8080 --lockout 8   (démonstration de la protection)

Le compte de laboratoire par défaut est  admin / Lab2024!

Quatre profils reproduisent la façon dont les applications de Metasploitable2
répondent, pour s'entraîner hors ligne avant de viser la vraie VM :

    --profil interne      intranet d'entreprise (comportement par défaut)
    --profil dvwa         DVWA : jeton de session, échec 200, réussite 302
    --profil wordpress    WordPress : champs log/pwd, testcookie, réussite 302
    --profil mutillidae   Mutillidae : la connexion accepte n'importe quoi

Le profil `dvwa` est volontairement plus strict que le profil par défaut : le
jeton `user_token` est lié à la session et vérifié à chaque essai, exactement
comme dans DVWA. Sans `--refresh-csrf`, l'outil voit donc des échecs.
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

PAGE_STYLE = """
    :root { color-scheme: light dark; }
    * { box-sizing: border-box; }
    body {
        margin: 0; min-height: 100vh; display: flex; align-items: center;
        justify-content: center; font-family: system-ui, "Segoe UI", sans-serif;
        background: linear-gradient(135deg, #1e293b, #0f172a); color: #e2e8f0;
    }
    .card {
        width: min(420px, 92vw); background: #1e293b; border: 1px solid #334155;
        border-radius: 14px; padding: 28px 30px;
        box-shadow: 0 18px 50px rgba(0, 0, 0, .45);
    }
    h1 { margin: 0 0 4px; font-size: 20px; }
    .sub { margin: 0 0 22px; color: #94a3b8; font-size: 13px; }
    label { display: block; font-size: 13px; margin: 14px 0 6px; color: #cbd5e1; }
    input {
        width: 100%; padding: 10px 12px; border-radius: 8px;
        border: 1px solid #475569; background: #0f172a; color: #f1f5f9; font-size: 14px;
    }
    input:focus { outline: 2px solid #38bdf8; outline-offset: 1px; }
    button {
        width: 100%; margin-top: 22px; padding: 11px; border: 0; border-radius: 8px;
        background: #38bdf8; color: #082f49; font-weight: 700; font-size: 15px; cursor: pointer;
    }
    button:hover { background: #7dd3fc; }
    .msg { padding: 11px 13px; border-radius: 8px; font-size: 13px; margin-bottom: 8px; }
    .err { background: #450a0a; border: 1px solid #b91c1c; color: #fecaca; }
    .ok  { background: #052e16; border: 1px solid #15803d; color: #bbf7d0; }
    .warn{ background: #422006; border: 1px solid #b45309; color: #fde68a; }
    .hint { margin-top: 20px; font-size: 12px; color: #64748b; line-height: 1.6; }
    code { background: #0f172a; padding: 1px 5px; border-radius: 4px; color: #7dd3fc; }
    table { width: 100%; font-size: 13px; border-collapse: collapse; margin-top: 8px; }
    th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid #334155; }
    th { color: #94a3b8; font-weight: 600; }
"""

LOGIN_FORM = """<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{titre} — Connexion</title><style>{style}</style></head>
<body><div class="card">
<h1>{titre}</h1>
<p class="sub">{sous_titre}</p>
{message}
<form method="post" action="{action}">
  <input type="hidden" name="{nom_token}" value="{token}">
  <label for="{nom_login}">Identifiant</label>
  <input id="{nom_login}" name="{nom_login}" type="text" value="{login}" autocomplete="off" autofocus>
  <label for="{nom_mot_de_passe}">Mot de passe</label>
  <input id="{nom_mot_de_passe}" name="{nom_mot_de_passe}" type="password" autocomplete="off">
  <button type="submit">Se connecter</button>
</form>
<p class="hint">{aide}</p>
</div></body></html>"""

DASHBOARD = """<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Intranet Lab — Espace connecté</title><style>{style}</style></head>
<body><div class="card">
<h1>Bienvenue {user}</h1>
<p class="sub">Connexion réussie — tableau de bord de démonstration</p>
<div class="msg ok">Authentification réussie. Session ouverte à {time}.</div>
<table>
<tr><th>Article</th><th>Quantité</th><th>Prix</th></tr>
<tr><td>Clavier mecanique</td><td>2</td><td>89.00 EUR</td></tr>
<tr><td>Ecran 27 pouces</td><td>1</td><td>249.00 EUR</td></tr>
<tr><td>Cable reseau 10m</td><td>5</td><td>12.00 EUR</td></tr>
</table>
<p class="hint">Document confidentiel — ne pas diffuser hors du laboratoire.</p>
</div></body></html>"""

LOCKED_PAGE = """<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<title>Intranet Lab — Compte temporairement bloque</title><style>{style}</style></head>
<body><div class="card">
<h1>Trop de tentatives</h1>
<div class="msg err">Compte temporairement bloque suite a trop de tentatives de connexion.</div>
<p class="sub">Cette protection a arrete l'outil de brute force. C'est le comportement attendu
d'une application correctement configuree.</p>
<p class="hint">Relancez le serveur avec <code>--lockout 0</code> pour desactiver la protection.</p>
</div></body></html>"""

BASIC_CHALLENGE = """<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<title>{titre}</title><style>{style}</style></head>
<body><div class="card">
<h1>{titre}</h1>
<p class="sub">{sous_titre}</p>
<div class="msg warn">Authentification HTTP Basic demandee : aucun formulaire n'est
present sur cette page.</div>
<p class="hint">{aide}</p>
</div></body></html>"""


@dataclass(frozen=True)
class Profil:
    """Reproduit la maniere dont une application repond a une tentative."""

    cle: str
    titre: str
    sous_titre: str
    chemin: str                       # route du formulaire, comme sur la vraie appli
    champ_login: str
    champ_mot_de_passe: str
    champ_token: str                  # nom du champ cache
    message_echec: str
    redirection: str                  # cible du 302 apres succes ("" = page directement)
    cookie: str
    identifiant: str
    mot_de_passe: str
    verifie_token: bool = False
    accepte_tout: bool = False
    aide: str = ""
    page_apres: str = "/dashboard"
    authentification: str = "form"     # "form" ou "basic"
    realm: str = ""                    # realm annonce dans WWW-Authenticate


PROFILS: Dict[str, Profil] = {
    "interne": Profil(
        cle="interne",
        titre="Intranet Lab",
        sous_titre="Serveur de laboratoire — authentification",
        chemin="/login",
        champ_login="login",
        champ_mot_de_passe="pass",
        champ_token="csrf_token",
        message_echec="Mot de passe invalide pour cet identifiant.",
        redirection="",
        cookie="lab_session",
        identifiant="admin",
        mot_de_passe="Lab2024!",
        aide="Champs du formulaire : <code>login</code>, <code>pass</code>, "
             "<code>csrf_token</code> (caché).<br>"
             "Cette page est volontairement faible : c'est une cible d'entraînement.",
    ),
    "dvwa": Profil(
        cle="dvwa",
        titre="DVWA — Damn Vulnerable Web Application",
        sous_titre="Émulation locale — formulaire de connexion de DVWA",
        chemin="/dvwa/login.php",
        champ_login="username",
        champ_mot_de_passe="password",
        champ_token="user_token",
        message_echec="Login failed",
        redirection="/dvwa/index.php",
        cookie="PHPSESSID",
        identifiant="admin",
        mot_de_passe="password",
        verifie_token=True,
        aide="Reproduction du comportement de DVWA : le champ caché "
             "<code>user_token</code> est lié à la session (<code>PHPSESSID</code>) "
             "et vérifié à chaque essai, l'échec renvoie HTTP 200 avec "
             "<code>Login failed</code>, la réussite une redirection 302.<br>"
             "Sans <code>--refresh-csrf</code>, un seul essai peut aboutir : "
             "les suivants sont rejetés pour jeton périmé.",
        page_apres="/dvwa/index.php",
    ),
    "wordpress": Profil(
        cle="wordpress",
        titre="WordPress — connexion",
        sous_titre="Émulation locale — formulaire wp-login.php",
        chemin="/wp-login.php",
        champ_login="log",
        champ_mot_de_passe="pwd",
        champ_token="redirect_to",
        message_echec="ERROR: The password you entered for the username "
                      "you may have registered is incorrect.",
        redirection="/wp-admin/",
        cookie="wordpress_logged_in",
        identifiant="admin",
        mot_de_passe="admin",
        aide="Reproduction du comportement de WordPress : les champs sont "
             "<code>log</code> et <code>pwd</code>, l'échec renvoie HTTP 200 avec "
             "le message « ERROR: ... », la réussite une redirection 302 vers "
             "<code>/wp-admin/</code>.",
        page_apres="/wp-admin/",
    ),
    "mutillidae": Profil(
        cle="mutillidae",
        titre="Mutillidae — connexion",
        sous_titre="Émulation locale — connexion volontairement ouverte",
        chemin="/mutillidae/index.php",
        champ_login="username",
        champ_mot_de_passe="password",
        champ_token="user_token",
        message_echec="Invalid credentials or invalid username/password combination.",
        redirection="/mutillidae/index.php?page=home.php",
        cookie="PHPSESSID",
        identifiant="admin",
        mot_de_passe="admin",
        verifie_token=True,
        accepte_tout=True,
        aide="Mutillidae n'est pas une cible de brute force : son formulaire "
             "accepte <em>n'importe quel</em> couple identifiant/mot de passe. "
             "Le premier essai réussit, ce qui suffit à le démontrer.",
        page_apres="/mutillidae/index.php",
    ),
    "phpmyadmin": Profil(
        cle="phpmyadmin",
        titre="phpMyAdmin — connexion",
        sous_titre="Émulation locale — formulaire d'accès à MySQL",
        chemin="/phpmyadmin/index.php",
        champ_login="pma_username",
        champ_mot_de_passe="pma_password",
        champ_token="token",
        message_echec="Cannot log in to the MySQL database.",
        redirection="/phpmyadmin/index.php?route=/",
        cookie="phpMyAdmin",
        identifiant="root",
        mot_de_passe="toor",
        aide="Reproduction du comportement de phpMyAdmin : les champs ne sont "
             "pas <code>username</code> / <code>password</code> mais "
             "<code>pma_username</code> et <code>pma_password</code>, et la page "
             "ne présente pas de champ mot de passe de type "
             "<code>password</code> classique à sa racine.<br>"
             "Sur Metasploitable2, phpMyAdmin écoute sur le port 8080.",
        page_apres="/phpmyadmin/index.php?route=/",
    ),
    "webgoat": Profil(
        cle="webgoat",
        titre="WebGoat — connexion",
        sous_titre="Émulation locale — accès aux leçons",
        chemin="/webgoat/login",
        champ_login="username",
        champ_mot_de_passe="password",
        champ_token="csrf",
        message_echec="Invalid credentials",
        redirection="/webgoat/lesson/0",
        cookie="JSESSIONID",
        identifiant="webgoat",
        mot_de_passe="webgoat",
        verifie_token=True,
        aide="Reproduction du comportement de WebGoat : l'échec renvoie "
             "<code>Invalid credentials</code>, la réussite une redirection 302 "
             "vers la première leçon.",
        page_apres="/webgoat/lesson/0",
    ),
    "tomcat": Profil(
        cle="tomcat",
        titre="Apache Tomcat Manager",
        sous_titre="Émulation locale — authentification HTTP Basic",
        chemin="/manager/html",
        champ_login="username",
        champ_mot_de_passe="password",
        champ_token="",
        message_echec="",
        redirection="",
        cookie="JSESSIONID",
        identifiant="tomcat",
        mot_de_passe="tomcat",
        # le vrai Tomcat annonce ce realm dans son en-tete 401
        realm="Tomcat Manager Application",
        aide="Aucune page de connexion ici : Tomcat demande une "
             "<em>authentification HTTP Basic</em>. Le serveur répond 401 avec "
             "l'en-tête <code>WWW-Authenticate</code>, et chaque requête doit "
             "porter les identifiants dans l'en-tête "
             "<code>Authorization: Basic ...</code>.<br>"
             "Il faut donc l'option <code>--basic-auth</code> de l'outil, et non "
             "des noms de champs. Sur Metasploitable2, Tomcat écoute sur le "
             "port 8080.",
        page_apres="/manager/status",
        authentification="basic",
    ),
}


class LabState:
    def __init__(self, profil: Profil, login: str, password: str, lockout: int,
                 latency: float) -> None:
        self.profil = profil
        self.login = login
        self.password = password
        self.lockout = lockout
        self.latency = latency
        self.attempts: Dict[str, int] = {}
        self.blocked: Dict[str, bool] = {}
        self.total = 0
        self.sessions: Dict[str, str] = {}
        self.jetons: Dict[str, str] = {}
        self.lock = threading.Lock()

    def register_failure(self, user: str) -> Tuple[int, bool]:
        with self.lock:
            self.total += 1
            count = self.attempts.get(user, 0) + 1
            self.attempts[user] = count
            if self.lockout and count >= self.lockout:
                self.blocked[user] = True
            return count, self.blocked.get(user, False)

    def note_success(self, user: str) -> None:
        with self.lock:
            self.total += 1
            self.attempts.pop(user, None)
            self.blocked[user] = False

    def ouvrir_session(self, user: str) -> str:
        """Cree un identifiant de session et le jeton de formulaire associe."""
        session_id = secrets.token_hex(16)
        with self.lock:
            self.sessions[session_id] = user
        return session_id

    def session_connue(self, session_id: Optional[str]) -> bool:
        with self.lock:
            return bool(session_id) and session_id in self.jetons

    def jeton_pour(self, session_id: str) -> str:
        """Renvoie un jeton neuf pour cette session (comme PHP a chaque affichage)."""
        with self.lock:
            jeton = secrets.token_hex(8)
            self.jetons[session_id] = jeton
            return jeton

    def jeton_valide(self, session_id: Optional[str], fourni: str) -> bool:
        if not self.profil.verifie_token:
            return True
        with self.lock:
            attendu = self.jetons.get(session_id or "")
        return bool(attendu) and secrets.compare_digest(attendu, fourni or "")


class Handler(BaseHTTPRequestHandler):
    server_version = "LabServer/1.0"
    protocol_version = "HTTP/1.1"
    state: LabState

    def log_message(self, fmt: str, *args: object) -> None:
        sys_out = getattr(self.server, "quiet", False)
        if not sys_out:
            stamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{stamp}] {self.address_string()} {fmt % args}")

    def send_page(self, body: str, status: int = 200,
                  cookie: Optional[str] = None,
                  entetes: Optional[Dict[str, str]] = None) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        for nom, valeur in (entetes or {}).items():
            self.send_header(nom, valeur)
        self.end_headers()
        self.wfile.write(payload)

    def send_redirect(self, location: str, cookie: Optional[str] = None) -> None:
        """Repond 302 comme le font DVWA et WordPress apres une reussite."""
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def render_login(self, message: str = "", kind: str = "", login: str = "",
                     token: str = "", status: int = 200,
                     cookie: Optional[str] = None) -> None:
        profil = self.state.profil
        block = f'<div class="msg {kind}">{html.escape(message)}</div>' if message else ""
        self.send_page(
            LOGIN_FORM.format(
                style=PAGE_STYLE, titre=html.escape(profil.titre),
                sous_titre=html.escape(profil.sous_titre),
                message=block, action=profil.chemin,
                nom_login=profil.champ_login, nom_mot_de_passe=profil.champ_mot_de_passe,
                nom_token=profil.champ_token, token=html.escape(token),
                login=html.escape(login), aide=profil.aide),
            status=status, cookie=cookie,
        )

    def session(self) -> Optional[str]:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            return None
        morsel = jar.get(self.state.profil.cookie)
        return morsel.value if morsel else None

    def session_pour_formulaire(self) -> Tuple[str, Optional[str]]:
        """Renvoie (identifiant de session, cookie a poser). Le second est None
        si le client avait deja une session connue, et garde donc son jeton."""
        courante = self.session()
        if self.state.session_connue(courante):
            assert courante is not None
            return courante, None
        session_id = secrets.token_hex(16)
        cookie = (f"{self.state.profil.cookie}={session_id}; Path=/; HttpOnly")
        return session_id, cookie

    def cookie_session(self) -> Optional[str]:
        return self.session()

    def send_json(self, payload: dict, status: int = 200) -> None:
        corps = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(corps)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(corps)

    def lire_corps(self) -> str:
        """Lit et vide le corps de la requête.

        Indispensable : sur une connexion TCP réutilisée (keep-alive), un corps
        non consommé est réinterprété comme la ligne d'état de la requête
        suivante, qui répond alors « 501 Unsupported method ». Ce problème
        n'apparaît pas avec curl, qui ferme la connexion à chaque appel.
        """
        try:
            longueur = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            longueur = 0
        if longueur <= 0:
            return ""
        return self.rfile.read(longueur).decode("utf-8", "replace")

    def api_login(self, brut: Optional[str] = None) -> None:
        """Point d'entrée JSON, pour exercer le mode -T json de l'outil."""
        if brut is None:
            brut = self.lire_corps()
        try:
            donnees = json.loads(brut) if brut.strip() else {}
        except json.JSONDecodeError:
            self.send_json({"status": "erreur", "message": "JSON invalide"}, 400)
            return
        if not isinstance(donnees, dict):
            self.send_json({"status": "erreur", "message": "objet JSON attendu"}, 400)
            return

        login = str(donnees.get("login", "")).strip()
        mot_de_passe = str(donnees.get("pass", ""))

        if self.state.latency:
            time.sleep(self.state.latency)

        if not login or not mot_de_passe:
            self.send_json({"status": "erreur", "message": "champs manquants"}, 400)
            return

        with self.state.lock:
            deja_bloque = self.state.blocked.get(login, False)
        if deja_bloque:
            self.send_json({"status": "bloque",
                            "message": "compte temporairement bloque"}, 429)
            return

        if login == self.state.login and mot_de_passe == self.state.password:
            self.state.note_success(login)
            jeton = secrets.token_hex(16)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] *** CONNEXION REUSSIE (API) : {login} ***")
            self.send_json({"status": "ok", "utilisateur": login, "jeton": jeton,
                            "message": "connexion reussie"})
            return

        count, blocked = self.state.register_failure(login)
        if blocked:
            self.send_json({"status": "bloque",
                            "message": "compte temporairement bloque"}, 429)
            return
        self.send_json({"status": "echec", "message": "mot de passe invalide",
                        "tentatives_restantes": max(0, self.state.lockout - count)
                        if self.state.lockout else None}, 401)

    def do_GET(self) -> None:
        profil = self.state.profil
        route = urlparse(self.path).path.rstrip("/") or "/"
        requete = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        envoye = {k: v[0] for k, v in requete.items()}
        if profil.authentification == "basic" and route in (profil.chemin.rstrip("/"), "/"):
            self.serve_basic()
            return
        if route == "/" and profil.chemin != "/" and profil.authentification != "basic":
            # sans cela, un debutant qui vise la racine conclut a tort
            # qu'il n'y a aucun formulaire a tester. En Basic, la racine
            # reste la cible : c'est elle qui renvoie le 401 attendu.
            self.send_redirect(profil.chemin)
            return
        if route == profil.chemin.rstrip("/") or (
                route == "/" and profil.chemin in ("/", "/login")):
            route = profil.chemin
        elif route == profil.page_apres:
            self.serve_page_apres()
            return

        if route == profil.chemin:
            if self.state.latency:
                time.sleep(self.state.latency)
            if profil.champ_login in envoye and profil.champ_mot_de_passe in envoye:
                self.authentifier(envoye[profil.champ_login],
                                  envoye[profil.champ_mot_de_passe], None, None,
                                  "Identifiants transmis en GET : ils apparaissent dans "
                                  "l'historique, les journaux et l'en-tete Referer.")
                return
            session_id, cookie = self.session_pour_formulaire()
            self.render_login(token=self.state.jeton_pour(session_id), cookie=cookie)
        elif route == "/dashboard" and profil.chemin == "/login":
            session_id = self.cookie_session()
            with self.state.lock:
                user = self.state.sessions.get(session_id or "")
            if user:
                self.send_page(DASHBOARD.format(
                    style=PAGE_STYLE, user=html.escape(user),
                    time=datetime.now().strftime("%H:%M:%S")))
            else:
                self.render_login("Session expiree, veuillez vous reconnecter.",
                                  "warn", status=401)
        elif route == "/health":
            with self.state.lock:
                payload = f'{{"status":"ok","profil":"{profil.cle}",' \
                          f'"tentatives":{self.state.total},' \
                          f'"identifiants_bloques":{len(self.state.blocked)}}}'
            self.send_page(payload, 200)
        elif route == "/stats":
            with self.state.lock:
                rows = "".join(
                    f"<tr><td>{html.escape(u)}</td><td>{c}</td>"
                    f"<td>{'bloque' if self.state.blocked.get(u) else 'actif'}</td></tr>"
                    for u, c in sorted(self.state.attempts.items(), key=lambda kv: -kv[1])
                ) or "<tr><td colspan=3>aucune tentative</td></tr>"
            self.send_page(f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<title>Statistiques</title><style>{PAGE_STYLE}</style></head><body><div class="card">
<h1>Statistiques du laboratoire</h1><p class="sub">Total des requetes recues : {self.state.total}</p>
<table><tr><th>Identifiant</th><th>Essais</th><th>Etat</th></tr>{rows}</table>
</div></body></html>""")
        else:
            self.send_page("<h1>404</h1>", 404)

    def do_POST(self) -> None:
        profil = self.state.profil
        route = urlparse(self.path).path.rstrip("/") or "/"
        # le corps doit toujours être consommé, sinon la requête suivante
        # de la même connexion est mal interprétée par le serveur
        corps = self.lire_corps()
        if profil.authentification == "basic" and route in (profil.chemin.rstrip("/"), "/"):
            self.serve_basic()
            return
        if route == "/api/login" and profil.chemin == "/login":
            self.api_login(corps)
            return
        if route == profil.chemin.rstrip("/"):
            route = profil.chemin
        if route != profil.chemin:
            self.send_page("<h1>404</h1>", 404)
            return

        form = {k: v[0] for k, v in parse_qs(corps, keep_blank_values=True).items()}
        login = form.get(profil.champ_login, "").strip()
        password = form.get(profil.champ_mot_de_passe, "")
        jeton = form.get(profil.champ_token, "")

        if self.state.latency:
            time.sleep(self.state.latency)

        if not login or not password:
            self.render_login("Champs obligatoires manquants.", "err", login,
                              token=self.state.jeton_pour(self.session_pour_formulaire()[0]))
            return

        if not self.state.jeton_valide(self.session(), jeton):
            # comme DVWA : jeton absent ou perime, la tentative est rejetee
            # sans compter comme un echec d'authentification
            session_id, cookie = self.session_pour_formulaire()
            self.render_login(profil.message_echec, "err", login,
                              token=self.state.jeton_pour(session_id), cookie=cookie)
            return

        self.authentifier(login, password)

    def identifiants_basic(self) -> Optional[Tuple[str, str]]:
        """Decode l'en-tete Authorization: Basic, comme Tomcat l'attend."""
        brut = self.headers.get("Authorization") or ""
        parties = brut.split(None, 1)
        if len(parties) != 2 or parties[0].lower() != "basic":
            return None
        try:
            decodé = base64.b64decode(parties[1]).decode("utf-8", "replace")
        except (ValueError, TypeError):
            return None
        login, separateur, password = decodé.partition(":")
        if not separateur:
            return None
        return login, password

    def defi_basic(self) -> Dict[str, str]:
        profil = self.state.profil
        return {"WWW-Authenticate": f'Basic realm="{profil.realm or profil.titre}"'}

    def serve_basic(self) -> None:
        """Repond comme une ressource protegee en authentification Basic."""
        profil = self.state.profil
        defi = self.defi_basic()
        if self.state.latency:
            time.sleep(self.state.latency)

        couple = self.identifiants_basic()
        if couple is None:
            self.send_page(BASIC_CHALLENGE.format(
                style=PAGE_STYLE, titre=html.escape(profil.titre),
                sous_titre=html.escape(profil.sous_titre), aide=profil.aide),
                401, entetes=defi)
            return

        login, password = couple
        with self.state.lock:
            deja_bloque = self.state.blocked.get(login, False)
        if deja_bloque:
            self.send_page(LOCKED_PAGE.format(style=PAGE_STYLE), 429, entetes=defi)
            return

        if login == self.state.login and password == self.state.password:
            self.state.note_success(login)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"*** CONNEXION REUSSIE (Basic) : {login} ***")
            self.send_page(DASHBOARD.format(
                style=PAGE_STYLE, user=html.escape(login),
                time=datetime.now().strftime("%H:%M:%S")), 200)
            return

        count, blocked = self.state.register_failure(login)
        if blocked:
            self.send_page(LOCKED_PAGE.format(style=PAGE_STYLE), 429, entetes=defi)
            return
        restant = f" Il vous reste {self.state.lockout - count} essai(s)." if self.state.lockout else ""
        self.send_page(BASIC_CHALLENGE.format(
            style=PAGE_STYLE, titre=html.escape(profil.titre),
            sous_titre=html.escape(profil.sous_titre),
            aide=profil.aide + "<br>Echec " + str(count) + "." + restant),
            401, entetes=defi)

    def serve_page_apres(self) -> None:
        """Page « apres connexion » : accessible seulement avec une session."""
        profil = self.state.profil
        session_id = self.cookie_session()
        with self.state.lock:
            user = self.state.sessions.get(session_id or "")
        if not user:
            self.send_redirect(profil.chemin)
            return
        self.send_page(DASHBOARD.format(
            style=PAGE_STYLE, user=html.escape(user),
            time=datetime.now().strftime("%H:%M:%S")))

    def authentifier(self, login: str, password: str, *annonce: object) -> None:
        """Logique d'authentification commune aux requêtes GET et POST."""
        profil = self.state.profil
        if len(annonce) >= 3 and annonce[2]:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {annonce[2]}")

        with self.state.lock:
            deja_bloque = self.state.blocked.get(login, False)

        if deja_bloque:
            self.send_page(LOCKED_PAGE.format(style=PAGE_STYLE), 429)
            return

        accepte = (login == self.state.login and password == self.state.password) \
            or profil.accepte_tout
        if accepte:
            self.state.note_success(login)
            session_id = self.state.ouvrir_session(login)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] *** CONNEXION REUSSIE : {login} ***")
            cookie = f"{profil.cookie}={session_id}; Path=/; HttpOnly"
            if profil.redirection:
                # DVWA et WordPress repondent par une redirection 302
                self.send_redirect(profil.redirection, cookie=cookie)
            else:
                self.send_page(
                    DASHBOARD.format(style=PAGE_STYLE, user=html.escape(login),
                                     time=datetime.now().strftime("%H:%M:%S")),
                    cookie=cookie,
                )
            return

        count, blocked = self.state.register_failure(login)
        if blocked:
            self.send_page(LOCKED_PAGE.format(style=PAGE_STYLE), 429)
            return

        if self.state.latency:
            time.sleep(self.state.latency)
        restant = f" Il vous reste {self.state.lockout - count} essai(s)." if self.state.lockout else ""
        session_id, cookie = self.session_pour_formulaire()
        self.render_login(f"{profil.message_echec}{restant}", "err", login,
                          token=self.state.jeton_pour(session_id),
                          status=401 if not profil.redirection else 200,
                          cookie=cookie)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Serveur de laboratoire avec formulaire de connexion vulnérable "
                    "(usage pédagogique local).")
    parser.add_argument("--host", default="127.0.0.1", help="adresse d'écoute (défaut : 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="port d'écoute (défaut : 8080)")
    parser.add_argument("--profil", choices=sorted(PROFILS), default="interne",
                        help="comportement de la cible (défaut : interne)")
    parser.add_argument("--user", default=None,
                        help="identifiant valide (défaut : celui du profil)")
    parser.add_argument("--password", default=None,
                        help="mot de passe valide (défaut : celui du profil)")
    parser.add_argument("--lockout", type=int, default=0,
                        help="bloquer le compte après N échecs (0 = désactivé, défaut : 0)")
    parser.add_argument("--latency", type=float, default=0.0,
                        help="délai artificiel par requête en secondes")
    parser.add_argument("--quiet", action="store_true", help="réduire la verbosité")
    args = parser.parse_args()

    profil = PROFILS[args.profil]
    identifiant = args.user or profil.identifiant
    mot_de_passe = args.password or profil.mot_de_passe

    if args.host not in ("127.0.0.1", "::1", "localhost"):
        print(f"ATTENTION : écoute sur {args.host}, le laboratoire devient accessible au réseau local.")

    Handler.state = LabState(profil, identifiant, mot_de_passe, args.lockout, args.latency)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.quiet = args.quiet

    print("=" * 62)
    print("  Serveur de laboratoire — cible d'entraînement BruteForceLab")
    print("=" * 62)
    print(f"  Adresse      : http://{args.host}:{args.port}/login")
    print(f"  Compte       : {identifiant} / {mot_de_passe}")
    if profil.cle != "interne":
        print(f"  Profil       : {profil.cle} ({profil.champ_login} / "
              f"{profil.champ_mot_de_passe}, jeton {profil.champ_token})")
        print(f"  Formulaire   : http://{args.host}:{args.port}{profil.chemin}")
        if profil.accepte_tout:
            print("  Attention    : ce profil accepte n'importe quel mot de passe "
                  "(démonstration d'une absence de contrôle).")
    print(f"  Verrouillage : {'désactivé' if not args.lockout else f'après {args.lockout} échecs'}")
    print(f"  Statistiques : http://{args.host}:{args.port}/stats")
    print("  Arrêt        : Ctrl+C")
    print("=" * 62)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt du serveur.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
