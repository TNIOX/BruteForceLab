#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BruteForceLab —outil pédagogique de brute force web (HTTP).

Modes disponibles :
    bruteforce.py                        interface interactive (mode pédagogique)
    bruteforce.py --inspect -u URL       inspecter un formulaire de connexion
    bruteforce.py -u URL -U admin ...    mode ligne de commande

Ce programme ne contient aucune charge utile offensive : il envoie uniquement
des requetes HTTP d'authentification classiques et s'arrete des la premiere
reussite. Voir MANUEL.md et readme.txt.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import itertools
import json
import os
import random
import re
import socket
import string
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    sys.stderr.write(
        "Le module 'requests' est requis.\n"
        "Installation :  python3 -m pip install -r requirements.txt\n"
    )
    raise SystemExit(2)

TOOL_NAME = "BruteForceLab"
VERSION = "1.0"
DEFAULT_DICTIONARY = "dico.txt"
DEFAULT_RESULTS_DIR = "resultats"
DEFAULT_USER_AGENT = f"{TOOL_NAME}/{VERSION} (outil pédagogique)"


# --------------------------------------------------------------------------
# Presentation terminal
# --------------------------------------------------------------------------

class Ui:
    """Petite couche d'affichage : couleurs ANSI, cadre, invite de saisie."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"

    def __init__(self) -> None:
        self.color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    def paint(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        return "".join(styles) + text + self.RESET

    def banner(self) -> None:
        line = "=" * 68
        print(self.paint(line, self.CYAN))
        print(self.paint(f"  {TOOL_NAME} v{VERSION} — brute force web pédagogique".ljust(66), self.BOLD, self.CYAN))
        print(self.paint(f"  Pensé pour la formation — à n'utiliser que sur une cible autorisée".ljust(66), self.DIM))
        print(self.paint(line, self.CYAN))

    def section(self, title: str) -> None:
        print()
        print(self.paint(f"── {title} " + "─" * max(0, 64 - len(title)), self.BOLD, self.BLUE))

    def info(self, text: str) -> None:
        print(f"  {self.paint('i', self.CYAN)} {text}")

    def ok(self, text: str) -> None:
        print(f"  {self.paint('+', self.GREEN)} {text}")

    def warn(self, text: str) -> None:
        print(f"  {self.paint('!', self.YELLOW)} {text}")

    def err(self, text: str) -> None:
        print(f"  {self.paint('x', self.RED)} {text}")

    def hit(self, text: str) -> None:
        print(f"  {self.paint('*', self.BOLD, self.GREEN)} {self.paint(text, self.BOLD, self.GREEN)}")

    def kv(self, key: str, value: str, width: int = 20) -> None:
        print(f"  {self.paint(key.ljust(width), self.DIM)} {value}")

    def table(self, rows: Sequence[Sequence[str]], headers: Sequence[str]) -> None:
        if not rows:
            return
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))
        sep = "  " + "-" * (sum(widths) + 2 * (len(widths) - 1))
        print(self.paint(sep, self.DIM))
        head = "  " + "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
        print(self.paint(head, self.BOLD))
        print(self.paint(sep, self.DIM))
        for row in rows:
            line = "  " + "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row))
            print(line)
        print(self.paint(sep, self.DIM))

    def ask(self, label: str, default: str = "", allow_empty: bool = False) -> str:
        suffix = self.paint(f" [{default}]", self.DIM) if default else ""
        prompt = (f"  {self.paint('?', self.BOLD, self.MAGENTA)} {self.paint(label, self.BOLD)}"
                  f"{suffix}\n    {self.paint('> ', self.MAGENTA)}")
        while True:
            try:
                answer = input(prompt)
            except EOFError:
                return default
            if not sys.stdout.isatty():
                print()
            answer = answer.strip()
            if not answer:
                if default:
                    return default
                if allow_empty:
                    return answer
                continue
            return answer

    def confirm(self, label: str, default: bool = False) -> bool:
        hint = "O/n" if default else "o/N"
        answer = self.ask(f"{label} ({self.paint(hint, self.DIM)})", "", allow_empty=True).lower()
        if not answer:
            return default
        return answer.startswith(("o", "y", "oui", "yes"))


ui = Ui()


# --------------------------------------------------------------------------
# Analyse HTML des formulaires
# --------------------------------------------------------------------------

@dataclass
class FormField:
    tag: str
    name: str
    type: str
    value: str = ""

    def is_secret(self) -> bool:
        return self.type.lower() == "password"


@dataclass
class FormInfo:
    action: str
    method: str
    fields: List[FormField] = field(default_factory=list)
    form_id: str = ""


class _FormCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: List[FormInfo] = []
        self._current: Optional[FormInfo] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        data = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current = FormInfo(
                action=data.get("action", ""),
                method=data.get("method", "get").upper(),
                form_id=data.get("id", ""),
            )
        elif tag in ("input", "button", "textarea", "select") and self._current is not None:
            name = data.get("name", "")
            if name:
                self._current.fields.append(
                    FormField(tag=tag, name=name, type=data.get("type", tag).lower(),
                              value=data.get("value", ""))
                )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None

    def close(self) -> None:  # pragma: no cover - fin de document
        super().close()
        if self._current is not None:
            self.forms.append(self._current)
            self._current = None


def parse_forms(html: str) -> List[FormInfo]:
    parser = _FormCollector()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass
    return parser.forms


LOGIN_HINTS = ("user", "login", "utilisateur", "mail", "email", "account",
               "compte", "ident", "auth", "name", "pseudo")
PASSWORD_HINTS = ("pass", "pwd", "motdepasse", "mdp", "secret")

# Noms de champs devant lesquels une valeur renvoyee par la cible doit etre
# masquee. « name » et « type » en sont volontairement absents : name="password"
# et type="password" appartiennent au balisage du formulaire, pas a l'essai.
INDICES_ECHEC = ("password", "passwd", "motdepasse", "utilisateur", "username",
                 "user", "login", "pwd", "email", "mail", "account", "compte",
                 "ident", "value")

# types de champs qui ne recoivent jamais une valeur a tester : un bouton
# "Login" porte un nom qui trompe l'heuristique, mais ce n'est pas un champ
# identifiant. DVWA illustre exactement le piege : <input type="submit"
# value="Login" name="Login"> sortait premier sur le vrai champ "username".
CHAMPS_NON_SAISISSABLES = ("submit", "button", "image", "reset", "file",
                           "checkbox", "radio")


def guess_role(field_name: str, kind: str) -> int:
    """Score un nom de champ pour le role demande (plus haut = plus probable)."""
    name = field_name.lower()
    hints = LOGIN_HINTS if kind == "login" else PASSWORD_HINTS
    score = 0
    if name == kind:
        score += 10
    for position, hint in enumerate(hints):
        if hint in name:
            score += len(hints) - position
    return score


def analyse_login_form(url: str, session: requests.Session, timeout: float,
                       verify: bool) -> Tuple[Optional[FormInfo], List[FormInfo], str]:
    """Recupere la page et designe le formulaire de connexion le plus plausible."""
    try:
        response = session.get(url, timeout=timeout, verify=verify, allow_redirects=True)
    except RequestException as exc:
        return None, [], f"Requête impossible vers {url} : {exc}"

    forms = parse_forms(response.text)
    if not forms:
        return None, [], "Aucun formulaire <form> détecté dans la page."

    for form in forms:
        if any(f.is_secret() for f in form.fields):
            target = form
            break
    else:
        target = forms[0]

    if target.action:
        target.action = urljoin(response.url, target.action)
    else:
        target.action = urljoin(response.url, response.url)
    return target, forms, ""


# --------------------------------------------------------------------------
# Empreinte de reponse et moteur de detection
# --------------------------------------------------------------------------

NOISE_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # Valeur de tous les champs de formulaire : jeton CSRF, nonce, valeur renvoyée.
    (re.compile(r"""(?i)(<(?:input|button|textarea|select)\b[^>]*?\bvalue\s*=\s*["'])[^"']*"""),
     r"\1<VALEUR>"),
    (re.compile(r'(?i)(["\']?[\w-]*(?:csrf|xsrf|authenticity)[\w-]*["\']?\s*[:=]\s*["\']?)'
                r'[^"\'&\s,;<>]{4,}'), r"\1<JETON>"),
    (re.compile(r"(?i)\b(sid|phpsessid|jsessionid|token)=[^&\s\"']+"), r"\1=<SESSION>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?\S*"), "<DATE>"),
    (re.compile(r"\b\d{10,13}\b"), "<HORODATAGE>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<EMPREINTE>"),
    (re.compile(r"(?i)\b(essai|tentative|attempt|request)\s*(n[°o]|numero|#)?\s*:?\s*\d+"),
     r"\1 <N>"),
    (re.compile(r"\b\d+\s*(secondes?|seconds?|ms|millisecondes?)\b", re.I), "<DUREE>"),
    (re.compile(r"\s+"), " "),
]


def normalize_body(text: str) -> str:
    """Neutralise les parties variables d'une page pour comparer deux reponses."""
    for pattern, replacement in NOISE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text.strip()


@dataclass(frozen=True)
class Fingerprint:
    status: int
    redirected: bool
    length: int
    digest: str
    location: str = ""

    @property
    def cluster(self) -> Tuple[int, bool, int]:
        # La longueur est groupee par tranches de 256 octets et non comparee
        # au byte pres : deux pages d'echec identiques peuvent differer de
        # quelques caracteres selon la longueur du mot de passe renvoye dans
        # la page (le vrai Mutillidae renvoie les identifiants recus). Au byte
        # pres, chaque essai paraissait etrre une page nouvelle, donc une
        # reussite.
        return (self.status, self.redirected, self.length // 256)

    def short(self) -> str:
        where = f" -> {self.location}" if self.location else ""
        return f"HTTP {self.status}{where} | {self.length} o | #{self.digest[:8]}"


def secrets_pertinents(secrets: Sequence[str]) -> List[str]:
    """Ne garde que les valeurs assez longues pour etre masquees sans degat.

    En dessous de trois caracteres, un mot de passe court revient partout dans
    une page : le masquer mutilerait le HTML au point de le rendre illisible,
    et les differences entre essais deviendraient fausses.
    """
    return [secret for secret in secrets if len(secret) >= 3]


def masque_les_valeurs(corps: str, secrets: Sequence[str]) -> str:
    """Remplace par <ESSAI> les valeurs essayees que la cible renvoie.

    Seules les valeurs Affectees a un champ d'identifiant sont remplacees :
    password='essai', username="essai", value="essai". C'est la forme que
    prennent les renvois d'un formulaire, et cela laisse intact le balisage de
    la page : name="password" et type="password" sont statiques et doivent
    rester inchanges, sinon deux echecs identiques donneraient deux
    empreintes differentes et l'outil remonterait une fausse alerte.

    Le vrai Mutillidae renvoie les identifiants recus dans sa page d'echec.
    Sans ce masque, chaque essai produit une empreinte differente et l'outil
    croit a une reussite des le premier essai.

    Une page qui renvoie un identifiant sans guillemets echappe au masque :
    l'essai est alors signale « inhabituel » plutot que « reussi », ce qui
    est le bon sens de la prudence.
    """
    cles = "|".join(INDICES_ECHEC)
    resultat = corps
    for secret in secrets_pertinents(secrets):
        motif = re.compile(r"(?i)\b(" + cles + r")(\s*=\s*)(['\"])" + re.escape(secret) + r"\3")
        resultat = motif.sub(r"\1\2\3<ESSAI>\3", resultat)
    return resultat


def fingerprint_of(response: requests.Response,
                   redactions: Sequence[str] = ()) -> Fingerprint:
    body = masque_les_valeurs(normalize_body(response.text or ""), redactions)
    digest = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()
    return Fingerprint(
        status=response.status_code,
        redirected=bool(response.history),
        length=len(body),
        digest=digest,
        location=(response.headers.get("Location") or "")[:60],
    )


class Verdict(Enum):
    SUCCESS = "SUCCES"
    FAILURE = "ECHEC"
    SUSPECT = "SUSPECT"
    LOCKED = "VERROUILLE"
    UNKNOWN = "INCONNU"


LOCKOUT_PATTERNS = (
    r"account\s+(?:is\s+)?(?:temporarily\s+)?locked",
    r"locked\s+out",
    r"too\s+many\s+(?:failed\s+)?(?:login|attempts|requests|sign)",
    r"rate\s*limit",
    r"trop\s+de\s+(?:tentatives|essais|connexions)",
    r"compte\s+(?:est\s+)?verrouill",
    r"please\s+wait\s+\d+\s*(?:second|minute)",
)
LOCKOUT_RE = re.compile("|".join(LOCKOUT_PATTERNS), re.IGNORECASE)


class DetectionEngine:
    """Decide si une reponse correspond a un echec, une reussite ou un cas limite.

    Trois strategie, de la plus fiable a la moins fiable :
      1. motifs explicites fournis par l'utilisateur (--success-pattern/--failure-pattern) ;
      2. calibration : une requête sonde sert de reference d'echec ;
      3. statistiques : le groupe de reponses le plus frequent est l'echec.
    """

    def __init__(self, success_patterns: Sequence[str], failure_patterns: Sequence[str],
                 success_on_redirect: bool, calibrated: Optional[Fingerprint] = None,
                 statistical_minimum: int = 2) -> None:
        self.success_patterns = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in success_patterns]
        self.failure_patterns = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in failure_patterns]
        self.success_on_redirect = success_on_redirect
        self.baseline = calibrated
        self.minimum = statistical_minimum
        self.clusters: Counter = Counter()
        self.digests: Counter = Counter()
        self.samples = 0
        self.unclassified = 0

    @property
    def strategy(self) -> str:
        if self.success_patterns or self.failure_patterns:
            return "motifs explicites"
        if self.baseline is not None:
            return "calibration (requete sonde)"
        return "statistique (majorite des reponses)"

    def observe(self, response: requests.Response,
                redactions: Sequence[str] = ()) -> None:
        fp = fingerprint_of(response, redactions)
        self.samples += 1
        self.clusters[fp.cluster] += 1
        self.digests[(fp.cluster, fp.digest)] += 1

    def classify(self, response: requests.Response,
                 redactions: Sequence[str] = ()) -> Verdict:
        text = response.text or ""
        fp = fingerprint_of(response, redactions)

        if response.status_code in (429, 503) or LOCKOUT_RE.search(text):
            return Verdict.LOCKED

        for pattern in self.success_patterns:
            if pattern.search(text):
                return Verdict.SUCCESS
        for pattern in self.failure_patterns:
            if pattern.search(text):
                return Verdict.FAILURE

        if self.success_on_redirect and 300 <= response.status_code < 400:
            return Verdict.SUCCESS

        if self.baseline is not None:
            if fp.cluster != self.baseline.cluster:
                return Verdict.SUCCESS
            if fp.digest != self.baseline.digest:
                return Verdict.SUSPECT
            return Verdict.FAILURE

        if self.samples < self.minimum:
            self.unclassified += 1
            return Verdict.UNKNOWN

        dominant = self.clusters.most_common(1)[0][0]
        if fp.cluster != dominant:
            return Verdict.SUCCESS
        dominant_digest = max(
            (count for (cluster, _digest), count in self.digests.items() if cluster == dominant),
            default=0,
        )
        same_digest = self.digests[(dominant, fp.digest)]
        if same_digest == dominant_digest and same_digest > 0:
            return Verdict.FAILURE
        return Verdict.SUSPECT


# --------------------------------------------------------------------------
# Cible et client HTTP
# --------------------------------------------------------------------------

@dataclass
class Target:
    url: str
    method: str = "POST"
    login_field: str = "login"
    password_field: str = "pass"
    body_type: str = "form"
    basic_auth: bool = False
    follow_redirects: bool = False
    users: List[str] = field(default_factory=list)
    extra_fields: List[Tuple[str, str]] = field(default_factory=list)
    headers: List[Tuple[str, str]] = field(default_factory=list)
    cookies: List[Tuple[str, str]] = field(default_factory=list)

    def payload(self, user: str, password: str) -> Dict[str, str]:
        if self.basic_auth:
            # en authentification Basic, les identifiants voyagent dans
            # l'en-tete Authorization, pas dans le corps de la requete
            return {}
        data: Dict[str, str] = {}
        for key, value in self.extra_fields:
            data[key] = value
        data[self.login_field] = user
        data[self.password_field] = password
        return data


def build_session(verify: bool, user_agent: str) -> requests.Session:
    session = requests.Session()
    session.verify = verify
    session.headers["User-Agent"] = user_agent
    return session


def send_auth_request(session: requests.Session, target: Target, user: str,
                      password: str, timeout: float) -> requests.Response:
    if target.basic_auth:
        # requests sends l'en-tete Authorization: Basic sur chaque requete
        session.auth = (user, password)
    data = target.payload(user, password)
    # phpMyAdmin repond 302 avec un corps vide dans les deux cas : seule la
    # page atteinte apres la redirection distingue la reussite de l'echec
    suivre = target.follow_redirects
    if target.method.upper() == "GET":
        return session.get(target.url, params=data, timeout=timeout, allow_redirects=suivre)
    if target.body_type == "json":
        return session.post(target.url, json=data, timeout=timeout, allow_redirects=suivre)
    return session.post(target.url, data=data, timeout=timeout, allow_redirects=suivre)


# --------------------------------------------------------------------------
# Securite : cible autorisee
# --------------------------------------------------------------------------

LOCAL_SUFFIXES = (".local", ".lan", ".internal", ".intranet", ".test", ".home.arpa", ".localhost")


def is_lab_host(host: str) -> bool:
    """Vrai si l'hote appartient a un reseau prive / de laboratoire."""
    if not host:
        return False
    host = host.strip("[]").lower()
    if host in ("localhost", "localhost.localdomain"):
        return True
    if host.endswith(LOCAL_SUFFIXES):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            resolved = socket.gethostbyname(host)
            address = ipaddress.ip_address(resolved)
        except (ValueError, socket.gaierror):
            return False
    return (address.is_private or address.is_loopback or address.is_link_local)


def ensure_target_allowed(url: str, force: bool, interactive: bool) -> bool:
    host = urlparse(url).hostname or ""
    if is_lab_host(host) or force:
        return True
    ui.warn(f"La cible {host} n'est pas un réseau privé (10/8, 172.16/12, 192.168/16, localhost).")
    ui.info("Cet outil pédagogique est prévu pour un laboratoire isolé ou une cible testée.")
    if interactive:
        return ui.confirm("Confirmez-vous disposer d'une autorisation écrite pour cette cible ?", default=False)
    ui.err("Utilisez --i-have-authorization si cette cible est couverte par une autorisation.")
    return False


# --------------------------------------------------------------------------
# Dictionnaires
# --------------------------------------------------------------------------

def load_words(path: Path, limit: Optional[int], start: int) -> List[str]:
    """Charge un dictionnaire : une ligne = un mot de passe, '#' = commentaire."""
    if not path.is_file():
        raise FileNotFoundError(f"Dictionnaire introuvable : {path}")
    words: List[str] = []
    skip = max(0, start)
    budget = limit if limit and limit > 0 else None
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            candidate = line.strip()
            if not candidate or candidate.startswith("#"):
                continue
            if skip:
                skip -= 1
                continue
            words.append(candidate)
            if budget and len(words) >= budget:
                break
    return words


def random_probe_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Zz" + "".join(random.choice(alphabet) for _ in range(28))


# --------------------------------------------------------------------------
# Moteur
# --------------------------------------------------------------------------

@dataclass
class Finding:
    user: str
    password: str
    verdict: Verdict
    fingerprint: str
    status: int
    elapsed: float
    attempt: int


@dataclass
class RunReport:
    started: str
    target_url: str
    method: str
    login_field: str
    password_field: str
    users: List[str]
    dictionary: str
    total_planned: int
    strategy: str
    delay: float
    attempts: int = 0
    elapsed: float = 0.0
    successes: List[Finding] = field(default_factory=list)
    suspects: List[Finding] = field(default_factory=list)
    locked: bool = False
    interrupted: bool = False
    error: str = ""
    unclassified: int = 0
    fingerprints: Counter = field(default_factory=Counter)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "outil": TOOL_NAME,
            "version": VERSION,
            "debut": self.started,
            "cible": self.target_url,
            "methode": self.method,
            "champs": {"login": self.login_field, "password": self.password_field},
            "utilisateurs": self.users,
            "dictionnaire": self.dictionary,
            "tentatives_prevues": self.total_planned,
            "tentatives_effectuees": self.attempts,
            "strategie_detection": self.strategy,
            "delai_requetes_s": self.delay,
            "duree_s": round(self.elapsed, 2),
            "debit_tentatives_s": round(self.attempts / self.elapsed, 2) if self.elapsed else 0,
            "verrouillage_detecte": self.locked,
            "interrompu": self.interrupted,
            "reponses_non_classifiables": self.unclassified,
            "reussites": [
                {"utilisateur": f.user, "mot_de_passe": f.password, "empreinte": f.fingerprint,
                 "http": f.status, "essai": f.attempt}
                for f in self.successes
            ],
            "suspects": [
                {"utilisateur": f.user, "mot_de_passe": f.password, "empreinte": f.fingerprint,
                 "http": f.status, "essai": f.attempt}
                for f in self.suspects
            ],
            "erreurs": self.error,
        }


def format_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def progress_line(current: int, total: int, started: float, user: str, password: str) -> str:
    elapsed = time.time() - started
    rate = current / elapsed if elapsed > 0 else 0.0
    remaining = (total - current) / rate if rate > 0 else 0.0
    percent = (current / total * 100) if total else 0.0
    width = 24
    filled = int(width * current / total) if total else 0
    bar = "#" * filled + "." * (width - filled)
    return (f"  [{bar}] {percent:5.1f}%  {current}/{total}  "
            f"{rate:5.1f}/s  restant {format_duration(remaining)}  "
            f"dernier: {user}:{password}")


def run_bruteforce(target: Target, words: List[str], session: requests.Session,
                   engine: DetectionEngine, delay: float, timeout: float,
                   refresh_hidden: Optional[Callable[[], None]],
                   dictionary_name: str, stop_on_suspect: bool) -> RunReport:
    total_planned = len(target.users) * len(words)
    report = RunReport(
        started=datetime.now().isoformat(timespec="seconds"),
        target_url=target.url,
        method=target.method.upper(),
        login_field=target.login_field,
        password_field=target.password_field,
        users=list(target.users),
        dictionary=dictionary_name,
        total_planned=total_planned,
        strategy=engine.strategy,
        delay=delay,
    )

    if not words or not target.users:
        report.error = "Aucune combinaison à tester."
        return report

    started = time.time()
    interactive = sys.stdout.isatty()
    last_draw = 0.0
    current_user: Optional[str] = None

    def arreter_progression() -> None:
        """Efface la ligne de progression avant d'écrire autre chose.

        Sans cela, un « SUCCÈS »	printi au milieu de la barre produirait
        une ligne illisible : « [...] 41.7% 5/12 * SUCCÈS — admin : ... ».
        """
        if interactive:
            sys.stdout.write("\r" + " " * 100 + "\r")
            sys.stdout.flush()

    try:
        for index, (user, password) in enumerate(itertools.product(target.users, words), start=1):
            if user != current_user:
                current_user = user
                arreter_progression()
                ui.section(f"Essais pour l'identifiant « {user} »")
            if refresh_hidden is not None:
                refresh_hidden()
            try:
                response = send_auth_request(session, target, user, password, timeout)
            except RequestException as exc:
                report.error = f"Erreur réseau à l'essai {index} : {exc}"
                report.attempts = index
                break

            redactions = (user, password)
            verdict = engine.classify(response, redactions)
            engine.observe(response, redactions)
            report.attempts = index
            report.fingerprints[fingerprint_of(response, redactions).short()] += 1

            if verdict is Verdict.SUCCESS:
                finding = Finding(user, password, verdict,
                                  fingerprint_of(response, redactions).short(),
                                  response.status_code, time.time() - started, index)
                report.successes.append(finding)
                arreter_progression()
                ui.hit(f"SUCCÈS — {user} : {password}")
                ui.kv("Empreinte", finding.fingerprint)
                if not stop_on_suspect:
                    break
            elif verdict is Verdict.SUSPECT:
                finding = Finding(user, password, verdict,
                                  fingerprint_of(response, redactions).short(),
                                  response.status_code, time.time() - started, index)
                report.suspects.append(finding)
                arreter_progression()
                ui.warn(f"Réponse inhabituelle (essai {index}) : {user} : {password}")
                ui.kv("Empreinte", finding.fingerprint)
                if stop_on_suspect:
                    break
            elif verdict is Verdict.LOCKED:
                report.locked = True
                report.error = (f"Blocage détecté à l'essai {index} (HTTP {response.status_code}). "
                                "La cible se protège : arrêt immédiat.")
                break

            if interactive and time.time() - last_draw > 0.1:
                sys.stdout.write("\r" + progress_line(index, total_planned, started, user, password))
                sys.stdout.flush()
                last_draw = time.time()
            elif not interactive and index % 100 == 0:
                ui.info(f"{index}/{total_planned} essais — {format_duration(time.time() - started)}")

            if delay > 0 and index < total_planned:
                time.sleep(delay + random.uniform(0, delay * 0.25))
    except KeyboardInterrupt:
        report.interrupted = True
        report.error = "Interruption manuelle (Ctrl+C)."
    finally:
        arreter_progression()
        report.elapsed = time.time() - started
        report.unclassified = engine.unclassified
    return report


# --------------------------------------------------------------------------
# Rapports
# --------------------------------------------------------------------------

def save_report(report: RunReport, results_dir: Path) -> Tuple[Path, Path]:
    results_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = results_dir / f"rapport_{stamp}.json"
    txt_path = results_dir / f"rapport_{stamp}.txt"

    json_path.write_text(json.dumps(report.as_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "=" * 70,
        f" {TOOL_NAME} v{VERSION} — rapport d'essai de mots de passe",
        "=" * 70,
        f"Date              : {report.started}",
        f"Cible             : {report.target_url}",
        f"Méthode           : {report.method}",
        f"Champ login       : {report.login_field}",
        f"Champ mot de passe: {report.password_field}",
        f"Utilisateurs      : {', '.join(report.users)}",
        f"Dictionnaire      : {report.dictionary}",
        f"Stratégie         : {report.strategy}",
        f"Tentatives        : {report.attempts}/{report.total_planned}",
        f"Durée             : {format_duration(report.elapsed)}"
        + (f"  ({report.attempts / report.elapsed:.1f} essais/s)" if report.elapsed else ""),
        "",
    ]
    if report.successes:
        lines.append(f"MOT DE PASSE TROUVÉ ({len(report.successes)}) :")
        for finding in report.successes:
            lines.append(f"  - {finding.user} : {finding.password}  [{finding.fingerprint}]")
    else:
        lines.append("MOT DE PASSE TROUVÉ : aucun")
    if report.suspects:
        lines.append("")
        lines.append(f"RÉPONSES INHABITUELLES À VÉRIFIER ({len(report.suspects)}) :")
        for finding in report.suspects:
            lines.append(f"  - {finding.user} : {finding.password}  [{finding.fingerprint}]")
    if report.locked:
        lines.append("")
        lines.append("VERROUILLAGE / LIMITATION DÉTECTÉE PAR LA CIBLE.")
    if report.error:
        if report.interrupted:
            lines += ["", "ESSAI INTERROMPU AVANT LA FIN DU DICTIONNAIRE : "
                          "le résultat est partiel.", ""]
        if report.error:
            lines += ["", f"Remarque : {report.error}"]
    if report.interrupted:
        ui.kv("Etat", ui.paint("INTERROMPU — résultat partiel", ui.YELLOW))
    if report.unclassified:
        lines += ["", f"Réponses non classifiables : {report.unclassified} "
                      "(aucune référence d'échec n'était encore établie)"]
    if report.fingerprints:
        lines += ["", "Empreintes observées (tri par fréquence) :"]
        for fingerprint, count in report.fingerprints.most_common(10):
            lines.append(f"  {count:>6} x  {fingerprint}")
    lines += ["", "=" * 70]
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, txt_path


def print_summary(report: RunReport, json_path: Path, txt_path: Path) -> None:
    ui.section("Bilan")
    ui.kv("Cible", report.target_url)
    ui.kv("Essais", f"{report.attempts}/{report.total_planned}")
    ui.kv("Durée", format_duration(report.elapsed))
    rate = report.attempts / report.elapsed if report.elapsed else 0.0
    ui.kv("Débit", f"{rate:.1f} tentatives/seconde")
    ui.kv("Détection", report.strategy)
    if report.successes:
        ui.kv("Résultat", ui.paint("MOT DE PASSE TROUVÉ", ui.BOLD, ui.GREEN))
        for finding in report.successes:
            ui.kv(f" Essai n°{finding.attempt}", f"{finding.user} : {finding.password}")
    else:
        ui.kv("Résultat", ui.paint("aucun couple trouvé", ui.YELLOW))
    if report.suspects:
        ui.kv("À vérifier", f"{len(report.suspects)} réponse(s) inhabituelle(s), voir le rapport")
    if report.unclassified:
        ui.kv("Non classifiables", f"{report.unclassified} reponse(s) avant etablissement "
                                   "de la reference d'echec")
    if report.error:
        ui.kv("Remarque", report.error)
    ui.kv("Rapport JSON", str(json_path))
    ui.kv("Rapport texte", str(txt_path))

    ui.section("Leçons — comment corriger cette faiblesse")
    for lesson in (
        "Un mot de passe long et unique est la protection la plus efficace : 12 caractères "
        "aléatoires ou une phrase de passe résistent aux dictionnaires.",
        "Verrouillez le compte après 5 à 10 échecs et limitez les tentatives par adresse IP ; "
        "c'est ce qui a arrêté ce script.",
        "Ajoutez un second facteur (MFA) : un mot de passe volé ne suffit alors plus.",
        "Surveillez les échecs d'authentification (journaux, SIEM) pour détecter les campagnes.",
        "Un message d'erreur identique pour « identifiant inconnu » et « mot de passe faux » "
        "empêche d'énumérer les comptes.",
    ):
        print(f"  {ui.paint('-', ui.DIM)} {lesson}")


# --------------------------------------------------------------------------
# Mode inspection
# --------------------------------------------------------------------------

def run_inspect(args: argparse.Namespace) -> int:
    ui.banner()
    ui.kv("URL", args.url)
    if not ensure_target_allowed(args.url, args.i_have_authorization, interactive=False):
        return 1

    session = build_session(not args.insecure, args.user_agent)
    for raw in args.header:
        key, _, value = raw.partition(":")
        if key.strip() and value.strip():
            session.headers[key.strip()] = value.strip()
    for raw in args.cookies:
        key, _, value = raw.partition("=")
        if key.strip():
            session.cookies.set(key.strip(), value.strip())

    form, forms, error = analyse_login_form(args.url, session, args.timeout, not args.insecure)
    if error:
        ui.err(error)
        return 1

    ui.section("Formulaires détectés")
    rows = []
    for index, item in enumerate(forms, start=1):
        rows.append([
            str(index),
            item.method,
            (item.action or "(page courante)")[:46],
            ", ".join(f.name for f in item.fields)[:46],
        ])
    ui.table(rows, ["#", "Méthode", "Action", "Champs"])

    assert form is not None
    ui.section(f"Formulaire de connexion analysé (formulaire n°{forms.index(form) + 1})")
    ui.kv("Action", form.action or "(page courante)")
    ui.kv("Méthode", form.method)

    rows = []
    login_guess, password_guess = None, None
    login_score = password_score = -1
    for item in form.fields:
        if item.type == "hidden":
            role, keep = "champ caché", "conserver"
        elif item.is_secret():
            role, keep = "MOT DE PASSE", "à tester"
        elif item.type in CHAMPS_NON_SAISISSABLES:
            role, keep = "bouton", "ignorer"
        else:
            login_candidate = guess_role(item.name, "login")
            if login_candidate > login_score:
                login_score, login_guess = login_candidate, item.name
            role, keep = "identifiant ?", "candidat"
        rows.append([item.name, item.type, role, keep, (item.value[:20] + "…") if len(item.value) > 20 else item.value])
    ui.table(rows, ["name", "type", "Rôle probable", "Traitement", "value"])

    if password_guess is None:
        password_guess = next((f.name for f in form.fields if f.is_secret()), "password")
    ui.section("Valeurs suggérées pour la ligne de commande")
    ui.kv("--login-field", login_guess or "login")
    ui.kv("--password-field", password_guess)
    hidden = [f.name for f in form.fields if f.type == "hidden"]
    if hidden:
        ui.kv("Champs cachés", ", ".join(hidden))
        ui.info("Ils sont envoyés automatiquement ; utilisez --extra-field pour les fixer.")
    if form.method.upper() == "GET":
        ui.warn("Ce formulaire utilise GET : les identifiants apparaîtront dans l'URL et les journaux.")
    return 0


# --------------------------------------------------------------------------
# Mode interactif
# --------------------------------------------------------------------------

def interactive_config(args: argparse.Namespace) -> Optional[Target]:
    ui.banner()
    ui.section("1. Cible")
    url = ui.ask("URL de la page de connexion", args.url or "")
    if not url:
        ui.err("Une URL est obligatoire.")
        return None
    if "://" not in url:
        url = "http://" + url
    if not urlparse(url).scheme in ("http", "https"):
        ui.err("Le schéma doit être http ou https.")
        return None

    if not ensure_target_allowed(url, args.i_have_authorization, interactive=True):
        ui.err("Arrêt : cible non autorisée.")
        return None

    session = build_session(not args.insecure, args.user_agent)
    form, forms, error = analyse_login_form(url, session, args.timeout, not args.insecure)
    if error:
        ui.warn(error)
    if form is not None:
        ui.section("2. Formulaire détecté automatiquement")
        rows = [[f.name, f.type, "champ caché" if f.type == "hidden" else
                 ("mot de passe" if f.is_secret() else "identifiant ?")] for f in form.fields]
        ui.table(rows, ["name", "type", "rôle probable"])
        method_default = "POST" if form.method.upper() == "POST" else "GET"
        if form.action and urlparse(form.action).path not in ("", "/"):
            ui.kv("Action détectée", form.action)
            use_action = ui.confirm("Utiliser cette URL d'action ?", default=True)
            if use_action:
                url = form.action
    else:
        method_default = "POST"

    ui.section("3. Méthode et champs")
    method = ui.ask("Méthode HTTP (GET/POST)", method_default).upper()
    if method not in ("GET", "POST"):
        method = "POST"

    login_default = ""
    password_default = ""
    if form is not None:
        candidates = [f for f in form.fields if f.type == "hidden"]
        texts = [f for f in form.fields if not f.is_secret() and f.type not in ("hidden", "submit", "button", "checkbox")]
        secrets = [f for f in form.fields if f.is_secret()]
        if texts:
            best = max(texts, key=lambda f: guess_role(f.name, "login"))
            login_default = best.name
        if secrets:
            password_default = secrets[0].name
        for item in candidates:
            ui.info(f"champ caché détecté : {item.name} (sera envoyé automatiquement)")

    login_field = ui.ask("Nom du champ LOGIN (attribut name)", login_default or args.login_field)
    password_field = ui.ask("Nom du champ MOT DE PASSE (attribut name)", password_default or args.password_field)
    if not login_field or not password_field:
        ui.err("Les deux noms de champs sont obligatoires.")
        return None

    body_type = "form"
    if method == "POST":
        body_type = ui.ask("Type de corps (form ou json)", "form").lower()
        if body_type not in ("form", "json"):
            body_type = "form"

    extra_fields: List[Tuple[str, str]] = []
    while ui.confirm("Ajouter un champ supplémentaire (clé=valeur) ?", default=False):
        raw = ui.ask("  clé=valeur", "")
        if "=" in raw:
            key, _, value = raw.partition("=")
            extra_fields.append((key.strip(), value.strip()))

    ui.section("4. Identifiants et dictionnaire")
    raw_users = ui.ask("Identifiant(s) à tester (séparés par des virgules)", args.user or "admin")
    users = [u.strip() for u in raw_users.split(",") if u.strip()]
    if not users:
        ui.err("Au moins un identifiant est nécessaire.")
        return None

    dictionary = ui.ask("Chemin du dictionnaire", args.dictionary or DEFAULT_DICTIONARY)
    if not Path(dictionary).is_file():
        ui.err(f"Fichier introuvable : {dictionary}")
        return None
    args.dictionary = dictionary

    ui.section("5. Rythme et détection")
    delay_raw = ui.ask("Délai entre deux essais en secondes", str(args.delay))
    try:
        args.delay = max(0.0, float(delay_raw))
    except ValueError:
        args.delay = 0.0
        ui.warn("Délai invalide, 0 s utilisé.")
    if args.delay > 10:
        ui.warn(f"Délai de {args.delay} s : l'essai sera très long. Voulez-vous continuer ?")
        if not ui.confirm("Réduire le délai à 1 s ?", default=True):
            args.delay = 1.0

    limit_raw = ui.ask("Nombre maximum d'essais (0 = tout le dictionnaire)", str(args.max_attempts or 0))
    try:
        limit = int(limit_raw)
    except ValueError:
        limit = 0
        ui.warn("Nombre invalide, le dictionnaire complet sera utilisé.")
    args.max_attempts = limit if limit > 0 else None

    success_pattern = ui.ask(
        "Texte/regle marquant une RÉUSSITE (Entée = détection automatique)",
        args.success_pattern or "", allow_empty=True)
    failure_pattern = ui.ask(
        "Texte/regle marquant un ÉCHEC (Entée = détection automatique)",
        args.failure_pattern or "", allow_empty=True)
    args.success_pattern = [success_pattern] if success_pattern else []
    args.failure_pattern = [failure_pattern] if failure_pattern else []

    return Target(
        url=url, method=method, login_field=login_field, password_field=password_field,
        body_type=body_type, users=users, extra_fields=extra_fields,
        follow_redirects=bool(args.follow_redirects),
    )


def summarise_config(target: Target, words: List[str], delay: float) -> None:
    ui.section("Récapitulatif — vérifiez avant de lancer")
    ui.kv("Cible", target.url)
    ui.kv("Méthode", target.method.upper() + (f" ({target.body_type})" if target.method == "POST" else ""))
    ui.kv("Champ login", f'name="{target.login_field}"')
    ui.kv("Champ mot de passe", f'name="{target.password_field}"')
    ui.kv("Utilisateurs", ", ".join(target.users))
    ui.kv("Dictionnaire", f"{len(words)} mots")
    ui.kv("Essais prévus", str(len(target.users) * len(words)))
    ui.kv("Délai", f"{delay} s")
    if delay == 0:
        ui.warn("Sans délai, l'outil envoie des requêtes en rafale : à n'utiliser que sur votre laboratoire.")


# --------------------------------------------------------------------------
# Ligne de commande
# --------------------------------------------------------------------------

# Profils d'applications de laboratoire connues : ils ne font que préremplir
# des options. Une option écrite explicitement sur la ligne de commande l'emporte.
PROFILS: Dict[str, Dict[str, object]] = {
    "dvwa": {
        "login_field": "username",
        "password_field": "password",
        "refresh_csrf": True,
        "success_on_redirect": True,
    },
    "wordpress": {
        "login_field": "log",
        "password_field": "pwd",
        "success_on_redirect": True,
    },
    "mutillidae": {
        "login_field": "username",
        "password_field": "password",
        "refresh_csrf": True,
    },
    "phpmyadmin": {
        "login_field": "pma_username",
        "password_field": "pma_password",
        "follow_redirects": True,
    },
    "webgoat": {
        "login_field": "username",
        "password_field": "password",
        "refresh_csrf": True,
    },
    "tomcat": {
        "basic_auth": True,
        "method": "GET",
    },
}

DESCRIPTIONS_PROFILS = {
    "dvwa": "DVWA : champs username/password, jeton de session, réussite par 302",
    "wordpress": "WordPress : champs log/pwd, réussite par 302 vers /wp-admin/",
    "mutillidae": "Mutillidae : champs username/password, jeton de session",
    "phpmyadmin": "phpMyAdmin : champs pma_username/pma_password, redirections suivies",
    "webgoat": "WebGoat : champs username/password et jeton de session rafraîchi",
    "tomcat": "Tomcat Manager : authentification HTTP Basic, pas de formulaire",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bruteforce.py",
        description=f"{TOOL_NAME} — essai de mots de passe sur un formulaire web (pédagogique).",
        epilog="Sans argument, l'outil démarre en mode interactif. Voir MANUEL.md.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--profil", choices=sorted(PROFILS), metavar="NOM",
                        help="préremplir les options pour une application connue : "
                             + " ; ".join(f"{nom} ({texte})"
                                         for nom, texte in DESCRIPTIONS_PROFILS.items()))
    parser.add_argument("-u", "--url", help="URL de la page de connexion")
    parser.add_argument("-U", "--user", action="append", default=[],
                        help="identifiant à tester (répétable ou séparé par des virgules)")
    parser.add_argument("-l", "--login-field", default="login",
                        help="attribut name du champ identifiant (défaut : login)")
    parser.add_argument("-p", "--password-field", default="pass",
                        help="attribut name du champ mot de passe (défaut : pass)")
    parser.add_argument("-m", "--method", choices=["GET", "POST"], default="POST",
                        help="méthode HTTP (défaut : POST)")
    parser.add_argument("-T", "--body-type", choices=["form", "json"], default="form",
                        help="encodage du corps POST (défaut : form)")
    parser.add_argument("-w", "--dictionary", default=DEFAULT_DICTIONARY,
                        help=f"fichier de mots de passe (défaut : {DEFAULT_DICTIONARY})")
    parser.add_argument("-d", "--delay", type=float, default=0.5,
                        help="délai entre deux essais en secondes (défaut : 0.5)")
    parser.add_argument("-t", "--timeout", type=float, default=10.0, help="délai d'attente réseau (défaut : 10)")
    parser.add_argument("-k", "--max-attempts", type=int, default=None, help="limiter le nombre d'essais")
    parser.add_argument("-s", "--start", type=int, default=0, help="reprendre le dictionnaire à cette ligne")
    parser.add_argument("-e", "--extra-field", action="append", default=[], metavar="CLE=VALEUR",
                        help="champ supplémentaire à envoyer (répétable)")
    parser.add_argument("-H", "--header", action="append", default=[], metavar="CLE: VALEUR",
                        help="en-tête HTTP supplémentaire (répétable)")
    parser.add_argument("-c", "--cookie", dest="cookies", action="append", default=[], metavar="CLE=VALEUR",
                        help="cookie à envoyer (répétable)")
    parser.add_argument("--success-pattern", action="append", default=[],
                        help="expression régulière présente en cas de succès")
    parser.add_argument("--failure-pattern", action="append", default=[],
                        help="expression régulière présente en cas d'échec")
    parser.add_argument("--success-on-redirect", action="store_true", default=None,
                        help="considérer une redirection 3xx comme une réussite")
    parser.add_argument("--no-success-on-redirect", action="store_false",
                        dest="success_on_redirect",
                        help="ne pas considérer une redirection comme une réussite "
                             "(désactive un profil)")
    parser.add_argument("--no-calibration", action="store_true",
                        help="ne pas envoyer de requête sonde avant l'attaque")
    parser.add_argument("--follow-redirects", action="store_true", default=None,
                        help="suivre les redirections 3xx pour comparer la page atteinte "
                             "(phpMyAdmin renvoie 302 et un corps vide dans les deux cas)")
    parser.add_argument("--no-follow-redirects", action="store_false", dest="follow_redirects",
                        help="ne pas suivre les redirections (désactive un profil)")
    parser.add_argument("--refresh-csrf", action="store_true", default=None,
                        help="recharger la page et son jeton CSRF avant chaque essai")
    parser.add_argument("--no-refresh-csrf", action="store_false", dest="refresh_csrf",
                        help="ne pas recharger le jeton (désactive un profil)")
    parser.add_argument("--basic-auth", action="store_true",
                        help="authentification HTTP Basic (Tomcat, Jupyter...) : "
                             "les identifiants vont dans l'en-tête Authorization, "
                             "pas dans un formulaire")
    parser.add_argument("--stop-on-suspect", action="store_true",
                        help="s'arrêter sur une réponse inhabituelle")
    parser.add_argument("-I", "--insecure", action="store_true", help="ignorer la vérification TLS")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="en-tête User-Agent")
    parser.add_argument("--results-dir", default=DEFAULT_RESULTS_DIR, help="dossier des rapports")
    parser.add_argument("--inspect", action="store_true", help="analyser le formulaire et afficher l'aide")
    parser.add_argument("--dry-run", action="store_true", help="afficher la requête sans l'envoyer")
    parser.add_argument("--i-have-authorization", action="store_true",
                        help="confirmer l'autorisation sur une cible hors réseau privé")
    parser.add_argument("-V", "--version", action="version", version=f"{TOOL_NAME} {VERSION}")
    return parser


def split_multi(values: Sequence[str]) -> List[str]:
    result: List[str] = []
    for value in values:
        result.extend(part.strip() for part in value.split(",") if part.strip())
    return result


def apply_cli_overrides(target: Target, args: argparse.Namespace) -> None:
    for raw in args.extra_field:
        key, _, value = raw.partition("=")
        if key.strip():
            target.extra_fields.append((key.strip(), value.strip()))


def describe_request(target: Target, user: str, password: str) -> str:
    entetes = {"User-Agent": DEFAULT_USER_AGENT}
    if target.basic_auth:
        brut = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        entetes["Authorization"] = f"Basic {brut}"
    prepared = requests.Request(
        target.method.upper(), target.url,
        params=target.payload(user, password) if target.method == "GET" else None,
        data=target.payload(user, password) if (target.method == "POST" and target.body_type == "form") else None,
        json=target.payload(user, password) if (target.method == "POST" and target.body_type == "json") else None,
        headers=entetes,
    ).prepare()
    corps = prepared.body or "(aucun corps : les identifiants sont dans l'en-tête)"
    return f"{prepared.method} {prepared.url}\n{corps}\n\nEn-têtes :\n{prepared.headers}"


def main(argv: Optional[Sequence[str]] = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(raw_args)

    if args.profil:
        # set_defaults avant l'analyse : une option saisie à la main gagne
        parser.set_defaults(**PROFILS[args.profil])
        args = parser.parse_args(raw_args)

    if args.inspect:
        if not args.url:
            parser.error("--inspect nécessite --url")
        return run_inspect(args)

    interactive = not raw_args
    if interactive:
        args.i_have_authorization = False
        target = interactive_config(args)
        if target is None:
            return 1
    else:
        if not args.url:
            parser.error("--url est obligatoire en mode ligne de commande")
        url = args.url if "://" in args.url else "http://" + args.url
        users = split_multi(args.user)
        if not users:
            parser.error("--user est obligatoire")
        if not ensure_target_allowed(url, args.i_have_authorization, interactive=False):
            return 1
        target = Target(url=url, method=args.method.upper(), login_field=args.login_field,
                        password_field=args.password_field, body_type=args.body_type,
                        basic_auth=args.basic_auth, users=users,
                        follow_redirects=bool(args.follow_redirects))
        apply_cli_overrides(target, args)
        ui.banner()
        if args.profil:
            ui.info(f"Profil {args.profil} — {DESCRIPTIONS_PROFILS[args.profil]}")
            if target.basic_auth:
                ui.kv("Authentification", "HTTP Basic (en-tête Authorization)")
            else:
                ui.kv("Champs", f"{target.login_field} / {target.password_field}")
            if args.refresh_csrf:
                ui.kv("Jeton CSRF", "rafraîchi avant chaque essai")
            if args.success_on_redirect:
                ui.kv("Réussite", "une redirection 3xx est considérée comme un succès")
            if target.follow_redirects:
                ui.kv("Redirections", "suivies pour comparer la page atteinte")

    try:
        words = load_words(Path(args.dictionary), args.max_attempts, args.start)
    except FileNotFoundError as exc:
        ui.err(str(exc))
        return 1
    if not words:
        ui.err("Le dictionnaire est vide.")
        return 1

    session = build_session(not args.insecure, args.user_agent)
    for raw in args.header:
        key, _, value = raw.partition(":")
        if key.strip() and value.strip():
            session.headers[key.strip()] = value.strip()
    for raw in args.cookies:
        key, _, value = raw.partition("=")
        if key.strip():
            session.cookies.set(key.strip(), value.strip())

    hidden_names = collect_hidden_fields(session, target, args.timeout, not args.insecure)
    if hidden_names:
        ui.ok(f"Champs cachés détectés et conservés : {', '.join(hidden_names)}")
    boutons = collect_submit_fields(session, target, args.timeout, not args.insecure)
    if len(boutons) == 1:
        ui.ok(f"Bouton de validation détecté et envoyé : {boutons[0][0]}={boutons[0][1]}")
    elif len(boutons) > 1:
        noms = ", ".join(f"{n}={v}" for n, v in boutons)
        ui.warn(f"Plusieurs boutons de validation ({noms}) : tous sont envoyés. "
                "Si la cible n'en attend qu'un, précisez-le avec --extra-field.")
    for nom, valeur in boutons:
        if nom not in {key for key, _ in target.extra_fields}:
            target.extra_fields.append((nom, valeur))

    if args.refresh_csrf and hidden_names:
        ui.info("Jeton CSRF rafraîchi avant chaque essai (--refresh-csrf).")
    refresher = make_hidden_refresher(session, target, args.timeout, not args.insecure) \
        if args.refresh_csrf else None

    if args.dry_run:
        ui.section("Simulation de requête (--dry-run, aucun envoi d'authentification)")
        print(describe_request(target, target.users[0], words[0]))
        ui.kv("Essais restants", f"{len(words)} mot(s) de passe x {len(target.users)} identifiant(s)")
        if hidden_names:
            ui.info("Les champs cachés ci-dessus proviennent de la page réellement servie.")
        return 0

    engine = DetectionEngine(
        success_patterns=args.success_pattern,
        failure_patterns=args.failure_pattern,
        success_on_redirect=args.success_on_redirect,
    )
    if not args.success_pattern and not args.failure_pattern and not args.no_calibration:
        probe = random_probe_password()
        try:
            reference = send_auth_request(session, target, target.users[0], probe, args.timeout)
        except RequestException as exc:
            ui.err(f"Requête de calibration impossible : {exc}")
            return 1
        if LOCKOUT_RE.search(reference.text or "") or reference.status_code in (429, 503):
            ui.err("La cible bloque déjà les tentatives : vérifiez qu'elle est prête pour le laboratoire.")
            return 1
        engine.baseline = fingerprint_of(reference, (target.users[0], probe))
        engine.clusters[engine.baseline.cluster] += 1
        engine.digests[(engine.baseline.cluster, engine.baseline.digest)] += 1
        ui.ok(f"Calibration effectuée — référence d'échec : {engine.baseline.short()}")

    if interactive:
        summarise_config(target, words, args.delay)
        if not ui.confirm("Lancer les essais ?", default=False):
            ui.info("Annulé.")
            return 0

    ui.section("Essais en cours")
    report = run_bruteforce(target, words, session, engine, args.delay, args.timeout,
                            refresher, str(args.dictionary), args.stop_on_suspect)

    json_path, txt_path = save_report(report, Path(args.results_dir))
    print_summary(report, json_path, txt_path)
    if report.successes:
        return 0
    if report.interrupted:
        return 130
    return 2


def choisir_formulaire(page: str) -> Optional[FormInfo]:
    """Retient le formulaire de connexion le plus plausible de la page."""
    forms = parse_forms(page)
    choisi = next((f for f in forms if any(x.is_secret() for x in f.fields)), None)
    if choisi is None and forms:
        choisi = forms[0]
    return choisi


def collect_submit_fields(session: requests.Session, target: Target, timeout: float,
                          verify: bool) -> List[Tuple[str, str]]:
    """Récupère les boutons de validation du formulaire.

    Certains backends n'exécutent leur code de connexion que si le bouton a
    été soumis : le vrai DVWA teste `isset($_POST['Login'])` et, si le champ
    manque, redirisplaye le formulaire tel quel — sans même un message
    d'erreur, ce qui fait croire à un échec d'authentification. Un navigateur
    envoie le bouton sur lequel on clique ; l'outil fait donc de même.
    """
    try:
        response = session.get(target.url, timeout=timeout, verify=verify, allow_redirects=True)
    except RequestException:
        return []
    choisi = choisir_formulaire(response.text or "")
    if choisi is None:
        return []
    return [(f.name, f.value) for f in choisi.fields
            if f.type in ("submit", "button") and f.name]


def collect_hidden_fields(session: requests.Session, target: Target, timeout: float,
                          verify: bool, update: bool = False) -> List[str]:
    """Récupère les champs cachés du formulaire (jeton CSRF, etc.).

    Renvoie la liste des champs cachés présents dans la page. A chaque appel,
    les valeurs déjà connues sont rafraîchies : c'est ce qui permet de
    recharger un jeton lié à la session avant chaque essai.
    """
    try:
        response = session.get(target.url, timeout=timeout, verify=verify, allow_redirects=True)
    except RequestException:
        return []
    chosen = choisir_formulaire(response.text or "")
    if chosen is None:
        return []
    if chosen.action and target.method == "POST" and not update:
        target.url = urljoin(response.url, chosen.action)

    index = {key: position for position, (key, _) in enumerate(target.extra_fields)}
    presents: List[str] = []
    for item in chosen.fields:
        if item.type != "hidden":
            continue
        presents.append(item.name)
        if item.name in index:
            if update:
                target.extra_fields[index[item.name]] = (item.name, item.value)
            continue
        index[item.name] = len(target.extra_fields)
        target.extra_fields.append((item.name, item.value))
    return presents


def make_hidden_refresher(session: requests.Session, target: Target, timeout: float,
                          verify: bool) -> Optional[Callable[[], None]]:
    """Construit un rappel qui recharge le jeton CSRF avant chaque essai."""
    if not collect_hidden_fields(session, target, timeout, verify):
        return None

    def refresh() -> None:
        collect_hidden_fields(session, target, timeout, verify, update=True)

    return refresh


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrompu.\n")
        raise SystemExit(130)
