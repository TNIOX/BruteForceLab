#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Suite de tests de BruteForceLab — exécutable sans dépendance externe.

    python3 tests/test_outils.py            # tout
    python3 tests/test_outils.py -v         # détail de chaque test
    python3 tests/test_outils.py detection  # seulement les tests "detection"

Les tests démarrent eux-mêmes le laboratoire (lab_server.py) sur un port
libre, n'effectuent aucune requête vers l'extérieur, et nettoient le dossier
resultats/ avant et après. Ils sont conçus pour être lus : chacun vérifie une
propriété décrite dans MANUEL.md.
"""

from __future__ import annotations

import json
import os
import pty
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
BRUTEFORCE = RACINE / "bruteforce.py"
LAB = RACINE / "lab_server.py"
DICO_LABO = RACINE / "dico_labo.txt"
DICO_META = RACINE / "dico_metasploitable.txt"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def charger_module(nom: str):
    """Importe un module du projet sans installer quoi que ce soit."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(nom, RACINE / f"{nom}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[nom] = module  # requis par dataclasses
    spec.loader.exec_module(module)
    return module


def port_libre() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def sans_couleur(flux: bytes | str) -> str:
    if isinstance(flux, bytes):
        flux = flux.decode("utf-8", "replace")
    return ANSI.sub("", flux)


def etat_terminal(flux: str) -> list[str]:
    """Rejoue \r et \n comme le ferait un terminal, ligne par ligne.

    Un \r replace le curseur en début de ligne sans effacer : c'est ce qui
    permet à la barre de progression de réécrire la même ligne.
    """
    lignes = [""]
    colonne = 0
    for caractere in flux:
        if caractere == "\r":
            colonne = 0
        elif caractere == "\n":
            lignes.append("")
            colonne = 0
        else:
            while len(lignes[-1]) <= colonne:
                lignes[-1] += " "
            lignes[-1] = lignes[-1][:colonne] + caractere + lignes[-1][colonne + 1:]
            colonne += 1
    return lignes


class Laboratoire:
    """Démarre lab_server.py sur un port libre et attend qu'il réponde."""

    def __init__(self, *options: str, chemin: str = "/login") -> None:
        self.port = port_libre()
        self.url = f"http://127.0.0.1:{self.port}{chemin}"
        self.api = f"http://127.0.0.1:{self.port}/api/login"
        self.process = subprocess.Popen(
            [sys.executable, str(LAB), "--port", str(self.port), "--quiet", *options],
            cwd=RACINE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        for _ in range(80):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=1).read()
                return
            except Exception:
                time.sleep(0.15)
        self.process.kill()
        raise RuntimeError("le laboratoire n'a pas démarré")

    def arreter(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()

    def executer(self, arguments: list[str], timeout: int = 60) -> tuple[str, int]:
        resultat = subprocess.run(
            [sys.executable, str(BRUTEFORCE), *arguments], cwd=RACINE,
            capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return sans_couleur(resultat.stdout + resultat.stderr), resultat.returncode

    def base(self, *drapeaux: str, **surcharge) -> list[str]:
        """Ligne de commande minimale, plus des drapeaux et des options."""
        arguments = ["-u", self.url, "-U", "admin", "-w", str(DICO_LABO), "-d", "0",
                     *drapeaux]
        for cle, valeur in surcharge.items():
            arguments += [cle, str(valeur)]
        return arguments


class BaseOutils(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lab = Laboratoire()
        cls.resultats = RACINE / "resultats"
        if cls.resultats.exists():
            shutil.rmtree(cls.resultats)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.lab.arreter()
        if cls.resultats.exists():
            shutil.rmtree(cls.resultats)

    def assertTrouve(self, sortie: str, mot_de_passe: str = "Lab2024!") -> None:
        self.assertIn("MOT DE PASSE TROUVÉ", sortie)
        self.assertIn(mot_de_passe, sortie)


# ---------------------------------------------------------------------------

class TestAnalyseDeFormulaire(BaseOutils):
    """--inspect doit deviner les noms de champs et repérer les jetons."""

    def test_inspect_detecte_les_trois_champs(self):
        sortie, code = self.lab.executer(["--inspect", "-u", self.lab.url])
        self.assertEqual(code, 0, sortie)
        for nom in ("login", "pass", "csrf_token"):
            self.assertIn(nom, sortie)

    def test_inspect_suggere_les_bonnes_options(self):
        sortie, _ = self.lab.executer(["--inspect", "-u", self.lab.url])
        self.assertRegex(sortie, r"--login-field\s+login")
        self.assertRegex(sortie, r"--password-field\s+pass")
        self.assertIn("Champs cachés", sortie)


class TestModeSec(BaseOutils):
    """--dry-run ne doit envoyer aucune requête d'authentification."""

    def test_dry_run_affiche_la_requete(self):
        sortie, code = self.lab.executer(["-u", self.lab.url, "-U", "admin", "--dry-run"])
        self.assertEqual(code, 0, sortie)
        self.assertIn("POST", sortie)

    def test_dry_run_inclut_le_jeton_csrf(self):
        sortie, _ = self.lab.executer(["-u", self.lab.url, "-U", "admin", "--dry-run"])
        self.assertIn("csrf_token", sortie)

    def test_dry_run_ne_touche_pas_aux_registres_du_laboratoire(self):
        self.lab.executer(["-u", self.lab.url, "-U", "admin", "--dry-run"])
        with urllib.request.urlopen(f"http://127.0.0.1:{self.lab.port}/health", timeout=3) as r:
            self.assertEqual(json.loads(r.read())["tentatives"], 0)


class TestDetection(BaseOutils):
    """Les trois stratégies de détection de la réussite."""

    def test_calibration_par_defaut(self):
        sortie, code = self.lab.executer(self.lab.base())
        self.assertEqual(code, 0, sortie)
        self.assertTrouve(sortie)
        self.assertIn("Calibration effectuée", sortie)
        self.assertNotIn("Réponse inhabituelle", sortie)

    def test_calibration_ne_renseigne_aucun_non_classifiable(self):
        sortie, _ = self.lab.executer(self.lab.base())
        self.assertNotIn("Non classifiables", sortie)

    def test_strategie_statistique(self):
        sortie, code = self.lab.executer(self.lab.base("--no-calibration"))
        self.assertEqual(code, 0, sortie)
        self.assertTrouve(sortie)
        self.assertIn("statistique", sortie)
        self.assertNotIn("Calibration effectuée", sortie)

    def test_strategie_statistique_signale_son_angle_mort(self):
        sortie, _ = self.lab.executer(self.lab.base("--no-calibration"))
        # sans référence d'échec, les 2 premières réponses ne sont pas
        # classifiables : l'outil doit l'annoncer plutôt que de mentir
        self.assertIn("Non classifiables", sortie)
        self.assertRegex(sortie, r"Non classifiables\s+2 reponse")

    def test_motifs_explicites(self):
        sortie, code = self.lab.executer(self.lab.base(
            "--success-pattern", "Connexion réussie",
            "--failure-pattern", "Mot de passe invalide"))
        self.assertEqual(code, 0, sortie)
        self.assertTrouve(sortie)

    def test_motifs_evitent_la_query_sonde(self):
        sortie, _ = self.lab.executer(self.lab.base("--success-pattern", "Connexion réussie"))
        self.assertNotIn("Calibration effectuée", sortie)

    def test_mauvais_nom_de_champ_ne_produit_pas_de_faux_positif(self):
        sortie, code = self.lab.executer(
            ["-u", self.lab.url, "-U", "admin", "-w", str(DICO_LABO), "-d", "0",
             "-p", "champ_qui_nexiste_pas"])
        self.assertEqual(code, 2, sortie)
        self.assertNotIn("MOT DE PASSE TROUVÉ", sortie)

    def test_stop_on_suspect_ne_change_pas_une_reussite_normale(self):
        sortie, code = self.lab.executer(self.lab.base("--stop-on-suspect"))
        self.assertEqual(code, 0, sortie)
        self.assertTrouve(sortie)


class TestHttp(BaseOutils):
    """Méthodes, corps, en-têtes, jetons."""

    def test_formulaire_get(self):
        sortie, code = self.lab.executer(self.lab.base("-m", "GET"))
        self.assertEqual(code, 0, sortie)
        self.assertTrouve(sortie)

    def test_api_json(self):
        sortie, code = self.lab.executer(
            ["-u", self.lab.api, "-U", "admin", "-w", str(DICO_LABO), "-d", "0",
             "-T", "json", "-l", "login", "-p", "pass"])
        self.assertEqual(code, 0, sortie)
        self.assertTrouve(sortie)

    def test_champ_supplementaire(self):
        sortie, code = self.lab.executer(self.lab.base("-e", "remember=1"))
        self.assertEqual(code, 0, sortie)
        self.assertTrouve(sortie)

    def test_en_tete_et_cookie(self):
        sortie, code = self.lab.executer(
            self.lab.base("-H", "X-Lab: 1", "-c", "session=abc"))
        self.assertEqual(code, 0, sortie)
        self.assertTrouve(sortie)

    def test_jeton_csrf_rafraichi(self):
        sortie, code = self.lab.executer(self.lab.base("--refresh-csrf"))
        self.assertEqual(code, 0, sortie)
        self.assertTrouve(sortie)

    def test_http_non_chiffre_refuse_sauf_option(self):
        # le laboratoire est en HTTP : il faut assumer explicitement
        sortie, code = self.lab.executer(self.lab.base())
        self.assertEqual(code, 0, sortie)
        sortie, code = self.lab.executer(self.lab.base("-I"))
        self.assertEqual(code, 0, sortie)
        self.assertTrouve(sortie)

    def test_user_agent_personnalise(self):
        sortie, code = self.lab.executer(self.lab.base("--user-agent", "Lab-Test/1.0"))
        self.assertEqual(code, 0, sortie)
        self.assertTrouve(sortie)


class TestRedirection(unittest.TestCase):
    """--success-on-redirect : utile, mais activé par choix."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "/bienvenue")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            self.do_GET()

        def log_message(self, *args):
            pass

    @classmethod
    def setUpClass(cls) -> None:
        cls.port = port_libre()
        cls.serveur = ThreadingHTTPServer(("127.0.0.1", cls.port), cls.Handler)
        cls.thread = threading.Thread(target=cls.serveur.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.port}/login"
        if (RACINE / "resultats").exists():
            shutil.rmtree(RACINE / "resultats")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.serveur.shutdown()
        cls.serveur.server_close()
        if (RACINE / "resultats").exists():
            shutil.rmtree(RACINE / "resultats")

    def lancer(self, *drapeaux: str) -> tuple[str, int]:
        resultat = subprocess.run(
            [sys.executable, str(BRUTEFORCE), "-u", self.url, "-U", "admin",
             "-w", str(DICO_LABO), "-d", "0", "-k", "3", *drapeaux],
            cwd=RACINE, capture_output=True, text=True, timeout=60,
            stdin=subprocess.DEVNULL)
        return sans_couleur(resultat.stdout + resultat.stderr), resultat.returncode

    def test_redirection_sans_option_n_est_pas_une_reussite(self):
        sortie, code = self.lancer()
        self.assertEqual(code, 2, sortie)
        self.assertNotIn("MOT DE PASSE TROUVÉ", sortie)

    def test_redirection_avec_option(self):
        sortie, code = self.lancer("--success-on-redirect")
        self.assertEqual(code, 0, sortie)
        self.assertIn("MOT DE PASSE TROUVÉ", sortie)


class TestRedirectionVide(unittest.TestCase):
    """Le vrai phpMyAdmin répond 302 et un corps vide, succès ou échec.

    Sans suivre la redirection, toutes les empreintes sont identiques (0 octet)
    et la calibration ne peut rien conclure : c'est ce qui faisait echouer la
    demonstration sur la VM. La page atteinte apres le 302, elle, differe.
    """

    class Handler(BaseHTTPRequestHandler):
        reussi = False

        def do_POST(self):
            longueur = int(self.headers.get("Content-Length", 0))
            corps = self.rfile.read(longueur).decode("utf-8", "replace")
            self.send_response(302)
            self.send_header("Location", "/index.php?token=x")
            self.send_header("Content-Length", "0")
            self.end_headers()
            # chaque requete cree une instance : l'etat vit sur la classe
            type(self).reussi = "pma_password=toor" in corps

        def do_GET(self):
            # la longueur compte : les pages reelles font plusieurs centaines
            # d'octets, donc les tranches de 256 diffferent entre echec et reussite
            if type(self).reussi:
                corps = b'<frameset rows="90,*"><frame src="navigation.php">' + b"x" * 600
            else:
                corps = b'<div class="error">#1045 - Access denied for user</div>' + b"y" * 200
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(corps)))
            self.end_headers()
            self.wfile.write(corps)

        def log_message(self, *args):
            pass

    @classmethod
    def setUpClass(cls) -> None:
        cls.port = port_libre()
        cls.serveur = ThreadingHTTPServer(("127.0.0.1", cls.port), cls.Handler)
        cls.thread = threading.Thread(target=cls.serveur.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.port}/index.php"
        if (RACINE / "resultats").exists():
            shutil.rmtree(RACINE / "resultats")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.serveur.shutdown()
        cls.serveur.server_close()
        if (RACINE / "resultats").exists():
            shutil.rmtree(RACINE / "resultats")

    def lancer(self, *drapeaux: str) -> tuple[str, int]:
        resultat = subprocess.run(
            [sys.executable, str(BRUTEFORCE), "-u", self.url, "-U", "root",
             "-l", "pma_username", "-p", "pma_password",
             "-w", str(DICO_META), "-d", "0", "-k", "6", *drapeaux],
            cwd=RACINE, capture_output=True, text=True, timeout=60,
            stdin=subprocess.DEVNULL)
        return sans_couleur(resultat.stdout + resultat.stderr), resultat.returncode

    def test_sans_suivre_la_redirection_aucun_couple(self):
        sortie, code = self.lancer("--no-follow-redirects")
        self.assertEqual(code, 2, sortie)
        self.assertIn("aucun couple", sortie)

    def test_en_suivant_la_redirection_le_couple_est_trouve(self):
        sortie, code = self.lancer("--follow-redirects")
        self.assertEqual(code, 0, sortie)
        self.assertIn("root : toor", sortie)


class TestProtectionDeLaCible(BaseOutils):
    """Garde-fous : réseau privé par défaut, autorisation explicite sinon."""

    def test_cible_publique_refusee(self):
        sortie, code = self.lab.executer(
            ["-u", "https://exemple-public.fr/login", "-U", "admin", "-w", str(DICO_LABO)])
        self.assertEqual(code, 1, sortie)
        self.assertIn("--i-have-authorization", sortie)

    def test_localhost_accepte(self):
        sortie, code = self.lab.executer(self.lab.base())
        self.assertEqual(code, 0, sortie)

    def test_dictionnaire_manquant_signale(self):
        sortie, code = self.lab.executer(
            ["-u", self.lab.url, "-U", "admin", "-w", "/tmp/fichier_inexistant.txt"])
        self.assertEqual(code, 1, sortie)
        self.assertIn("introuvable", sortie)

    def test_url_obligatoire_en_mode_cli(self):
        sortie, code = self.lab.executer(["-U", "admin"])
        self.assertEqual(code, 2, sortie)
        self.assertIn("--url est obligatoire", sortie)

    def test_cible_injoignable_signalee(self):
        sortie, code = self.lab.executer(
            ["-u", f"http://127.0.0.1:{port_libre()}/login", "-U", "admin",
             "-w", str(DICO_LABO)])
        self.assertEqual(code, 1, sortie)


class TestVerrouillage(unittest.TestCase):
    """La cible doit pouvoir arrêter l'outil : c'est la protection efficace."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.lab = Laboratoire("--lockout", "5")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.lab.arreter()

    def test_arret_immediat_sur_verrouillage(self):
        sortie, code = self.lab.executer(self.lab.base())
        self.assertIn("Blocage détecté", sortie)
        self.assertIn("arrêt immédiat", sortie)
        self.assertNotIn("Lab2024!", sortie)
        self.assertEqual(code, 2)

    def test_compte_bloque_cote_serveur(self):
        self.lab.executer(self.lab.base())
        with urllib.request.urlopen(f"http://127.0.0.1:{self.lab.port}/health", timeout=3) as r:
            etat = json.loads(r.read())
        self.assertGreaterEqual(etat["tentatives"], 5)
        self.assertGreaterEqual(etat["identifiants_bloques"], 1)

    def test_rapport_signale_le_verrouillage(self):
        self.lab.executer(self.lab.base())
        rapports = sorted((RACINE / "resultats").glob("rapport_*.json"))
        donnees = json.loads(rapports[-1].read_text(encoding="utf-8"))
        self.assertTrue(donnees["verrouillage_detecte"])


class TestMultiplicateurs(BaseOutils):
    """Plusieurs identifiants, limites, reprise."""

    def test_deux_identifiants(self):
        sortie, code = self.lab.executer(
            ["-u", self.lab.url, "-U", "root,admin", "-w", str(DICO_LABO), "-d", "0"])
        self.assertEqual(code, 0, sortie)
        self.assertIn("Essais pour l'identifiant « root »", sortie)
        self.assertIn("Essais pour l'identifiant « admin »", sortie)

    def test_limite_d_essais(self):
        sortie, code = self.lab.executer(self.lab.base("-k", "3"))
        self.assertEqual(code, 2, sortie)
        self.assertRegex(sortie, r"Essais\s+3/3")

    def test_reprise_avec_start(self):
        sortie, code = self.lab.executer(self.lab.base("-s", "5", "-k", "1"))
        self.assertEqual(code, 0, sortie)
        self.assertTrouve(sortie)


class TestRapports(BaseOutils):
    """Les rapports doivent être écrits et exploitables."""

    def test_rapport_json_valide(self):
        self.lab.executer(self.lab.base())
        rapports = sorted((RACINE / "resultats").glob("rapport_*.json"))
        self.assertTrue(rapports, "aucun rapport JSON produit")
        donnees = json.loads(rapports[-1].read_text(encoding="utf-8"))
        for cle in ("cible", "methode", "champs", "tentatives_effectuees",
                    "strategie_detection", "reussites", "suspects",
                    "interrompu", "reponses_non_classifiables"):
            self.assertIn(cle, donnees)
        self.assertEqual(len(donnees["reussites"]), 1)
        self.assertEqual(donnees["reussites"][0]["mot_de_passe"], "Lab2024!")

    def test_rapport_texte_presente_les_empreintes(self):
        self.lab.executer(self.lab.base())
        rapports = sorted((RACINE / "resultats").glob("rapport_*.txt"))
        self.assertTrue(rapports)
        contenu = rapports[-1].read_text(encoding="utf-8")
        self.assertIn("Empreintes observées", contenu)
        self.assertIn("Lab2024!", contenu)

    def test_dossier_personnalise(self):
        with tempfile.TemporaryDirectory() as dossier:
            sortie, code = self.lab.executer(self.lab.base("--results-dir", dossier))
            self.assertEqual(code, 0, sortie)
            self.assertTrue(list(Path(dossier).glob("rapport_*.json")))


class TestTerminal(unittest.TestCase):
    """Les chemins qui ne s'exercent qu'avec un vrai terminal."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.lab = Laboratoire()
        if (RACINE / "resultats").exists():
            shutil.rmtree(RACINE / "resultats")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.lab.arreter()
        if (RACINE / "resultats").exists():
            shutil.rmtree(RACINE / "resultats")

    def executer_en_terminal(self, arguments: list[str], interrupre_apres: float | None = None
                             ) -> tuple[str, int]:
        maitre, esclave = pty.openpty()
        process = subprocess.Popen(
            [sys.executable, str(BRUTEFORCE), *arguments], cwd=RACINE,
            stdout=esclave, stderr=esclave, stdin=subprocess.DEVNULL, start_new_session=True)
        os.close(esclave)
        brut = b""
        if interrupre_apres:
            time.sleep(interrupre_apres)
            os.killpg(os.getpgid(process.pid), signal.SIGINT)
        while process.poll() is None:
            pret, _, _ = select.select([maitre], [], [], 0.5)
            if pret:
                try:
                    brut += os.read(maitre, 65536)
                except OSError:
                    break
        code = process.wait(timeout=30)
        os.close(maitre)
        return sans_couleur(brut.decode("utf-8", "replace")), code

    def test_barre_de_progression_reste_sur_une_seule_ligne(self):
        sortie, code = self.executer_en_terminal(
            ["-u", self.lab.url, "-U", "admin", "-w", str(DICO_LABO),
             "-d", "0.15", "-k", "12"])
        self.assertEqual(code, 0, sortie)
        self.assertIn("MOT DE PASSE TROUVÉ", sortie)

        # la barre est bien écrite, et réutilise la ligne : entre la première
        # et la dernière image, il ne doit y avoir aucun retour à la ligne
        images = list(re.finditer(r"\[[#.]+\]\s+\d+\.\d+%", sortie))
        self.assertGreaterEqual(len(images), 2, "la barre n'a pas été mise à jour")
        entre_les_barres = sortie[images[0].start():images[-1].end()]
        self.assertNotIn("\n", entre_les_barres,
                         "chaque image de barre a fait défiler une nouvelle ligne")
        self.assertGreaterEqual(entre_les_barres.count("\r"), len(images) - 1,
                                "les images de barre ne sont pas séparées par un retour chariot")

    def test_progression_effacee_avant_le_bilan(self):
        sortie, _ = self.executer_en_terminal(
            ["-u", self.lab.url, "-U", "admin", "-w", str(DICO_LABO),
             "-d", "0.15", "-k", "12"])
        lignes = [ligne.rstrip() for ligne in etat_terminal(sortie)]

        # état final du terminal : plus aucune trace de la barre
        self.assertFalse([l for l in lignes if re.search(r"\[[#.]+\]", l)],
                         "la barre a été laissée à l'écran")
        # le « SUCCÈS » ne doit pas être collé au texte de la barre
        succes = next(l for l in lignes if "SUCCÈS" in l)
        self.assertNotIn("%", succes, "la ligne de succès est corrompue")
        self.assertNotIn("]", succes)
        bilan = next(l for l in lignes if "Bilan" in l)
        self.assertRegex(bilan, r"^── Bilan ─+$", f"ligne de bilan inattendue : {bilan!r}")
        self.assertTrue(any("Essais" in l and "12" in l for l in lignes))

    def test_progression_effacee_sans_reussite(self):
        # le bilan doit rester lisible même quand rien n'est trouvé
        sortie, code = self.executer_en_terminal(
            ["-u", self.lab.url, "-U", "admin", "-w", str(DICO_LABO),
             "-d", "0.1", "-k", "5"])
        self.assertEqual(code, 2, sortie)
        lignes = [ligne.rstrip() for ligne in etat_terminal(sortie)]
        self.assertFalse([l for l in lignes if re.search(r"\[[#.]+\]", l)],
                         "la barre a été laissée à l'écran")
        self.assertTrue(any("aucun couple trouvé" in l for l in lignes))

    def test_sortie_non_terminale_sans_code_ansi(self):
        sortie, code = self.lab.executer(self.lab.base("-k", "4"))
        self.assertEqual(code, 2, sortie)
        self.assertNotIn("\x1b[", sortie, "pas de couleur sans terminal")
        self.assertNotIn("\r", sortie)

    def test_ctrl_c_code_130_et_rapport_partiel(self):
        sortie, code = self.executer_en_terminal(
            ["-u", self.lab.url, "-U", "admin", "-w", str(DICO_LABO), "-d", "1"],
            interrupre_apres=3.5)
        self.assertEqual(code, 130, "un essai interrompu doit renvoyer 130, pas 2")

        rapports = sorted((RACINE / "resultats").glob("rapport_*.json"))
        self.assertTrue(rapports, "aucun rapport après interruption")
        donnees = json.loads(rapports[-1].read_text(encoding="utf-8"))
        self.assertTrue(donnees["interrompu"])
        self.assertIn("Interruption", donnees["erreurs"])
        self.assertLess(donnees["tentatives_effectuees"], donnees["tentatives_prevues"])


class TestModeInteractif(unittest.TestCase):
    """L'interface guidée doit reprendre exactement les valeurs saisies."""

    QUESTIONS = (
        "URL du formulaire",
        "Champ pour l'identifiant",
        "Champ pour le mot de passe",
        "Type de corps",
        "Identifiants",
        "Dictionnaire",
        "Délai",
        "maximum d'essais",
        "Confirmer",
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls.lab = Laboratoire()
        cls.dico = RACINE / "dico_test_interactif.txt"
        cls.dico.write_text("aaa\nbbb\nccc\nLab2024!\n", encoding="utf-8")
        if (RACINE / "resultats").exists():
            shutil.rmtree(RACINE / "resultats")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.lab.arreter()
        cls.dico.unlink(missing_ok=True)
        if (RACINE / "resultats").exists():
            shutil.rmtree(RACINE / "resultats")

    def test_parcours_complet(self):
        reponses = "\n".join([
            self.lab.url,   # URL
            "",              # utiliser l'action détectée
            "",              # méthode -> POST
            "",              # champ login -> login
            "",              # champ mot de passe -> pass
            "",              # type de corps -> form
            "n",             # champ supplémentaire ? non
            "admin",         # identifiant
            "dico_test_interactif.txt",   # dictionnaire
            "0.02",          # délai
            "0",             # nombre maximum d'essais
            "",              # motif de réussite -> automatique
            "",              # motif d'échec -> automatique
            "o",             # lancer
        ]) + "\n"
        resultat = subprocess.run(
            [sys.executable, str(BRUTEFORCE)], cwd=RACINE, input=reponses,
            capture_output=True, text=True, timeout=90)
        sortie = sans_couleur(resultat.stdout + resultat.stderr)
        self.assertEqual(resultat.returncode, 0, sortie)
        # le dictionnaire saisi doit être respecté, pas le dico.txt par défaut
        self.assertIn("4 mots", sortie)
        self.assertIn("Lab2024!", sortie)
        self.assertIn("csrf_token", sortie)
        self.assertNotIn("Réponse inhabituelle", sortie)


class TestJetonDeSession(BaseOutils):
    """Un jeton lié à la session doit être rechargé, sinon plus rien ne passe.

    C'est le comportement de DVWA, et le piège classique d'une démonstration :
    l'outil paraît fonctionner (les requêtes partent) mais la cible rejette
    toutes les tentatives.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.lab = Laboratoire("--profil", "dvwa", chemin="/dvwa/login.php")
        if (RACINE / "resultats").exists():
            shutil.rmtree(RACINE / "resultats")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.lab.arreter()
        if (RACINE / "resultats").exists():
            shutil.rmtree(RACINE / "resultats")

    def base(self, *options: str) -> list[str]:
        return ["-u", self.lab.url, "-U", "admin", "-w", str(DICO_META), "-d", "0", *options]

    def test_jeton_perime_sans_rafraichissement(self):
        sortie, code = self.lab.executer(self.base("--profil", "dvwa", "--no-refresh-csrf",
                                                   "-k", "4"))
        self.assertEqual(code, 2, sortie)
        self.assertNotIn("MOT DE PASSE TROUVÉ", sortie)
        # la cible a bien reçu les requêtes, elle les a rejetées
        with urllib.request.urlopen(f"http://127.0.0.1:{self.lab.port}/health", timeout=3) as r:
            self.assertGreater(json.loads(r.read())["tentatives"], 0)

    def test_avec_rafraichissement_le_mot_de_passe_est_trouve(self):
        sortie, code = self.lab.executer(self.base("--profil", "dvwa"))
        self.assertEqual(code, 0, sortie)
        self.assertIn("MOT DE PASSE TROUVÉ", sortie)
        self.assertIn("password", sortie)
        self.assertIn("Jeton CSRF rafraîchi", sortie)

    def test_profil_dvwa_renseigne_les_bons_champs(self):
        sortie, code = self.lab.executer(self.base("--profil", "dvwa", "--dry-run"))
        self.assertEqual(code, 0, sortie)
        self.assertIn("username", sortie)
        self.assertIn("user_token", sortie)

    def test_option_explicite_prime_sur_le_profil(self):
        sortie, _ = self.lab.executer(self.base("--profil", "dvwa", "--dry-run",
                                                "-p", "champ_du_profil_ecrase"))
        self.assertIn("champ_du_profil_ecrase", sortie)


class TestProfilsDApplications(unittest.TestCase):
    """Les profils reproduisent la façon dont ces applications répondent."""

    DICO = RACINE / "dico_metasploitable.txt"
    CHEMINS = {"dvwa": "/dvwa/login.php", "wordpress": "/wp-login.php",
               "mutillidae": "/mutillidae/index.php",
               "phpmyadmin": "/phpmyadmin/index.php", "webgoat": "/webgoat/login",
               "tomcat": "/manager/html"}
    # identifiant attendu par le profil : le laboratoire interne utilise admin,
    # les autres applications ont leurs propres comptes par défaut
    IDENTIFIANTS = {"dvwa": "admin", "wordpress": "admin", "mutillidae": "admin",
                    "phpmyadmin": "root", "webgoat": "webgoat", "tomcat": "tomcat"}

    def lancer(self, profil: str, *options: str) -> tuple[Laboratoire, list[str], int]:
        lab = Laboratoire("--profil", profil, chemin=self.CHEMINS[profil])
        sortie, code = lab.executer(
            ["-u", lab.url, "-U", self.IDENTIFIANTS[profil], "-w", str(self.DICO),
             "-d", "0", "--profil", profil, *options])
        return lab, sortie, code

    @classmethod
    def setUpClass(cls) -> None:
        if (RACINE / "resultats").exists():
            shutil.rmtree(RACINE / "resultats")

    @classmethod
    def tearDownClass(cls) -> None:
        if (RACINE / "resultats").exists():
            shutil.rmtree(RACINE / "resultats")

    def test_racine_redirigee_vers_le_profil(self):
        """Viser la racine ne doit pas produire un « aucun couple trouvé ».

        Un debutant qui lance l'outil sur http://127.0.0.1:port/ sans
        connaitre le chemin du profil verrait sinon un 404 et aucune
        conclusion. Chaque profil redirige donc la racine vers sa page.
        """
        for profil, identifiant in self.IDENTIFIANTS.items():
            with self.subTest(profil=profil):
                lab = Laboratoire("--profil", profil, chemin="/")
                try:
                    sortie, code = lab.executer(
                        ["-u", lab.url, "-U", identifiant, "-w", str(self.DICO),
                         "-d", "0", "--profil", profil])
                    self.assertEqual(code, 0, sortie)
                    self.assertIn("MOT DE PASSE TROUVÉ", sortie)
                finally:
                    lab.arreter()

    def test_dvwa_reussit_par_redirection(self):
        lab, sortie, code = self.lancer("dvwa")
        try:
            self.assertEqual(code, 0, sortie)
            self.assertIn("MOT DE PASSE TROUVÉ", sortie)
            rapports = sorted((RACINE / "resultats").glob("rapport_*.json"))
            donnees = json.loads(rapports[-1].read_text(encoding="utf-8"))
            self.assertEqual(donnees["reussites"][0]["http"], 302)
        finally:
            lab.arreter()

    def test_wordpress_champs_log_et_pwd(self):
        lab, sortie, code = self.lancer("wordpress")
        try:
            self.assertEqual(code, 0, sortie)
            self.assertIn("admin : admin", sortie)
        finally:
            lab.arreter()

    def test_mutillidae_accepte_le_premier_couple(self):
        lab, sortie, code = self.lancer("mutillidae")
        try:
            self.assertEqual(code, 0, sortie)
            # aucun dictionnaire n'est nécessaire : c'est le but de la démonstration
            self.assertIn("Essai n°1", sortie)
        finally:
            lab.arreter()

    def test_phpmyadmin_champs_pma(self):
        lab, sortie, code = self.lancer("phpmyadmin")
        try:
            self.assertEqual(code, 0, sortie)
            self.assertIn("pma_username", sortie)
            self.assertIn("root : toor", sortie)
        finally:
            lab.arreter()

    def test_phpmyadmin_echoue_avec_les_champs_par_defaut(self):
        """Sans --profil, pma_username/pma_password ne sont pas envoyés."""
        lab = Laboratoire("--profil", "phpmyadmin", chemin=self.CHEMINS["phpmyadmin"])
        try:
            sortie, code = lab.executer(["-u", lab.url, "-U", "root",
                                         "-w", str(self.DICO), "-d", "0"])
            self.assertEqual(code, 2, sortie)
            self.assertIn("aucun couple", sortie)
        finally:
            lab.arreter()

    def test_webgoat_rafraichit_le_jeton(self):
        lab, sortie, code = self.lancer("webgoat")
        try:
            self.assertEqual(code, 0, sortie)
            self.assertIn("webgoat : webgoat", sortie)
            self.assertIn("csrf", sortie)
        finally:
            lab.arreter()

    def test_tomcat_authentification_basic(self):
        lab, sortie, code = self.lancer("tomcat")
        try:
            self.assertEqual(code, 0, sortie)
            self.assertIn("HTTP Basic", sortie)
            self.assertIn("tomcat : tomcat", sortie)
        finally:
            lab.arreter()

    def test_tomcat_sans_basic_auth_ne_trouve_rien(self):
        """Sans --basic-auth, aucun identifiant n'est envoyé : que des 401."""
        lab = Laboratoire("--profil", "tomcat", chemin=self.CHEMINS["tomcat"])
        try:
            sortie, code = lab.executer(["-u", lab.url, "-U", "tomcat",
                                         "-w", str(self.DICO), "-d", "0", "-k", "3"])
            self.assertEqual(code, 2, sortie)
            self.assertIn("aucun couple", sortie)
        finally:
            lab.arreter()

    def test_tomcat_realm_identique_au_vrai_tomcat(self):
        """Le realm annonce doit correspondre à celui du Tomcat réel."""
        lab = Laboratoire("--profil", "tomcat", chemin=self.CHEMINS["tomcat"])
        try:
            reponse = urllib.request.urlopen(lab.url, timeout=5)
            self.fail("le gestionnaire Tomcat doit renvoyer 401")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 401)
            self.assertEqual(exc.headers["WWW-Authenticate"],
                             'Basic realm="Tomcat Manager Application"')
        finally:
            lab.arreter()

    def test_tomcat_option_basic_auth_explicite(self):
        lab = Laboratoire("--profil", "tomcat", chemin=self.CHEMINS["tomcat"])
        try:
            sortie, code = lab.executer(["-u", lab.url, "-U", "tomcat",
                                         "-w", str(self.DICO), "-d", "0",
                                         "--basic-auth", "-m", "GET"])
            self.assertEqual(code, 0, sortie)
        finally:
            lab.arreter()

    def test_profil_inconnu_refuse(self):
        resultat = subprocess.run(
            [sys.executable, str(BRUTEFORCE), "--profil", "inexistant", "-u", "http://127.0.0.1/",
             "-U", "admin"], cwd=RACINE, capture_output=True, text=True, timeout=30,
            stdin=subprocess.DEVNULL)
        self.assertEqual(resultat.returncode, 2)
        self.assertIn("profil", resultat.stderr.lower())


class TestOutilsSecondaires(unittest.TestCase):
    """test.py (inspecteur) et bruteforcessh.py (version simplifiée)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.lab = Laboratoire()
        if (RACINE / "resultats").exists():
            shutil.rmtree(RACINE / "resultats")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.lab.arreter()
        if (RACINE / "resultats").exists():
            shutil.rmtree(RACINE / "resultats")

    def lancer(self, arguments: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, *arguments], cwd=RACINE,
                              capture_output=True, text=True, timeout=60,
                              stdin=subprocess.DEVNULL)

    def test_inspecteur_identifie_les_champs(self):
        resultat = self.lancer(
            ["test.py", "-u", self.lab.url, "-U", "admin", "-P", "Lab2024!"])
        sortie = sans_couleur(resultat.stdout + resultat.stderr)
        self.assertEqual(resultat.returncode, 0, sortie)
        self.assertIn("rôle=IDENTIFIANT", sortie)
        self.assertIn("rôle=MOT DE PASSE", sortie)
        self.assertIn("rôle=jeton technique", sortie)
        self.assertIn("DIFFERENT", sortie)

    def test_inspecteur_ne_confond_pas_jeton_et_identifiant(self):
        sortie = self.lancer(["test.py", "-u", self.lab.url, "-U", "admin"]).stdout
        self.assertIn("champ login", sortie)
        self.assertNotRegex(sortie, r"csrf_token\s*:\s*IDENTIFIANT")

    def test_version_simplifiee_trouve_avec_motif(self):
        resultat = self.lancer(
            ["bruteforcessh.py", "-u", self.lab.url, "-U", "admin", "-w", str(DICO_LABO),
             "-d", "0.02", "-s", "Connexion réussie", "-f", "Mot de passe invalide"])
        sortie = sans_couleur(resultat.stdout + resultat.stderr)
        self.assertEqual(resultat.returncode, 0, sortie)
        self.assertIn("TROUVE", sortie)
        self.assertIn("Lab2024!", sortie)

    def test_version_simplifiee_sans_motif_donne_un_code_3(self):
        resultat = self.lancer(
            ["bruteforcessh.py", "-u", self.lab.url, "-U", "admin", "-w", str(DICO_LABO),
             "-d", "0.02", "-k", "2"])
        self.assertEqual(resultat.returncode, 3, resultat.stdout)
        self.assertIn("indéterminé", resultat.stdout)



class TestCibleReelle(unittest.TestCase):
    """Ce que la vraie VM de Metasploitable2 a appris, sans la joindre.

    Chaque test reproduit ici une page observée sur la VM d'atelier, afin que
    la régression soit vérifiable hors ligne.
    """

    def setUp(self) -> None:
        self.bf = charger_module("bruteforce")

    class Reponse:
        """Fausse réponse HTTP, suffisante pour calculer une empreinte."""

        def __init__(self, corps: str, statut: int = 200) -> None:
            self.text = corps
            self.status_code = statut
            self.history: list = []
            self.headers: dict = {}

    # --- le bouton de validation ------------------------------------------

    def test_bouton_de_validation_envoye_automatiquement(self):
        """Le vrai DVWA n'exécute son handler que si $_POST['Login'] existe.

        Sans le bouton, la page revient identique, sans le moindre message
        d'erreur : l'outil croyait à un échec d'authentification.
        """
        page = """<form action="login.php" method="post">
        <input type="text" name="username">
        <input type="password" name="password">
        <p class="submit"><input type="submit" value="Login" name="Login"></p>
        </form>"""
        champs = self.bf.parse_forms(page)[0].fields
        boutons = [(f.name, f.value) for f in champs
                   if f.type in ("submit", "button") and f.name]
        self.assertEqual(boutons, [("Login", "Login")])

    def test_bouton_non_propose_comme_champ_identifiant(self):
        """--inspect doit proposer username, et surtout pas le bouton Login."""
        page = """<form action="login.php" method="post">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="submit" value="Login" name="Login">
        </form>"""
        formulaire = self.bf.parse_forms(page)[0]
        meilleur, score = None, -1
        for champ in formulaire.fields:
            if champ.type in ("hidden", "password"):
                continue
            if champ.type in self.bf.CHAMPS_NON_SAISISSABLES:
                continue
            note = self.bf.guess_role(champ.name, "login")
            if note > score:
                meilleur, score = champ.name, note
        self.assertEqual(meilleur, "username")

    # --- la page qui renvoie les identifiants ------------------------------

    def test_page_qui_renvoie_les_identifiants(self):
        """Le vrai Mutillidae renvoie l'identifiant et le mot de passe reçus."""
        masque = self.bf.masque_les_valeurs
        self.assertIn("<ESSAI>", masque("password='essai'", ("essai",)))
        self.assertIn("<ESSAI>", masque('value="essai"', ("essai",)))
        # le balisage du formulaire, lui, ne bouge pas
        intact = 'type="password" name="password"'
        self.assertEqual(masque(intact, ("password",)), intact)

    def test_empreintes_identiques_quand_les_echecs_varient(self):
        """Deux échecs qui ne diffèrent que par la valeur renvoyée.

        C'est la situation du vrai Mutillidae. Avant le masquage, chaque
        essai changeait la longueur de la page : le moteur concluait à une
        réussite au premier essai.
        """
        # ligne réellement renvoyée par le Mutillidae de la VM
        modele = ('<td class="error-label">Diagnotic Information</td>'
                  '<td class="error-detail">SELECT * FROM accounts WHERE '
                  "username='admin' AND password='{m}'</td>")
        empreintes = set()
        for mot in ("admin", "motdepasse-long", "P@ssw0rd-2024", "zzz-inconnu"):
            corps = modele.format(m=mot)
            empreintes.add(self.bf.fingerprint_of(
                self.Reponse(corps), ("admin", mot)).digest)
        self.assertEqual(len(empreintes), 1,
                         "les pages d'échec doivent partager une empreinte")

    def test_longitudes_comparees_par_tranches(self):
        """Deux pages presque identiques ne doivent pas changer de cluster."""
        gauche = self.bf.fingerprint_of(self.Reponse("x" * 1000))
        droite = self.bf.fingerprint_of(self.Reponse("x" * 1010))
        self.assertEqual(gauche.cluster, droite.cluster)

    def test_reussite_toujours_reconnue(self):
        """Le masquage ne doit pas noyer une vraie réussite."""
        echec = ("SELECT * FROM accounts WHERE username='admin' "
                 "AND password='essai'")
        # même longueur, contenu différent : le cas limite doit rester prudent
        meme_taille = "<html><h1>Connecté en tant que admin</h1></html>"
        # page d'accueil, nettement plus longue (le cas de Tomcat)
        accueil = "<html><body>" + ("Bienvenue sur le Tomcat Manager. " * 8) + "</body></html>"
        moteur = self.bf.DetectionEngine([], [], False)
        moteur.baseline = self.bf.fingerprint_of(self.Reponse(echec), ("essai",))
        self.assertIs(moteur.classify(self.Reponse(meme_taille)), self.bf.Verdict.SUSPECT)
        self.assertIs(moteur.classify(self.Reponse(accueil)), self.bf.Verdict.SUCCESS)
        # et un motif explicite l'emporte toujours
        explicite = self.bf.DetectionEngine(["Connecté"], [], False)
        self.assertIs(explicite.classify(self.Reponse(meme_taille)),
                      self.bf.Verdict.SUCCESS)


if __name__ == "__main__":
    unittest.main(verbosity=2 if "-v" in sys.argv else 1)