#!/usr/bin/env python3
"""Pilote de vérification manuelle des profils (utilitaire de développement)."""
import socket, subprocess, sys, time, urllib.request, re
from pathlib import Path
RACINE = str(Path(__file__).resolve().parents[2])


def port_libre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def lancer(port, *options):
    p = subprocess.Popen([sys.executable, f"{RACINE}/lab_server.py", "--port", str(port),
                          "--quiet", *options], cwd=RACINE,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    for _ in range(80):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1).read()
            return p
        except Exception:
            time.sleep(0.15)
    p.kill()
    raise SystemExit("serveur muet")


def brute(port, chemin, *options, dico="dico.txt", **kw):
    r = subprocess.run([sys.executable, f"{RACINE}/bruteforce.py",
                        "-u", f"http://127.0.0.1:{port}{chemin}", "-U", "admin",
                        "-w", f"{RACINE}/{dico}", "-d", "0", *options],
                       cwd=RACINE, capture_output=True, text=True, timeout=90,
                       stdin=subprocess.DEVNULL)
    return re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr), r.returncode


def cas(titre, options_lab, chemin, *options_brute, attendu=0, dico="dico.txt"):
    port = port_libre()
    serveur = lancer(port, *options_lab)
    try:
        sortie, code = brute(port, chemin, *options_brute, dico=dico)
    finally:
        serveur.terminate()
        serveur.wait(timeout=5)
    ok = "OK  " if code == attendu else "ECHEC"
    print(f"[{ok}] {titre}  (code={code}, attendu={attendu})")
    for ligne in sortie.splitlines():
        if any(m in ligne for m in ("Champs cachés", "Jeton CSRF", "MOT DE PASSE TROUVÉ",
                                    "Essai n°", "Non classifiables", "aucun couple",
                                    "Erreur", "Détection", "arrêt immédiat", "Blocage",
                                    "aucun formulaire", "Champ pour", "login-field",
                                    "password-field", "hypothèse", "profil")):
            print("        " + ligne.strip()[:110])
    return code == attendu


resultats = []
resultats.append(cas("dvwa --profil dvwa", ("--profil", "dvwa"), "/dvwa/login.php",
                     "--profil", "dvwa", dico="dico_metasploitable.txt"))
resultats.append(cas("dvwa SANS --refresh-csrf (jeton perime)", ("--profil", "dvwa"),
                     "/dvwa/login.php", "--profil", "dvwa", "--no-refresh-csrf", "-k", "4",
                     dico="dico_metasploitable.txt", attendu=2))
resultats.append(cas("dvwa + motifs explicites", ("--profil", "dvwa"), "/dvwa/login.php",
                     "--profil", "dvwa", "--success-pattern", "^$",
                     "--failure-pattern", "Login failed",
                     dico="dico_metasploitable.txt"))
resultats.append(cas("wordpress", ("--profil", "wordpress"), "/wp-login.php",
                     "--profil", "wordpress", dico="dico_metasploitable.txt"))
resultats.append(cas("mutillidae (accepte tout)", ("--profil", "mutillidae"),
                     "/mutillidae/index.php", "--profil", "mutillidae",
                     dico="dico_metasploitable.txt"))
resultats.append(cas("profil interne (non-regression)", ("--profil", "interne"), "/login",
                     dico="dico_labo.txt"))
print()
print(f"{sum(resultats)}/{len(resultats)} cas conformes")
sys.exit(0 if all(resultats) else 1)