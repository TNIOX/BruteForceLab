#!/usr/bin/env python3
import socket, subprocess, sys, time, re
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
            import urllib.request
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1).read()
            return p
        except Exception:
            time.sleep(0.15)
    p.kill()
    raise SystemExit("serveur muet")


def cas(titre, chemin, options_lab, options_brute, dico, attendu=0, user="root"):
    port = port_libre()
    serveur = lancer(port, *options_lab)
    try:
        r = subprocess.run([sys.executable, f"{RACINE}/bruteforce.py",
                            "-u", f"http://127.0.0.1:{port}{chemin}", "-U", user,
                            "-w", f"{RACINE}/{dico}", "-d", "0", *options_brute],
                           cwd=RACINE, capture_output=True, text=True, timeout=90,
                           stdin=subprocess.DEVNULL)
        sortie, code = re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr), r.returncode
    finally:
        serveur.terminate()
        serveur.wait(timeout=5)
    ok = "OK  " if code == attendu else "ECHEC"
    print(f"[{ok}] {titre}  (code={code}, attendu={attendu})")
    for ligne in sortie.splitlines():
        if any(m in ligne for m in ("Profil", "Authentification", "Champs cachés", "MOT DE PASSE",
                                    "Essai n°", "aucun couple", "aucun formulaire", "Erreur",
                                    "Authorization", "aucun corps")):
            print("        " + ligne.strip()[:100])
    return code == attendu


DICO_META = "dico_metasploitable.txt"
resultats = []
resultats.append(cas("phpmyadmin (pma_username/pma_password)", "/phpmyadmin/index.php",
                     ("--profil", "phpmyadmin"), ("--profil", "phpmyadmin",),
                     DICO_META))
resultats.append(cas("phpmyadmin sans le profil (champs par defaut)", "/phpmyadmin/index.php",
                     ("--profil", "phpmyadmin"), (), DICO_META, attendu=2))
resultats.append(cas("webgoat", "/webgoat/login", ("--profil", "webgoat"),
                     ("--profil", "webgoat",), DICO_META, user="webgoat"))
resultats.append(cas("tomcat (Basic)", "/manager/html", ("--profil", "tomcat"),
                     ("--profil", "tomcat",), DICO_META, user="tomcat"))
resultats.append(cas("tomcat sans --basic-auth", "/manager/html", ("--profil", "tomcat"),
                     ("-k", "3",), DICO_META, attendu=2, user="tomcat"))
resultats.append(cas("tomcat + --basic-auth explicite", "/manager/html", ("--profil", "tomcat"),
                     ("--basic-auth", "-U", "tomcat",), DICO_META))
resultats.append(cas("tomcat, mauvais identifiant", "/manager/html", ("--profil", "tomcat"),
                     ("--profil", "tomcat",), DICO_META, attendu=2, user="admin"))
print()
print(f"{sum(resultats)}/{len(resultats)} cas conformes")
sys.exit(0 if all(resultats) else 1)