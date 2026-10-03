import tempfile
import atexit
import shutil
import socket
#!/usr/bin/env python3
"""Banc de test automatisé pour bruteforce.py contre lab_server.py."""
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]


def port_libre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
SCRATCH = Path(tempfile.mkdtemp(prefix='recette-'))
atexit.register(shutil.rmtree, SCRATCH, True)
PORT = port_libre()
URL = f"http://127.0.0.1:{PORT}/login"
DICT = SCRATCH / "testdict.txt"

DICT.write_text(
    "\n".join(["admin", "123456", "motdepasse", "password", "qwerty",
               "azerty", "Lab2024!", "letmein", "welcome", "secret"]) + "\n",
    encoding="utf-8",
)

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def start_lab(extra=None):
    args = [sys.executable, "lab_server.py", "--port", str(PORT), "--quiet"]
    if extra:
        args += extra
    proc = subprocess.Popen(args, cwd=BASE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True)
    for _ in range(60):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=1).read()
            return proc
        except Exception:
            time.sleep(0.15)
    proc.kill()
    raise RuntimeError("le serveur de laboratoire n'a pas démarré")


def run(args, expect_code=None):
    result = subprocess.run([sys.executable, "bruteforce.py", *args], cwd=BASE,
                            capture_output=True, text=True, timeout=120)
    out = ANSI.sub("", result.stdout + result.stderr)
    tag = "OK " if (expect_code is None or result.returncode == expect_code) else "ECHEC"
    print(f"\n{'=' * 70}\n[{tag}] {' '.join(args)}  (code={result.returncode})\n{'=' * 70}")
    print(out.rstrip())
    return out, result.returncode


def check(label, condition, detail=""):
    print(f"  {'PASS' if condition else 'FAIL'}  {label}{(' — ' + detail) if detail else ''}")
    return bool(condition)


def main():
    failures = []
    print("Serveur de laboratoire :", URL)
    lab = start_lab()
    try:
        # 1. Inspection du formulaire
        out, _ = run(["--inspect", "-u", URL])
        failures.append(not check("détecte les 3 champs", all(
            n in out for n in ("login", "pass", "csrf_token"))))
        failures.append(not check("suggère login/pass",
                                  re.search(r"--login-field\s+login", out)
                                  and re.search(r"--password-field\s+pass", out)))

        # 2. Requête simulée
        out, _ = run(["-u", URL, "-U", "admin", "-w", str(DICT), "--dry-run"])
        failures.append(not check("dry-run affiche POST", "POST" in out))
        failures.append(not check("dry-run inclut le csrf", "csrf_token" in out))

        # 3. Trouver le mot de passe
        out, code = run(["-u", URL, "-U", "admin", "-l", "login", "-p", "pass",
                         "-w", str(DICT), "-d", "0", "-k", "50"])
        failures.append(not check("trouve le mot de passe", "Lab2024!" in out
                                  and "MOT DE PASSE TROUVÉ" in out))
        failures.append(not check("code retour 0", code == 0, f"code={code}"))

        # 4. Aucun résultat
        small = SCRATCH / "nodict.txt"
        small.write_text("aaa\nbbb\nccc\n", encoding="utf-8")
        out, code = run(["-u", URL, "-U", "admin", "-w", str(small), "-d", "0"])
        failures.append(not check("aucun résultat => code 2", code == 2, f"code={code}"))

        # 5. Détection par motif explicite
        out, code = run(["-u", URL, "-U", "admin", "-p", "pass", "-w", str(DICT),
                         "-d", "0", "--success-pattern", "Connexion r",
                         "--failure-pattern", "Mot de passe invalide"])
        failures.append(not check("détection par motif", "Lab2024!" in out))

        # 6. Redirection traitée comme succès
        out, code = run(["-u", URL, "-U", "admin", "-w", str(small), "-d", "0",
                         "--success-on-redirect"])
        failures.append(not check("pas de faux positif sur 3xx", "MOT DE PASSE TROUVÉ" not in out))

        # 7. Champ manquant => aucun succès
        out, code = run(["-u", URL, "-U", "admin", "-p", "mauvais_champ", "-w", str(DICT),
                         "-d", "0", "-k", "20"])
        failures.append(not check("mauvais nom de champ => rien", "MOT DE PASSE TROUVÉ" not in out))

        # 8. Rapport JSON produit et valide
        reports = sorted((BASE / "resultats").glob("rapport_*.json"))
        import json
        if reports:
            data = json.loads(reports[-1].read_text(encoding="utf-8"))
            ok = all(k in data for k in ("cible", "tentatives_effectuees", "strategie_detection"))
            failures.append(not check("rapport JSON exploitable", ok, str(reports[-1].name)))
        else:
            failures.append(not check("rapport JSON présent", False))

        # 9. Garde-fou hors réseau privé
        out, code = run(["-u", "https://exemple-public.fr/login", "-U", "admin", "-w", str(DICT)])
        failures.append(not check("bloque la cible publique sans autorisation", code == 1))
        failures.append(not check("message d'autorisation", "--i-have-authorization" in out))
    finally:
        lab.terminate()

    # 10. Verrouillage serveur
    lab2 = start_lab(["--lockout", "5"])
    try:
        out, code = run(["-u", URL, "-U", "admin", "-w", str(DICT), "-d", "0", "-k", "30"])
        failures.append(not check("détecte le verrouillage", "verrouill" in out.lower()))
        failures.append(not check("mentionne l'arrêt immédiat", "arrêt immédiat" in out.lower()))
    finally:
        lab2.terminate()

    print("\n" + "=" * 70)
    print(f"RÉSULTAT : {len([f for f in failures if f])} échec(s) sur {len(failures)} vérification(s)")
    print("=" * 70)
    return 1 if any(failures) else 0


if __name__ == "__main__":
    raise SystemExit(main())
