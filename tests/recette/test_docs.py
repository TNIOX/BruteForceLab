import socket
import json, re, subprocess, sys, time, urllib.request
from pathlib import Path
BASE = Path(__file__).resolve().parents[2]


def port_libre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
PORT = port_libre()
lab = subprocess.Popen([sys.executable, "lab_server.py", "--port", str(PORT)],
                       cwd=BASE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, start_new_session=True)
for _ in range(60):
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=1).read(); break
    except Exception: time.sleep(0.15)
U = f"http://127.0.0.1:{PORT}/login"
def run(args, t=60):
    r = subprocess.run([sys.executable, *args], cwd=BASE, capture_output=True, text=True, timeout=t)
    return re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr), r.returncode
try:
    cmds = [
      ("§3 etape 2 : --inspect",
       ["bruteforce.py", "--inspect", "-u", U],
       ["--login-field", "login", "--password-field", "pass", "csrf_token"]),
      ("§3 etape 3 : attaque bornee",
       ["bruteforce.py", "-u", U, "-U", "admin", "-l", "login", "-p", "pass", "-w", "dico_labo.txt", "-d", "0.2"],
       ["Lab2024!", "MOT DE PASSE TROUVÉ", "rapport_"]),
      ("§5.3 : --dry-run",
       ["bruteforce.py", "-u", U, "-U", "admin", "--dry-run"],
       ["POST", "csrf_token", "Simulation"]),
      ("§8.1 : --refresh-csrf",
       ["bruteforce.py", "-u", U, "-U", "admin", "-w", "dico_labo.txt", "-d", "0.05", "--refresh-csrf"],
       ["Lab2024!"]),
      ("§6.1 : motifs explicites",
       ["bruteforce.py", "-u", U, "-U", "admin", "-d", "0.05",
        "-w", "dico_labo.txt", "--success-pattern", "Connexion r", "--failure-pattern", "Mot de passe invalide"],
       ["Lab2024!", "motifs explicites"]),
      ("§8.6 : reprise -s 5000",
       ["bruteforce.py", "-u", U, "-U", "admin", "-w", "dico_labo.txt", "-s", "5", "-d", "0.05", "-k", "5"],
       ["Bilan"]),
      ("§8.7 : deux identifiants",
       ["bruteforce.py", "-u", U, "-U", "admin,root", "-w", "dico_labo.txt", "-d", "0.05", "-k", "4"],
       ["Bilan"]),
    ]
    ok_all = True
    for nom, args, attendus in cmds:
        out, code = run(args)
        manquants = [a for a in attendus if a not in out]
        ok = not manquants
        ok_all &= ok
        print(f"{'PASS' if ok else 'FAIL'}  {nom}  (code={code})"
              + (f"  manque: {manquants}" if manquants else ""))
    stats = urllib.request.urlopen(f"http://127.0.0.1:{PORT}/stats", timeout=3).read().decode()
    ok = "Statistiques du laboratoire" in stats
    ok_all &= ok
    print(f"{'PASS' if ok else 'FAIL'}  /stats affiche les tentatives du serveur")
    sante = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=3).read())
    ok = sante["tentatives"] > 0
    ok_all &= ok
    print(f"{'PASS' if ok else 'FAIL'}  /health compte les tentatives ({sante['tentatives']})")
    sys.exit(0 if ok_all else 1)
finally:
    lab.terminate()
