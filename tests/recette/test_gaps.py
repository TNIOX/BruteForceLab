import tempfile
import atexit
import shutil
import socket
import json, re, subprocess, sys, time, urllib.request
from pathlib import Path
BASE = Path(__file__).resolve().parents[2]


def port_libre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
SCRATCH = Path(tempfile.mkdtemp(prefix='recette-'))
atexit.register(shutil.rmtree, SCRATCH, True)
PORT = port_libre()
DICT = BASE / "dico_labo.txt"
lab = subprocess.Popen([sys.executable, "lab_server.py", "--port", str(PORT), "--quiet"],
                       cwd=BASE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
for _ in range(60):
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=1).read(); break
    except Exception: time.sleep(0.15)
U = f"http://127.0.0.1:{PORT}/login"
API = f"http://127.0.0.1:{PORT}/api/login"
res = []
def run(nom, args, attendus, t=60, expect=None):
    try:
        r = subprocess.run([sys.executable, "bruteforce.py", *args], cwd=BASE,
                           capture_output=True, text=True, timeout=t)
        out = re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr)
        code = r.returncode
    except subprocess.TimeoutExpired:
        out, code = "<<TIMEOUT>>", -1
    manque = [a for a in attendus if a not in out]
    ok = not manque and (expect is None or code == expect)
    res.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {nom}  (code={code})"
          + (f"  manque={manque}" if manque else ""))
    if not ok and "-v" in sys.argv:
        print("   >>", out.strip().replace("\n", "\n   >> ")[:1500])
    return out
try:
    base = ["-u", U, "-U", "admin", "-w", "dico_labo.txt", "-d", "0"]
    run("A. --no-calibration (strategie statistique)", base + ["--no-calibration"],
        ["Lab2024!", "statistique"], expect=0)
    run("B. -e / --extra-field", base + ["-e", "remember=1"],
        ["Lab2024!"], expect=0)
    run("C. -H / --header", base + ["-H", "X-Lab: 1", "-H", "X-Deux: 2"], ["Lab2024!"], expect=0)
    run("D. -c / --cookie", base + ["-c", "session=abc"], ["Lab2024!"], expect=0)
    run("E. --user-agent", base + ["--user-agent", "Mozilla/5.0"], ["Lab2024!"], expect=0)
    run("F. -T json (endpoint /api/login)", ["-u", API, "-U", "admin", "-w", "dico_labo.txt",
        "-d", "0", "-T", "json", "-l", "login", "-p", "pass"], ["Lab2024!"], expect=0)
    rapports = SCRATCH / "rapports"
    run("G. --results-dir", base + ["--results-dir", str(rapports)],
        [str(rapports / "rapport_")], expect=0)
    run("H. -t / --timeout", base + ["-t", "5"], ["Lab2024!"], expect=0)
    run("I. -I / --insecure (http, sans effet)", base + ["-I"], ["Lab2024!"], expect=0)
    run("J. --stop-on-suspect", base + ["--stop-on-suspect"], ["Lab2024!"], expect=0)
    run("K. dictionnaire absent", ["-u", U, "-U", "admin", "-w", str(SCRATCH / "nexiste.txt")],
        ["introuvable"], expect=1)
    run("L. --url absent", ["-U", "admin"], ["obligatoire"], expect=2)
    run("M. --user absent", ["-u", U], ["obligatoire"], expect=2)
    run("N. champs multiples -U repete", ["-u", U, "-U", "root", "-U", "admin",
                                          "-w", "dico_labo.txt", "-d", "0"],
        ["admin", "root", "Essais pour"], expect=0)
    # Verrouillage declenche par un TEXTE, sans code 429
    run("O. sans verrouillage (controle)", base + ["-k", "20"], ["Lab2024!"], expect=0)
finally:
    lab.terminate()
print(f"\n{len(res)-sum(res)} echec(s) sur {len(res)}")
sys.exit(1 if not all(res) else 0)
