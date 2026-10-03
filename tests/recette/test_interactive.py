import socket
import re, subprocess, sys, time, urllib.request
from pathlib import Path
BASE = Path(__file__).resolve().parents[2]


def port_libre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
PORT = port_libre()
lab = subprocess.Popen([sys.executable, "lab_server.py", "--port", str(PORT), "--quiet"],
                       cwd=BASE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       start_new_session=True)
for _ in range(60):
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=1).read(); break
    except Exception: time.sleep(0.15)
try:
    d = BASE / "dico_demo.txt"
    d.write_text("# demonstration\naaa\nbbb\nccc\nLab2024!\n", encoding="utf-8")
    answers = "\n".join([
        f"http://127.0.0.1:{PORT}/login",  # 1 URL
        "",                                  # 2 action détectée (défaut oui)
        "",                                  # 3 méthode -> POST
        "",                                  # 4 champ login -> login
        "",                                  # 5 champ mot de passe -> pass
        "",                                  # 6 type de corps -> form
        "n",                                 # 7 champ supplémentaire ? non
        "admin",                             # 8 identifiant
        "dico_demo.txt",                     # 9 dictionnaire
        "0.05",                              # 10 délai
        "5",                                 # 11 max essais
        "",                                  # 12 motif succès -> auto
        "",                                  # 13 motif échec -> auto
        "o",                                 # 14 lancer
    ]) + "\n"
    r = subprocess.run([sys.executable, "bruteforce.py"], cwd=BASE, input=answers,
                       capture_output=True, text=True, timeout=60)
    out = re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr)
    print(out)
    print("CODE RETOUR:", r.returncode)
    import json
    rp = sorted((BASE / "resultats").glob("rapport_*.json"))[-1]
    data = json.loads(rp.read_text())
    print("RAPPORT:", json.dumps({k: data[k] for k in
        ("tentatives_effectuees", "tentatives_prevues", "duree_s",
         "strategie_detection", "reussites", "suspects")}, ensure_ascii=False, indent=2))
    checks = {
        "dictionnaire charge": "Dictionnaire         4 mots" in out,
        "essais prevus = 5": "Essais prévus        4" in out,
        "succes detecte": "MOT DE PASSE TROUVÉ" in out and "Lab2024!" in out,
        "csrf conserve": "csrf_token" in out,
    }
    print("\n--- VERIFICATIONS ---")
    for k, v in checks.items():
        print(f"  {'PASS' if v else 'FAIL'}  {k}")
    d.unlink(missing_ok=True)
    sys.exit(0 if all(checks.values()) else 1)
finally:
    lab.terminate()
