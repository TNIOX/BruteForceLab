import tempfile
import atexit
import shutil
import socket
import re, subprocess, sys, time, urllib.request
from pathlib import Path
BASE = Path(__file__).resolve().parents[2]


def port_libre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
SCRATCH = Path(tempfile.mkdtemp(prefix='recette-'))
atexit.register(shutil.rmtree, SCRATCH, True)
PORT = port_libre()
lab = subprocess.Popen([sys.executable, "lab_server.py", "--port", str(PORT), "--quiet"],
                       cwd=BASE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
for _ in range(60):
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=1).read(); break
    except Exception: time.sleep(0.15)
try:
    d = SCRATCH / "g.txt"; d.write_text("aaa\nbbb\nLab2024!\n", encoding="utf-8")
    U = f"http://127.0.0.1:{PORT}/login"
    checks = {}
    for nom, args in [
        ("POST (defaut)", ["-u", U, "-U", "admin", "-w", str(d), "-d", "0", "-m", "POST"]),
        ("GET", ["-u", U, "-U", "admin", "-w", str(d), "-d", "0", "-m", "GET"]),
        ("GET + success-on-redirect", ["-u", U, "-U", "admin", "-w", str(d), "-d", "0",
                                        "-m", "GET", "--success-on-redirect"]),
    ]:
        r = subprocess.run([sys.executable, "bruteforce.py", *args], cwd=BASE,
                           capture_output=True, text=True, timeout=60)
        out = re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr)
        ok = "MOT DE PASSE TROUVÉ" in out and "Lab2024!" in out
        checks[nom] = ok
        print(f"{'PASS' if ok else 'FAIL'}  {nom} (code={r.returncode})")
        if not ok:
            print(out[-1200:])
    sys.exit(0 if all(checks.values()) else 1)
finally:
    lab.terminate()
