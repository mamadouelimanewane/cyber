"""
Gravity Security — Lanceur tout-en-un (sans Docker)

Usage:
  python start.py              # Lance tout (serveur + collector + console)
  python start.py --no-console # Serveur + collector seulement
  python start.py --server     # Serveur seul
  python start.py --check      # Vérifie les dépendances et quitte

Ports:
  8000 — Serveur central (API + WebSocket)
  8001 — Collector régional
  5173 — Console web (npm run dev)
"""
import argparse
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

BASE = Path(__file__).parent

# ── Couleurs ANSI ─────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"

COLORS = {
    "server":    ("\033[94m", "[SERVER   ]"),   # bleu
    "collector": ("\033[92m", "[COLLECTOR]"),   # vert
    "console":   ("\033[96m", "[CONSOLE  ]"),   # cyan
    "launcher":  ("\033[93m", "[GRAVITY  ]"),   # jaune
}

def log(component: str, msg: str, error: bool = False):
    color, tag = COLORS.get(component, (GRAY, f"[{component.upper()[:8]}]"))
    stream = sys.stderr if error else sys.stdout
    prefix = RED + tag if error else color + tag
    print(f"{prefix}{RESET} {msg}", file=stream)

# ── Vérification des dépendances ──────────────────────────────────────────────

def check_deps() -> bool:
    ok = True
    log("launcher", f"{BOLD}Vérification des dépendances...{RESET}")

    # Python packages
    required_packages = ["fastapi", "uvicorn", "pydantic", "websockets", "aiosqlite"]
    for pkg in required_packages:
        try:
            __import__(pkg.replace("-", "_"))
            log("launcher", f"  {GREEN}✓{RESET} {pkg}")
        except ImportError:
            log("launcher", f"  {RED}✗{RESET} {pkg} — installer avec: pip install {pkg}", error=True)
            ok = False

    # Node.js pour la console
    node = shutil.which("node")
    npm  = shutil.which("npm")
    if node and npm:
        node_ver = subprocess.check_output([node, "--version"], text=True).strip()
        log("launcher", f"  {GREEN}✓{RESET} Node.js {node_ver}")
    else:
        log("launcher", f"  {YELLOW}!{RESET} Node.js non trouvé — console web indisponible")

    # node_modules
    console_dir = BASE / "console"
    if (console_dir / "node_modules").exists():
        log("launcher", f"  {GREEN}✓{RESET} node_modules présent")
    elif npm:
        log("launcher", f"  {YELLOW}!{RESET} node_modules absent — exécution de npm install...")
        subprocess.run([npm, "install"], cwd=console_dir, check=False)

    return ok

# ── Lecteur de sortie (thread) ────────────────────────────────────────────────

def stream_output(proc: subprocess.Popen, component: str):
    """Lit stdout+stderr d'un processus et les affiche avec préfixe coloré."""
    def _read(stream, error):
        try:
            for line in iter(stream.readline, ""):
                line = line.rstrip()
                if line:
                    log(component, line, error=error)
        except Exception:
            pass

    t1 = threading.Thread(target=_read, args=(proc.stdout, False), daemon=True)
    t2 = threading.Thread(target=_read, args=(proc.stderr, True),  daemon=True)
    t1.start()
    t2.start()

# ── Processus gérés ───────────────────────────────────────────────────────────

_procs: list[subprocess.Popen] = []

def start_server() -> subprocess.Popen:
    env = os.environ.copy()
    env["PYTHONPATH"]      = str(BASE / "server")
    env["DB_URL"]          = f"sqlite+aiosqlite:///{BASE}/data/gravity.db"
    env["SHARED_SECRET"]   = env.get("SHARED_SECRET", "gravity-dev-secret")
    env["PYTHONUNBUFFERED"] = "1"

    # Créer le dossier data si nécessaire
    (BASE / "data").mkdir(exist_ok=True)

    cmd = [
        sys.executable, "-m", "uvicorn",
        "src.main:app",
        "--host", "0.0.0.0",
        "--port", "8000",
        "--reload",
        "--reload-dir", str(BASE / "server" / "src"),
        "--log-level", "warning",
    ]
    proc = subprocess.Popen(
        cmd, cwd=BASE / "server", env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    stream_output(proc, "server")
    log("launcher", f"{GREEN}Serveur démarré{RESET} → http://localhost:8000  (PID {proc.pid})")
    return proc


def start_collector() -> subprocess.Popen:
    env = os.environ.copy()
    env["PYTHONPATH"]       = str(BASE / "collector")
    env["COLLECTOR_ID"]     = "local-collector-001"
    env["CENTRAL_URL"]      = "http://localhost:8000"
    env["SHARED_SECRET"]    = env.get("SHARED_SECRET", "gravity-dev-secret")
    env["FLUSH_INTERVAL"]   = "3"
    env["PYTHONUNBUFFERED"] = "1"

    cmd = [sys.executable, str(BASE / "collector" / "src" / "main.py")]
    proc = subprocess.Popen(
        cmd, cwd=BASE / "collector", env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    stream_output(proc, "collector")
    log("launcher", f"{GREEN}Collector démarré{RESET} → http://localhost:8001  (PID {proc.pid})")
    return proc


def start_console() -> subprocess.Popen | None:
    npm = shutil.which("npm")
    if not npm:
        log("launcher", f"{YELLOW}Console web ignorée{RESET} (Node.js non disponible)")
        return None

    console_dir = BASE / "console"
    env = os.environ.copy()
    env["VITE_API_URL"] = "http://localhost:8000"
    env["VITE_WS_URL"]  = "ws://localhost:8000/ws"

    cmd = [npm, "run", "dev", "--", "--host", "0.0.0.0"]
    proc = subprocess.Popen(
        cmd, cwd=console_dir, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    stream_output(proc, "console")
    log("launcher", f"{GREEN}Console démarrée{RESET} → http://localhost:5173  (PID {proc.pid})")
    return proc

# ── Arrêt propre ──────────────────────────────────────────────────────────────

def shutdown(sig=None, frame=None):
    print()
    log("launcher", f"{YELLOW}Arrêt en cours...{RESET}")
    for p in _procs:
        try:
            p.terminate()
        except Exception:
            pass
    time.sleep(1)
    for p in _procs:
        try:
            if p.poll() is None:
                p.kill()
        except Exception:
            pass
    log("launcher", f"{GREEN}Tous les processus arrêtés.{RESET}")
    sys.exit(0)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Gravity Security — Lanceur")
    parser.add_argument("--no-console", action="store_true", help="Ne pas lancer la console web")
    parser.add_argument("--server",     action="store_true", help="Serveur central seulement")
    parser.add_argument("--check",      action="store_true", help="Vérifier les dépendances et quitter")
    args = parser.parse_args()

    # Bannière
    print(f"\n{BOLD}{BLUE}{'='*55}")
    print(f"  GRAVITY SECURITY -- Lanceur Local (sans Docker)")
    print(f"{'='*55}{RESET}\n")

    if not check_deps():
        sys.exit(1)

    if args.check:
        log("launcher", f"{GREEN}Dépendances OK{RESET}")
        sys.exit(0)

    # Signaux d'arrêt
    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Lancement
    log("launcher", "Démarrage des composants...")
    time.sleep(0.3)

    server_proc = start_server()
    _procs.append(server_proc)

    if not args.server:
        time.sleep(1.5)  # Laisser le serveur démarrer avant le collector
        collector_proc = start_collector()
        _procs.append(collector_proc)

        if not args.no_console:
            time.sleep(0.5)
            console_proc = start_console()
            if console_proc:
                _procs.append(console_proc)

    print()
    log("launcher", f"{BOLD}Stack Gravity Security opérationnelle{RESET}")
    log("launcher", f"  API     → {CYAN}http://localhost:8000/docs{RESET}")
    log("launcher", f"  Console → {CYAN}http://localhost:5173{RESET}")
    log("launcher", f"  Appuyer {BOLD}Ctrl+C{RESET} pour arrêter")
    print()

    # Surveiller les processus
    try:
        while True:
            time.sleep(2)
            for proc in list(_procs):
                ret = proc.poll()
                if ret is not None and ret != 0:
                    # Processus crashé — identifier lequel
                    name = next(
                        (k for k, (c, t) in COLORS.items()
                         if proc.pid and k in ["server", "collector", "console"]),
                        "composant"
                    )
                    log("launcher", f"{RED}Processus {proc.pid} terminé (code {ret}){RESET}", error=True)
    except KeyboardInterrupt:
        shutdown()

if __name__ == "__main__":
    main()
