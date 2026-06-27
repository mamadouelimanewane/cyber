"""
Gravity Load Simulator — Simule N agents pour valider la scalabilité.

Usage :
  # Simuler 100 agents (mode rapide, terminal)
  python demo/load_simulator.py --agents 100 --rate 10

  # Simuler 10 000 agents sur le collector
  python demo/load_simulator.py --agents 10000 --target http://collector:8001

  # Mode stress test (rafale d'alertes)
  python demo/load_simulator.py --agents 1000 --stress

Métriques affichées :
  - Alertes envoyées / sec
  - Taux de succès / échec
  - Latence p50 / p95 / p99
  - Compression ratio
"""

import argparse
import hashlib
import json
import random
import sys
import threading
import time
import urllib.request
import zlib
from collections import deque
from datetime import datetime
from typing import Dict, List

# ── Données synthétiques ─────────────────────────────────────────────────────

ALERT_TYPES = [
    ("SUSPICIOUS_PROCESS",  0.45, 0.65),
    ("FILE_THREAT",         0.50, 0.75),
    ("MEMORY_THREAT",       0.70, 0.90),
    ("DNA_MUTATION",        0.60, 0.85),
    ("NAC_BLOCK",           0.40, 0.60),
    ("SYSCALL_ANOMALY",     0.55, 0.75),
    ("UEBA_ANOMALY",        0.50, 0.70),
    ("HONEYTOKEN_TRIGGERED",0.90, 0.99),
    ("RANSOMWARE_DETECTED", 0.85, 0.99),
    ("QBSM_COLLAPSE",       0.88, 0.99),
    ("CBGA_GENOME_MATCH",   0.80, 0.95),
    ("SUPPLY_CHAIN_DLL_HIJACK", 0.75, 0.90),
]

PROCESSES = [
    "explorer.exe", "svchost.exe", "notepad.exe", "chrome.exe",
    "powershell.exe", "cmd.exe", "python.exe", "node.exe",
    "evil.exe", "ransomware.exe", "mshta.exe", "wscript.exe",
]

AGENT_REGIONS = [
    "eu-west", "eu-east", "us-east", "us-west",
    "ap-south", "ap-north", "af-1", "latam-1",
]


def make_alert(agent_id: str, agent_idx: int) -> Dict:
    alert_type, score_min, score_max = random.choice(ALERT_TYPES)
    process = random.choice(PROCESSES)
    pid = random.randint(1000, 65535)
    return {
        "type": alert_type,
        "agent_id": agent_id,
        "pid": pid,
        "process": process,
        "threat_score": round(random.uniform(score_min, score_max), 3),
        "timestamp": time.time(),
        "region": AGENT_REGIONS[agent_idx % len(AGENT_REGIONS)],
        "cmdline": f"{process} --arg{random.randint(1, 99)}",
        "parent": "explorer.exe",
    }


# ── Métriques ─────────────────────────────────────────────────────────────────

class Metrics:
    def __init__(self):
        self.sent = 0
        self.errors = 0
        self.bytes_raw = 0
        self.bytes_compressed = 0
        self._latencies: deque = deque(maxlen=10000)
        self._lock = threading.Lock()
        self._start = time.time()

    def record(self, count: int, raw: int, compressed: int, latency_ms: float, ok: bool):
        with self._lock:
            if ok:
                self.sent += count
                self.bytes_raw += raw
                self.bytes_compressed += compressed
                self._latencies.append(latency_ms)
            else:
                self.errors += 1

    def report(self) -> Dict:
        with self._lock:
            elapsed = time.time() - self._start
            lats = sorted(self._latencies)
            n = len(lats)
            return {
                "elapsed_s":     round(elapsed, 1),
                "sent_total":    self.sent,
                "errors":        self.errors,
                "rps":           round(self.sent / max(elapsed, 1), 1),
                "success_rate":  f"{100 * self.sent / max(self.sent + self.errors, 1):.1f}%",
                "compression":   f"{self.bytes_raw / max(self.bytes_compressed, 1):.1f}x" if self.bytes_compressed else "N/A",
                "p50_ms":        round(lats[n // 2], 1) if n else 0,
                "p95_ms":        round(lats[int(n * 0.95)], 1) if n > 20 else 0,
                "p99_ms":        round(lats[int(n * 0.99)], 1) if n > 100 else 0,
            }


# ── Agent simulé ──────────────────────────────────────────────────────────────

class SimulatedAgent(threading.Thread):
    def __init__(self, idx: int, target_url: str, shared_secret: str,
                 alerts_per_min: float, metrics: Metrics, stress: bool = False):
        super().__init__(daemon=True)
        self.idx = idx
        self.agent_id = f"sim-agent-{AGENT_REGIONS[idx % len(AGENT_REGIONS)]}-{idx:05d}"
        self.target_url = target_url.rstrip("/")
        self._token = hashlib.sha256(f"{self.agent_id}:{shared_secret}".encode()).hexdigest()[:32]
        self._interval = 60.0 / max(alerts_per_min, 1)
        self._metrics = metrics
        self._stress = stress
        self._running = True

    def run(self):
        # Décalage aléatoire au démarrage pour éviter la tempête initiale
        time.sleep(random.uniform(0, min(self._interval, 5.0)))

        while self._running:
            batch_size = random.randint(1, 5) if not self._stress else random.randint(10, 50)
            batch = [make_alert(self.agent_id, self.idx) for _ in range(batch_size)]

            payload = {
                "agent_id": self.agent_id,
                "token": self._token,
                "ts": time.time(),
                "alerts": batch,
                "count": len(batch),
            }

            raw = json.dumps(payload, default=str).encode()
            compressed = zlib.compress(raw, level=6)

            t0 = time.perf_counter()
            ok = self._post(compressed, len(batch))
            latency = (time.perf_counter() - t0) * 1000

            self._metrics.record(len(batch), len(raw), len(compressed), latency, ok)
            time.sleep(self._interval if not self._stress else 0.1)

    def _post(self, body: bytes, count: int) -> bool:
        try:
            req = urllib.request.Request(
                f"{self.target_url}/collect/alerts",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Content-Encoding": "zlib",
                    "X-Gravity-Agent": self.agent_id,
                    "X-Gravity-Token": self._token,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def stop(self):
        self._running = False


# ── Affichage live ─────────────────────────────────────────────────────────────

def print_dashboard(metrics: Metrics, n_agents: int, target: str):
    r = metrics.report()
    sys.stdout.write("\033[2J\033[H")  # Clear screen
    print(f"{'═'*60}")
    print(f"  GRAVITY SECURITY — Load Simulator")
    print(f"  {n_agents} agents → {target}")
    print(f"{'═'*60}")
    print(f"  Alertes envoyées : {r['sent_total']:>10,}")
    print(f"  Alertes / sec    : {r['rps']:>10.1f}")
    print(f"  Erreurs          : {r['errors']:>10,}   ({r['success_rate']} succès)")
    print(f"  Compression      : {r['compression']:>10}")
    print(f"  Latence p50      : {r['p50_ms']:>9.1f}ms")
    print(f"  Latence p95      : {r['p95_ms']:>9.1f}ms")
    print(f"  Latence p99      : {r['p99_ms']:>9.1f}ms")
    print(f"  Durée            : {r['elapsed_s']:>9.1f}s")
    print(f"{'─'*60}")
    print(f"  [Ctrl+C pour arrêter]")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Gravity Load Simulator")
    parser.add_argument("--agents",  type=int,   default=100,
                        help="Nombre d'agents simulés (défaut: 100)")
    parser.add_argument("--target",  default="http://localhost:8001",
                        help="URL du collector ou serveur (défaut: localhost:8001)")
    parser.add_argument("--rate",    type=float, default=10,
                        help="Alertes par minute par agent (défaut: 10)")
    parser.add_argument("--secret",  default="gravity-security-secret-change-me",
                        help="Secret partagé")
    parser.add_argument("--stress",  action="store_true",
                        help="Mode stress — rafales d'alertes")
    parser.add_argument("--duration", type=int,  default=0,
                        help="Durée en secondes (0 = infini)")
    args = parser.parse_args()

    print(f"Démarrage de {args.agents} agents simulés → {args.target}")
    print(f"Taux : {args.rate} alertes/min/agent | Stress: {args.stress}")
    print(f"Lancement dans 2 secondes...")
    time.sleep(2)

    metrics = Metrics()
    agents: List[SimulatedAgent] = []

    # Démarrer les agents par vagues de 50 pour éviter la tempête initiale
    for i in range(args.agents):
        agent = SimulatedAgent(i, args.target, args.secret, args.rate, metrics, args.stress)
        agents.append(agent)
        agent.start()
        if (i + 1) % 50 == 0:
            print(f"  {i + 1}/{args.agents} agents démarrés...")
            time.sleep(0.1)

    print(f"  {args.agents}/{args.agents} agents actifs ✓")
    time.sleep(1)

    start = time.time()
    try:
        while True:
            print_dashboard(metrics, args.agents, args.target)
            time.sleep(1)
            if args.duration and (time.time() - start) >= args.duration:
                break
    except KeyboardInterrupt:
        pass
    finally:
        print("\nArrêt des agents...")
        for a in agents:
            a.stop()
        time.sleep(1)
        r = metrics.report()
        print(f"\n{'═'*60}")
        print(f"  RÉSULTATS FINAUX — {args.agents} agents / {r['elapsed_s']}s")
        print(f"  Total envoyé : {r['sent_total']:,} alertes")
        print(f"  Débit moyen  : {r['rps']} alertes/sec")
        print(f"  Succès       : {r['success_rate']}")
        print(f"  Compression  : {r['compression']}")
        print(f"{'═'*60}")


if __name__ == "__main__":
    main()
