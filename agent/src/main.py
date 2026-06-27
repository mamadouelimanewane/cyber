"""
Gravity Security Agent — Point d'entrée principal
S'exécute sur chaque machine à protéger.
"""

import os
import sys
import time
import json
import logging
import argparse
import threading
import urllib.request
import urllib.parse
from typing import Dict, Any

from chaos_engine import ChaosEngine
from process_monitor import ProcessMonitor
from network_filter import NACFilter
from scanner import BehavioralScanner, SignatureScanner
from patent_engine import GravityPatentEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("gravity_agent.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("gravity.agent")

DEFAULT_CONFIG = {
    "agent_id": "agent-001",
    "shared_secret": "gravity-security-secret-change-me",
    "server_url": "http://localhost:8000",
    "scan_paths": ["C:\\Users", "C:\\Windows\\Temp", "C:\\ProgramData"],
    "poll_interval": 2.0,
    "report_interval": 30,
}


class GravityAgent:
    """Agent de sécurité Gravity — orchestre tous les modules."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.agent_id = config["agent_id"]
        self.server_url = config["server_url"]

        # Initialisation des modules
        self.chaos = ChaosEngine(self.agent_id, config["shared_secret"])
        self.nac = NACFilter(self.agent_id, config["shared_secret"])
        self.process_monitor = ProcessMonitor(
            callback=self._on_process_alert,
            poll_interval=config["poll_interval"],
        )
        self.behavioral_scanner = BehavioralScanner()
        self.signature_scanner = SignatureScanner()

        # Moteur des algorithmes brevetables — zéro overhead, enrichit les alertes existantes
        master_key = hashlib.sha256(config["shared_secret"].encode()).digest()
        self.patent = GravityPatentEngine(
            agent_id=self.agent_id,
            master_key=master_key,
            on_patent_alert=self._on_patent_alert,
        )

        self._alerts_buffer = []
        self._running = False

    # ------------------------------------------------------------------ #
    #  Cycle de vie                                                      #
    # ------------------------------------------------------------------ #

    def start(self):
        logger.info(f"Gravity Security Agent démarré — ID: {self.agent_id}")
        logger.info(f"Serveur: {self.server_url}")
        logger.info(f"Signatures chargées: {self.signature_scanner.signature_count}")

        self._running = True
        self.process_monitor.start()

        # Thread de reporting vers le serveur
        reporter = threading.Thread(target=self._report_loop, daemon=True)
        reporter.start()

        # Thread de scan périodique
        scanner = threading.Thread(target=self._scan_loop, daemon=True)
        scanner.start()

        logger.info("Tous les modules actifs — surveillance en cours")

        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        logger.info("Arrêt de l'agent Gravity Security...")
        self._running = False
        self.process_monitor.stop()
        logger.info("Agent arrêté.")

    # ------------------------------------------------------------------ #
    #  Callbacks & Alertes                                               #
    # ------------------------------------------------------------------ #

    def _on_process_alert(self, alert: Dict):
        """Reçoit les alertes du ProcessMonitor."""
        cmdline = alert.get("cmdline", "")
        if cmdline:
            sigs = self.signature_scanner.scan_command(cmdline)
            if sigs:
                alert["signature_matches"] = sigs
                alert["threat_score"] = min(1.0, alert.get("threat_score", 0) + 0.2)

        # Enrichissement par les algorithmes brevetables (QBSM, CBGA, RCTC…)
        alert = self.patent.process(alert)

        self._alerts_buffer.append(alert)
        self._print_alert(alert)

    def _on_patent_alert(self, alert: Dict):
        """Reçoit les alertes générées par les modules brevets (QBSM collapse, CBGA match…)."""
        self._alerts_buffer.append(alert)
        logger.warning(
            f"[BREVET] {alert.get('type', 'PATENT_ALERT')} — "
            f"{alert.get('process', 'N/A')} — score {alert.get('threat_score', 0):.2f}"
        )

    def _on_nac_alert(self, alert: Dict):
        """Reçoit les alertes du NACFilter."""
        self._alerts_buffer.append(alert)

    def _print_alert(self, alert: Dict):
        severity = "CRITIQUE" if alert.get("threat_score", 0) > 0.8 else "AVERTISSEMENT"
        logger.warning(
            f"\n{'='*60}\n"
            f"  [{severity}] {alert.get('type', 'ALERTE')}\n"
            f"  Processus : {alert.get('process', 'N/A')} (PID {alert.get('pid', 'N/A')})\n"
            f"  Parent    : {alert.get('parent', 'N/A')}\n"
            f"  Score     : {alert.get('threat_score', 0):.2f}/1.00\n"
            f"  Raison    : {alert.get('reason', 'N/A')}\n"
            f"  Commande  : {alert.get('cmdline', '')[:100]}\n"
            f"{'='*60}"
        )

    # ------------------------------------------------------------------ #
    #  Scan périodique                                                   #
    # ------------------------------------------------------------------ #

    def _scan_loop(self):
        while self._running:
            for path in self.config.get("scan_paths", []):
                if os.path.exists(path):
                    logger.info(f"Scan de {path}...")
                    results = self.behavioral_scanner.scan_directory(path)
                    for r in results:
                        alert = {
                            "type": "FILE_THREAT",
                            "file": r.file_path,
                            "threat_score": r.threat_score,
                            "entropy": r.entropy,
                            "reasons": r.reasons,
                            "hash": r.file_hash,
                        }
                        self._alerts_buffer.append(alert)
                        logger.warning(f"[FICHIER SUSPECT] {r.file_path} — {r.threat_score:.2f}")
            time.sleep(300)  # Scan toutes les 5 minutes

    # ------------------------------------------------------------------ #
    #  Reporting vers le serveur                                        #
    # ------------------------------------------------------------------ #

    def _report_loop(self):
        interval = self.config.get("report_interval", 30)
        while self._running:
            time.sleep(interval)
            self._send_heartbeat()
            if self._alerts_buffer:
                self._send_alerts()

    def _send_heartbeat(self):
        payload = {
            "agent_id": self.agent_id,
            "type": "heartbeat",
            "timestamp": time.time(),
            "stats": {
                "nac": self.nac.get_stats(),
                "processes": len(self.process_monitor._known_pids),
                "alerts_pending": len(self._alerts_buffer),
                "patent": self.patent.get_status(),
            },
        }
        self._post("/api/agents/heartbeat", payload)

    def _send_alerts(self):
        alerts = list(self._alerts_buffer)
        self._alerts_buffer.clear()
        payload = {"agent_id": self.agent_id, "alerts": alerts}
        self._post("/api/alerts", payload)

    def _post(self, endpoint: str, data: Dict):
        try:
            url = self.server_url.rstrip("/") + endpoint
            body = json.dumps(data).encode("utf-8")
            req = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                pass
        except Exception as e:
            logger.debug(f"Erreur envoi {endpoint}: {e}")


# ------------------------------------------------------------------ #
#  Point d'entrée CLI                                               #
# ------------------------------------------------------------------ #

def main():
    parser = argparse.ArgumentParser(description="Gravity Security Agent")
    parser.add_argument("--config", default="agent_config.json", help="Fichier de configuration")
    parser.add_argument("--agent-id", help="Identifiant de l'agent")
    parser.add_argument("--server", help="URL du serveur Gravity")
    args = parser.parse_args()

    config = dict(DEFAULT_CONFIG)

    if os.path.exists(args.config):
        with open(args.config, encoding="utf-8") as f:
            config.update(json.load(f))

    if args.agent_id:
        config["agent_id"] = args.agent_id
    if args.server:
        config["server_url"] = args.server

    agent = GravityAgent(config)
    agent.start()


if __name__ == "__main__":
    main()
