"""
Gravity Security — Process Chain Monitor
Surveille les arbres de processus et détecte les chaînes d'exécution malveillantes.

Principe Cyber 2.0 :
  virus → programme_non_légitime → programme_légitime → action_illégale

Ce module construit un graphe d'appels en temps réel et identifie
les patterns anormaux même quand des outils légitimes sont détournés.
"""

import os
import time
import json
import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field, asdict

try:
    import psutil
except ImportError:
    psutil = None

from .chain_analyzer import ProcessChainAnalyzer

logger = logging.getLogger("gravity.process_monitor")


@dataclass
class ProcessNode:
    pid: int
    name: str
    exe: str
    cmdline: List[str]
    parent_pid: int
    parent_name: str
    create_time: float
    username: str
    connections: List[Dict] = field(default_factory=list)
    children: List[int] = field(default_factory=list)
    threat_score: float = 0.0
    flagged: bool = False
    flag_reason: str = ""


class ProcessMonitor:
    """
    Surveillance en temps réel des processus et de leurs relations parent/enfant.
    Détecte les chaînes d'exécution suspectes via ProcessChainAnalyzer.
    """

    # Processus légitimes qui ne devraient PAS lancer d'autres processus réseau
    SUSPICIOUS_PARENTS = {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "acrobat.exe", "acrord32.exe", "chrome.exe", "firefox.exe",
        "notepad.exe", "wordpad.exe",
    }

    # Processus légitimes souvent détournés comme vecteurs (LOLBins)
    LOLBINS = {
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
        "bitsadmin.exe", "wmic.exe", "msiexec.exe", "installutil.exe",
        "regasm.exe", "regsvcs.exe", "msconfig.exe", "schtasks.exe",
        "at.exe", "net.exe", "net1.exe", "sc.exe",
    }

    def __init__(self, callback=None, poll_interval: float = 2.0):
        self.callback = callback
        self.poll_interval = poll_interval
        self.analyzer = ProcessChainAnalyzer()
        self._known_pids: Dict[int, ProcessNode] = {}
        self._alerts: List[Dict] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._whitelist: Set[str] = self._load_default_whitelist()

    # ------------------------------------------------------------------ #
    #  Démarrage / Arrêt                                                 #
    # ------------------------------------------------------------------ #

    def start(self):
        """Démarre la surveillance en arrière-plan."""
        if psutil is None:
            logger.error("psutil non installé — pip install psutil")
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("ProcessMonitor démarré")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("ProcessMonitor arrêté")

    # ------------------------------------------------------------------ #
    #  Boucle principale                                                 #
    # ------------------------------------------------------------------ #

    def _monitor_loop(self):
        while self._running:
            try:
                self._scan_processes()
            except Exception as e:
                logger.error(f"Erreur scan processus: {e}")
            time.sleep(self.poll_interval)

    def _scan_processes(self):
        current_pids: Set[int] = set()

        for proc in psutil.process_iter(
            ["pid", "name", "exe", "cmdline", "ppid", "create_time", "username", "connections"]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                current_pids.add(pid)

                if pid in self._known_pids:
                    continue  # déjà vu

                parent_pid = info.get("ppid", 0) or 0
                parent_name = ""
                if parent_pid and parent_pid in self._known_pids:
                    parent_name = self._known_pids[parent_pid].name

                node = ProcessNode(
                    pid=pid,
                    name=(info.get("name") or "").lower(),
                    exe=info.get("exe") or "",
                    cmdline=info.get("cmdline") or [],
                    parent_pid=parent_pid,
                    parent_name=parent_name,
                    create_time=info.get("create_time") or time.time(),
                    username=info.get("username") or "",
                    connections=[
                        {"laddr": str(c.laddr), "raddr": str(c.raddr), "status": c.status}
                        for c in (info.get("connections") or [])
                    ],
                )

                # Enregistrer l'enfant chez le parent
                if parent_pid in self._known_pids:
                    self._known_pids[parent_pid].children.append(pid)

                self._known_pids[pid] = node

                # Analyse de la chaîne
                score, reason = self.analyzer.analyze(node, self._known_pids)
                if score > 0:
                    node.threat_score = score
                    node.flagged = True
                    node.flag_reason = reason
                    self._raise_alert(node)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Nettoyer les processus terminés
        dead = set(self._known_pids.keys()) - current_pids
        for pid in dead:
            del self._known_pids[pid]

    # ------------------------------------------------------------------ #
    #  Alertes                                                           #
    # ------------------------------------------------------------------ #

    def _raise_alert(self, node: ProcessNode):
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "SUSPICIOUS_PROCESS",
            "pid": node.pid,
            "process": node.name,
            "exe": node.exe,
            "parent": node.parent_name,
            "threat_score": node.threat_score,
            "reason": node.flag_reason,
            "cmdline": " ".join(node.cmdline),
        }
        self._alerts.append(alert)
        logger.warning(f"[ALERTE] {node.name} (PID {node.pid}) — score {node.threat_score:.2f} — {node.flag_reason}")
        if self.callback:
            self.callback(alert)

    def get_alerts(self) -> List[Dict]:
        return list(self._alerts)

    def get_process_tree(self) -> Dict:
        """Retourne l'arbre de processus complet pour le dashboard."""
        return {
            pid: asdict(node)
            for pid, node in self._known_pids.items()
        }

    # ------------------------------------------------------------------ #
    #  Whitelist                                                         #
    # ------------------------------------------------------------------ #

    def _load_default_whitelist(self) -> Set[str]:
        return {
            "system", "smss.exe", "csrss.exe", "wininit.exe",
            "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
            "explorer.exe", "taskmgr.exe", "spoolsv.exe",
        }

    def add_to_whitelist(self, process_name: str):
        self._whitelist.add(process_name.lower())

    def is_whitelisted(self, process_name: str) -> bool:
        return process_name.lower() in self._whitelist
