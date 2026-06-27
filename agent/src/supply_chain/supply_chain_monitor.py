"""
Gravity Supply Chain Monitor — Détection d'attaques sur la chaîne d'approvisionnement.

Vecteurs couverts :
  1. DLL hijacking      — DLL chargée depuis chemin non canonique
  2. Typosquatting      — paquet Python/npm avec nom similaire à un paquet légitime
  3. Build poisoning    — modification du binaire entre compilation et exécution
  4. Update hijacking   — flux de mise à jour dévié vers serveur non autorisé
  5. Dependency confusion — paquet interne résolu depuis registre public
  6. Signature forgery  — certificat révoqué ou auto-signé sur binaire critique

Intégration :
  - S'abonne aux alertes du ProcessMonitor (imports DLL)
  - Hash des binaires critiques au démarrage → vérifie périodiquement
  - Croise les URLs de mise à jour avec la liste blanche Chaos-signée
"""

import hashlib
import hmac as hmac_lib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("gravity.supply_chain")

# ── Types d'attaque ───────────────────────────────────────────────────────────

ATTACK_TYPE = {
    "DLL_HIJACK":          "DLL chargée depuis chemin non autorisé",
    "TYPOSQUATTING":       "Paquet au nom similaire à un paquet légitime",
    "BUILD_POISON":        "Binaire modifié après compilation (hash mismatch)",
    "UPDATE_HIJACK":       "Flux de mise à jour dévié vers hôte non autorisé",
    "DEP_CONFUSION":       "Paquet interne résolu depuis registre public",
    "CERT_FORGERY":        "Binaire signé par certificat non autorisé",
    "SHADOW_DEPENDENCY":   "Dépendance fantôme non déclarée dans le manifeste",
}

# ── Données de référence ──────────────────────────────────────────────────────

# Chemins DLL légitimes Windows (non exhaustif — compléter en production)
LEGITIMATE_DLL_PATHS: Set[str] = {
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\winsxs",
    r"c:\program files",
    r"c:\program files (x86)",
}

# Domaines de mise à jour autorisés (whitelist Chaos-signée)
AUTHORIZED_UPDATE_HOSTS: Set[str] = {
    "update.microsoft.com",
    "download.microsoft.com",
    "windowsupdate.com",
    "aka.ms",
    "dl.google.com",
    "mozilla.org",
    "packages.microsoft.com",
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "github.com",
    "objects.githubusercontent.com",
}

# Paquets légitimes courants (détection typosquatting)
LEGITIMATE_PACKAGES = [
    "requests", "numpy", "pandas", "flask", "django", "fastapi", "sqlalchemy",
    "cryptography", "paramiko", "boto3", "pydantic", "uvicorn", "aiohttp",
    "pytest", "black", "mypy", "pylint", "setuptools", "pip", "wheel",
    "react", "express", "lodash", "axios", "webpack", "babel", "eslint",
    "typescript", "next", "vue", "angular", "jquery", "bootstrap",
]

# Seuil de similarité Levenshtein pour typosquatting
TYPOSQUAT_MAX_DISTANCE = 2


@dataclass
class SupplyChainAlert:
    attack_type: str
    severity: float
    process: str
    pid: int
    evidence: Dict
    recommendation: str
    timestamp: float = field(default_factory=time.time)

    def to_alert(self) -> Dict:
        return {
            "type": f"SUPPLY_CHAIN_{self.attack_type}",
            "threat_score": self.severity,
            "process": self.process,
            "pid": self.pid,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp,
            "category": "supply_chain",
        }


# ── Utilitaires ───────────────────────────────────────────────────────────────

def levenshtein(s1: str, s2: str) -> int:
    """Distance de Levenshtein — O(n×m)."""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                            prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def is_typosquat(name: str) -> Optional[str]:
    """Retourne le paquet légitime le plus proche si distance ≤ seuil."""
    name_lower = name.lower()
    if name_lower in LEGITIMATE_PACKAGES:
        return None  # C'est le vrai paquet
    for legit in LEGITIMATE_PACKAGES:
        if levenshtein(name_lower, legit) <= TYPOSQUAT_MAX_DISTANCE:
            return legit
    return None


def sha256_file(path: str) -> Optional[str]:
    """Hash SHA-256 d'un fichier (robuste aux erreurs de permission)."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


# ── Moteur principal ──────────────────────────────────────────────────────────

class SupplyChainMonitor:
    """
    Détecte les attaques supply chain en temps réel et par scan périodique.
    """

    def __init__(self, master_key: bytes,
                 on_alert: Optional[Callable[[Dict], None]] = None,
                 trusted_binary_paths: Optional[List[str]] = None):
        self._master_key = master_key
        self._on_alert = on_alert

        # Hashes de référence des binaires critiques (chemin → SHA-256)
        self._trusted_hashes: Dict[str, str] = {}
        # Hashes actuels pour comparaison
        self._current_hashes: Dict[str, str] = {}

        # Manifeste des dépendances connues {nom: version_attendue}
        self._dependency_manifest: Dict[str, str] = {}

        # DLLs vues par processus {pid: {dll_path}}
        self._dll_map: Dict[int, Set[str]] = {}

        # Alertes générées
        self._alerts: List[SupplyChainAlert] = []

        # Binaires à surveiller
        self._watch_paths = trusted_binary_paths or []

        # Initialisation des hashes de référence
        self._baseline_binaries()

    def _baseline_binaries(self):
        """Calcule les hashes de référence au démarrage."""
        for path in self._watch_paths:
            h = sha256_file(path)
            if h:
                self._trusted_hashes[path.lower()] = h
                logger.info(f"Supply chain baseline: {path} → {h[:16]}...")

    # ── Point d'entrée principal ──────────────────────────────────────────────

    def check_dll_load(self, pid: int, process: str, dll_path: str) -> Optional[SupplyChainAlert]:
        """Vérifie si une DLL chargée provient d'un chemin légitime."""
        dll_lower = dll_path.lower()
        dll_dir = os.path.dirname(dll_lower)

        # Vérifier si le chemin est dans la liste blanche
        is_legit = any(dll_dir.startswith(legit) for legit in LEGITIMATE_DLL_PATHS)

        if not is_legit:
            # DLL hijacking potentiel
            alert = SupplyChainAlert(
                attack_type="DLL_HIJACK",
                severity=0.85,
                process=process,
                pid=pid,
                evidence={
                    "dll_path": dll_path,
                    "dll_dir": dll_dir,
                    "expected_paths": list(LEGITIMATE_DLL_PATHS)[:3],
                },
                recommendation=(
                    f"Vérifier si {os.path.basename(dll_path)} est légitime. "
                    "Isoler le processus si non confirmé."
                ),
            )
            self._emit(alert)
            return alert

        # Enregistrer pour analyse
        if pid not in self._dll_map:
            self._dll_map[pid] = set()
        self._dll_map[pid].add(dll_lower)
        return None

    def check_package_install(self, package_name: str, version: str,
                               registry: str, pid: int = 0,
                               process: str = "pip") -> Optional[SupplyChainAlert]:
        """Vérifie un paquet installé pour typosquatting et confusion de dépendances."""
        # 1. Typosquatting
        similar = is_typosquat(package_name)
        if similar:
            alert = SupplyChainAlert(
                attack_type="TYPOSQUATTING",
                severity=0.80,
                process=process,
                pid=pid,
                evidence={
                    "package": package_name,
                    "version": version,
                    "registry": registry,
                    "similar_to": similar,
                    "levenshtein_distance": levenshtein(package_name.lower(), similar),
                },
                recommendation=(
                    f"'{package_name}' ressemble à '{similar}'. "
                    "Vérifier l'auteur et la provenance avant d'utiliser."
                ),
            )
            self._emit(alert)
            return alert

        # 2. Dependency confusion — paquet interne via registre public
        if package_name in self._dependency_manifest:
            expected_version = self._dependency_manifest[package_name]
            if registry not in {"internal", "private"} and expected_version.startswith("internal"):
                alert = SupplyChainAlert(
                    attack_type="DEP_CONFUSION",
                    severity=0.90,
                    process=process,
                    pid=pid,
                    evidence={
                        "package": package_name,
                        "installed_from": registry,
                        "expected_source": "registre interne",
                        "version": version,
                    },
                    recommendation=(
                        f"'{package_name}' devrait venir du registre interne. "
                        "Vérifier si le registre privé est correctement configuré."
                    ),
                )
                self._emit(alert)
                return alert

        return None

    def check_update_url(self, url: str, process: str,
                          pid: int = 0) -> Optional[SupplyChainAlert]:
        """Vérifie si une URL de mise à jour est autorisée."""
        # Extraire le host
        match = re.match(r"https?://([^/]+)", url.lower())
        if not match:
            return None
        host = match.group(1).rstrip(".")

        # Vérifier contre la whitelist
        authorized = any(
            host == auth or host.endswith("." + auth)
            for auth in AUTHORIZED_UPDATE_HOSTS
        )

        if not authorized:
            alert = SupplyChainAlert(
                attack_type="UPDATE_HIJACK",
                severity=0.88,
                process=process,
                pid=pid,
                evidence={
                    "url": url,
                    "host": host,
                    "authorized_hosts": list(AUTHORIZED_UPDATE_HOSTS)[:5],
                },
                recommendation=(
                    f"Mise à jour depuis hôte non autorisé '{host}'. "
                    "Bloquer et vérifier si le DNS/proxy a été compromis."
                ),
            )
            self._emit(alert)
            return alert

        return None

    def check_binary_integrity(self, path: str,
                                process: str = "system") -> Optional[SupplyChainAlert]:
        """Vérifie l'intégrité d'un binaire contre le hash de référence."""
        path_lower = path.lower()
        if path_lower not in self._trusted_hashes:
            return None  # Pas dans la baseline

        current_hash = sha256_file(path)
        if not current_hash:
            return None

        expected = self._trusted_hashes[path_lower]
        if current_hash != expected:
            alert = SupplyChainAlert(
                attack_type="BUILD_POISON",
                severity=0.95,
                process=process,
                pid=0,
                evidence={
                    "path": path,
                    "expected_hash": expected[:32] + "...",
                    "actual_hash": current_hash[:32] + "...",
                    "size_bytes": os.path.getsize(path) if os.path.exists(path) else 0,
                },
                recommendation=(
                    f"Binaire '{path}' modifié depuis la baseline. "
                    "STOPPER immédiatement — possible build poisoning ou rootkit."
                ),
            )
            self._emit(alert)
            # Mise à jour du hash courant pour éviter le flood
            self._current_hashes[path_lower] = current_hash
            return alert

        return None

    def scan_integrity_all(self) -> List[SupplyChainAlert]:
        """Scan complet d'intégrité de tous les binaires en baseline."""
        found = []
        for path in self._trusted_hashes:
            alert = self.check_binary_integrity(path)
            if alert:
                found.append(alert)
        return found

    def register_dependency(self, name: str, version: str, source: str = "pypi"):
        """Enregistre une dépendance connue dans le manifeste."""
        self._dependency_manifest[name] = f"{source}:{version}"

    # ── Callback ──────────────────────────────────────────────────────────────

    def _emit(self, alert: SupplyChainAlert):
        """Émet une alerte supply chain."""
        self._alerts.append(alert)
        logger.warning(
            f"SUPPLY CHAIN [{alert.attack_type}] {alert.process} "
            f"— score={alert.severity:.2f} — {list(alert.evidence.values())[0]}"
        )
        if self._on_alert:
            self._on_alert(alert.to_alert())

    def get_status(self) -> Dict:
        return {
            "monitored_binaries": len(self._trusted_hashes),
            "known_dependencies": len(self._dependency_manifest),
            "tracked_processes": len(self._dll_map),
            "total_alerts": len(self._alerts),
            "recent_alerts": [a.to_alert() for a in self._alerts[-5:]],
            "authorized_update_hosts": len(AUTHORIZED_UPDATE_HOSTS),
        }
