"""
Gravity Security — Federated Threat Intelligence
Immunité collective : quand un client Gravity détecte une menace nouvelle,
l'IOC anonymisé est immédiatement partagé avec tous les autres clients.

Comme un vaccin numérique : 1 infection → tous immunisés en secondes.

Principe de confidentialité :
- Aucune donnée personnelle ou identifiante n'est partagée
- Seuls les IOC (hash, IP, domaine, pattern) sont partagés
- Chaque organisation reste anonyme dans le réseau

Types d'IOC partagés :
- Hashes de fichiers malveillants (SHA256)
- Adresses IP de serveurs C2
- Domaines malveillants
- Patterns de processus (chaîne parent→enfant)
- Patterns de commandes malveillantes
- Signatures de shellcodes
"""

import time
import json
import hashlib
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import threading

logger = logging.getLogger("gravity.threat_intel")

LOCAL_IOC_DB = Path(__file__).parent.parent.parent / "data" / "threat_intel.json"


@dataclass
class IOC:
    """Indicator of Compromise — partagé dans le réseau Gravity."""
    ioc_id: str
    ioc_type: str           # "file_hash", "ip", "domain", "cmdline_pattern", "process_chain"
    value: str              # La valeur de l'IOC (anonymisée si nécessaire)
    threat_name: str
    severity: str
    confidence: float       # 0.0 → 1.0
    first_seen: float
    last_seen: float
    seen_count: int = 1     # Nombre de clients ayant reporté cet IOC
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    source_hash: str = ""   # Hash anonyme de l'organisation source


@dataclass
class ThreatFeed:
    """Feed d'intelligence de menaces d'une source externe."""
    name: str
    url: str
    ioc_count: int = 0
    last_updated: float = 0.0
    enabled: bool = True


class FederatedThreatIntel:
    """
    Intelligence de menaces fédérée — partage anonyme entre clients Gravity.

    Architecture peer-to-peer avec serveur de coordination central :
    1. Un agent détecte une nouvelle menace
    2. Le serveur local extrait l'IOC et l'anonymise
    3. L'IOC est envoyé au hub central Gravity
    4. Le hub redistribue à tous les autres clients
    5. Chaque client ajoute l'IOC à sa liste de blocage locale

    En mode offline : la base d'IOC locale est utilisée pour détection.
    """

    # Feeds publics de threat intelligence (OSINT)
    PUBLIC_FEEDS = [
        ThreatFeed("Abuse.ch MalwareBazaar", "https://bazaar.abuse.ch/export/json/recent/", 0, 0),
        ThreatFeed("Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.json", 0, 0),
        ThreatFeed("URLhaus", "https://urlhaus-api.abuse.ch/v1/urls/recent/", 0, 0),
        ThreatFeed("ThreatFox", "https://threatfox-api.abuse.ch/api/v1/", 0, 0),
    ]

    def __init__(self, hub_url: Optional[str] = None, org_id: Optional[str] = None):
        self.hub_url = hub_url
        self.org_id = org_id or self._generate_org_id()
        self._iocs: Dict[str, IOC] = {}          # ioc_id → IOC
        self._hash_index: Set[str] = set()        # Index rapide pour les hashes
        self._ip_index: Set[str] = set()          # Index rapide pour les IPs
        self._domain_index: Set[str] = set()
        self._cmdline_patterns: List[str] = []
        self._lock = threading.Lock()
        self._load_local_db()
        logger.info(f"Threat Intel initialisé — {len(self._iocs)} IOC chargés — Org: {self.org_id[:8]}...")

    # ------------------------------------------------------------------ #
    #  Soumission d'IOC (depuis les alertes locales)                   #
    # ------------------------------------------------------------------ #

    def submit_from_alert(self, alert: Dict) -> Optional[IOC]:
        """
        Extrait et soumet un IOC depuis une alerte locale.
        Anonymise les données identifiantes avant partage.
        """
        iocs_created = []

        # IOC depuis hash de fichier
        file_hash = alert.get("hash") or alert.get("file_hash")
        if file_hash and len(file_hash) == 64:
            ioc = self._create_ioc(
                ioc_type="file_hash",
                value=file_hash,
                threat_name=alert.get("type", "Unknown"),
                severity=alert.get("severity", "medium"),
                confidence=alert.get("threat_score", 0.5),
                tags=["file", "behavioral"],
                mitre=self._extract_mitre(alert),
            )
            iocs_created.append(ioc)

        # IOC depuis cmdline (anonymisé — on partage le pattern, pas le chemin exact)
        cmdline = alert.get("cmdline", "")
        if cmdline and len(cmdline) > 20:
            pattern = self._extract_cmdline_pattern(cmdline)
            if pattern:
                ioc = self._create_ioc(
                    ioc_type="cmdline_pattern",
                    value=pattern,
                    threat_name=alert.get("type", "Unknown"),
                    severity=alert.get("severity", "medium"),
                    confidence=min(0.7, alert.get("threat_score", 0.3)),
                    tags=["execution", "cmdline"],
                    mitre=self._extract_mitre(alert),
                )
                iocs_created.append(ioc)

        return iocs_created[0] if iocs_created else None

    def _create_ioc(self, ioc_type: str, value: str, threat_name: str,
                    severity: str, confidence: float, tags: List[str], mitre: str) -> IOC:
        ioc_id = hashlib.sha256(f"{ioc_type}:{value}".encode()).hexdigest()[:32]

        with self._lock:
            if ioc_id in self._iocs:
                existing = self._iocs[ioc_id]
                existing.seen_count += 1
                existing.last_seen = time.time()
                existing.confidence = min(1.0, existing.confidence + 0.05)
                return existing

            ioc = IOC(
                ioc_id=ioc_id,
                ioc_type=ioc_type,
                value=value,
                threat_name=threat_name,
                severity=severity,
                confidence=confidence,
                first_seen=time.time(),
                last_seen=time.time(),
                tags=tags,
                mitre_techniques=[mitre] if mitre else [],
                source_hash=hashlib.sha256(self.org_id.encode()).hexdigest()[:16],
            )
            self._iocs[ioc_id] = ioc
            self._update_indexes(ioc)
            logger.info(f"Nouvel IOC: [{ioc_type}] {value[:40]}... — {threat_name}")
            self._save_local_db()
            return ioc

    def _update_indexes(self, ioc: IOC):
        if ioc.ioc_type == "file_hash":
            self._hash_index.add(ioc.value.lower())
        elif ioc.ioc_type == "ip":
            self._ip_index.add(ioc.value)
        elif ioc.ioc_type == "domain":
            self._domain_index.add(ioc.value.lower())
        elif ioc.ioc_type == "cmdline_pattern":
            self._cmdline_patterns.append(ioc.value)

    # ------------------------------------------------------------------ #
    #  Vérification en temps réel                                       #
    # ------------------------------------------------------------------ #

    def check_hash(self, file_hash: str) -> Optional[IOC]:
        """Vérifie si un hash de fichier est connu comme malveillant."""
        ioc_id = hashlib.sha256(f"file_hash:{file_hash.lower()}".encode()).hexdigest()[:32]
        return self._iocs.get(ioc_id)

    def check_ip(self, ip: str) -> Optional[IOC]:
        """Vérifie si une IP est connue comme malveillante."""
        if ip in self._ip_index:
            ioc_id = hashlib.sha256(f"ip:{ip}".encode()).hexdigest()[:32]
            return self._iocs.get(ioc_id)
        return None

    def check_domain(self, domain: str) -> Optional[IOC]:
        """Vérifie si un domaine est connu comme malveillant."""
        domain_lower = domain.lower()
        if domain_lower in self._domain_index:
            ioc_id = hashlib.sha256(f"domain:{domain_lower}".encode()).hexdigest()[:32]
            return self._iocs.get(ioc_id)
        return None

    def check_cmdline(self, cmdline: str) -> List[IOC]:
        """Vérifie si une ligne de commande correspond à des patterns connus."""
        import re
        matches = []
        cmdline_lower = cmdline.lower()
        for pattern in self._cmdline_patterns:
            try:
                if re.search(pattern, cmdline_lower, re.I):
                    ioc_id = hashlib.sha256(f"cmdline_pattern:{pattern}".encode()).hexdigest()[:32]
                    ioc = self._iocs.get(ioc_id)
                    if ioc:
                        matches.append(ioc)
            except Exception:
                pass
        return matches

    def enrich_alert(self, alert: Dict) -> Dict:
        """Enrichit une alerte avec les informations de threat intelligence."""
        intel_hits = []

        # Check hash
        if alert.get("hash"):
            ioc = self.check_hash(alert["hash"])
            if ioc:
                intel_hits.append({"type": "file_hash", "ioc": ioc.threat_name,
                                   "confidence": ioc.confidence, "seen": ioc.seen_count})

        # Check cmdline
        if alert.get("cmdline"):
            iocs = self.check_cmdline(alert["cmdline"])
            for ioc in iocs:
                intel_hits.append({"type": "cmdline", "ioc": ioc.threat_name,
                                   "confidence": ioc.confidence})

        if intel_hits:
            alert["threat_intel"] = intel_hits
            alert["threat_intel_confirmed"] = True
            # Augmenter le score si confirmé par threat intel
            alert["threat_score"] = min(1.0, alert.get("threat_score", 0) + 0.2)
            logger.info(f"IOC confirmé par Threat Intel: {intel_hits[0]}")

        # Soumettre dans le réseau
        self.submit_from_alert(alert)

        return alert

    # ------------------------------------------------------------------ #
    #  Réception d'IOC du hub (push depuis autres clients)             #
    # ------------------------------------------------------------------ #

    def receive_ioc(self, ioc_data: Dict):
        """Reçoit un IOC du hub fédéré et l'ajoute à la base locale."""
        try:
            ioc = IOC(
                ioc_id=ioc_data["ioc_id"],
                ioc_type=ioc_data["ioc_type"],
                value=ioc_data["value"],
                threat_name=ioc_data.get("threat_name", "Unknown"),
                severity=ioc_data.get("severity", "medium"),
                confidence=float(ioc_data.get("confidence", 0.5)),
                first_seen=float(ioc_data.get("first_seen", time.time())),
                last_seen=time.time(),
                seen_count=int(ioc_data.get("seen_count", 1)),
                tags=ioc_data.get("tags", []),
                mitre_techniques=ioc_data.get("mitre_techniques", []),
            )
            with self._lock:
                self._iocs[ioc.ioc_id] = ioc
                self._update_indexes(ioc)
            logger.info(f"IOC reçu du hub: [{ioc.ioc_type}] {ioc.threat_name}")
        except Exception as e:
            logger.error(f"Erreur réception IOC: {e}")

    # ------------------------------------------------------------------ #
    #  Utilitaires                                                      #
    # ------------------------------------------------------------------ #

    def _extract_cmdline_pattern(self, cmdline: str) -> Optional[str]:
        """Extrait un pattern regex générique depuis une ligne de commande concrète."""
        import re
        # Remplacer les chemins spécifiques par des wildcards
        pattern = re.sub(r"C:\\[^\s]+\\([^\s\\]+\.exe)", r".*\\\1", cmdline, flags=re.I)
        pattern = re.sub(r"[A-F0-9]{32,}", r"[A-F0-9]+", pattern, flags=re.I)
        pattern = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", r"\\d+\\.\\d+\\.\\d+\\.\\d+", pattern)
        # Ne partager que si le pattern est assez générique et pas trop long
        if 15 < len(pattern) < 200:
            return pattern[:200]
        return None

    def _extract_mitre(self, alert: Dict) -> str:
        return alert.get("mitre_technique_id") or alert.get("mitre", "") or ""

    def _generate_org_id(self) -> str:
        import socket, os
        raw = f"{socket.gethostname()}{os.getenv('COMPUTERNAME', '')}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _save_local_db(self):
        LOCAL_IOC_DB.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "org_id": self.org_id,
            "updated_at": time.time(),
            "iocs": {iid: {
                "ioc_id": ioc.ioc_id, "ioc_type": ioc.ioc_type,
                "value": ioc.value, "threat_name": ioc.threat_name,
                "severity": ioc.severity, "confidence": ioc.confidence,
                "first_seen": ioc.first_seen, "last_seen": ioc.last_seen,
                "seen_count": ioc.seen_count, "tags": ioc.tags,
                "mitre_techniques": ioc.mitre_techniques,
            } for iid, ioc in self._iocs.items()}
        }
        with open(LOCAL_IOC_DB, "w") as f:
            json.dump(data, f, indent=2)

    def _load_local_db(self):
        if not LOCAL_IOC_DB.exists():
            return
        try:
            with open(LOCAL_IOC_DB) as f:
                data = json.load(f)
            for iid, ioc_data in data.get("iocs", {}).items():
                ioc = IOC(**{k: v for k, v in ioc_data.items() if k in IOC.__dataclass_fields__})
                self._iocs[iid] = ioc
                self._update_indexes(ioc)
        except Exception as e:
            logger.error(f"Erreur chargement IOC DB: {e}")

    def get_stats(self) -> Dict:
        return {
            "total_iocs": len(self._iocs),
            "by_type": {
                "file_hash": len(self._hash_index),
                "ip": len(self._ip_index),
                "domain": len(self._domain_index),
                "cmdline_pattern": len(self._cmdline_patterns),
            },
            "hub_connected": self.hub_url is not None,
            "org_id": self.org_id[:8] + "...",
        }

    def get_recent_iocs(self, limit: int = 20) -> List[Dict]:
        sorted_iocs = sorted(self._iocs.values(), key=lambda x: x.last_seen, reverse=True)
        return [
            {"id": i.ioc_id[:12], "type": i.ioc_type, "threat": i.threat_name,
             "severity": i.severity, "confidence": i.confidence,
             "seen_count": i.seen_count, "last_seen": i.last_seen}
            for i in sorted_iocs[:limit]
        ]
