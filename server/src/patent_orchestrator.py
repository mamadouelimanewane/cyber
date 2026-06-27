"""
Gravity Patent Orchestrator — Côté serveur.

Centralise l'état des 5 brevets reçu de tous les agents,
expose les données via des endpoints FastAPI.

ASN (Shadow Network) vit ici car il analyse le trafic RÉSEAU global
que le serveur voit mieux que les agents individuels.
"""

import hashlib
import logging
import time
from typing import Dict, List, Optional

logger = logging.getLogger("gravity.patent.server")


class PatentOrchestrator:
    """Agrège l'état des brevets de tous les agents et fait tourner l'ASN côté serveur."""

    def __init__(self, master_secret: str = "gravity-security-secret-change-me"):
        self._master_key = hashlib.sha256(master_secret.encode()).digest()

        # État agrégé par agent_id
        self._agent_states: Dict[str, Dict] = {}

        # Alertes brevets reçues de tous les agents
        self._patent_alerts: List[Dict] = []

        # ASN (Shadow Network) — analyse côté serveur
        self._asn = None
        self._init_asn()

    def _init_asn(self):
        try:
            import sys, os
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agent", "src"))
            from asn.shadow_network import AdversarialShadowNetwork
            self._asn = AdversarialShadowNetwork(on_alert=self._on_asn_alert)
            logger.info("PATENT-SERVER: ASN initialisé")
        except ImportError as e:
            logger.debug(f"PATENT-SERVER: ASN non disponible: {e}")

    # ── Ingestion ─────────────────────────────────────────────────────────────

    def ingest_heartbeat(self, agent_id: str, patent_stats: Dict):
        """Reçoit les stats brevets d'un agent via son heartbeat."""
        self._agent_states[agent_id] = {
            "agent_id": agent_id,
            "updated_at": time.time(),
            **patent_stats,
        }

    def ingest_patent_alert(self, alert: Dict):
        """Reçoit une alerte générée par un module brevet d'un agent."""
        alert["server_received_at"] = time.time()
        self._patent_alerts.append(alert)
        # Garder seulement les 500 dernières
        if len(self._patent_alerts) > 500:
            self._patent_alerts = self._patent_alerts[-500:]

    def ingest_network_event(self, event: Dict):
        """Reçoit un événement réseau d'un agent → ASN."""
        if not self._asn:
            return
        try:
            from asn.shadow_network import NetworkPacket
            pkt = NetworkPacket(
                src_ip=event.get("src_ip", ""),
                dst_ip=event.get("dst_ip", ""),
                src_port=event.get("src_port", 0),
                dst_port=event.get("dst_port", 0),
                size=event.get("size", 0),
                timestamp=event.get("timestamp", time.time()),
                protocol=event.get("protocol", "TCP"),
                chaos_signed=event.get("chaos_signed", False),
            )
            self._asn.observe_packet(pkt)
        except Exception as e:
            logger.debug(f"PATENT-SERVER: ASN observe error: {e}")

    def _on_asn_alert(self, asn_alert):
        """Reçoit une alerte ASN et l'ajoute au flux global."""
        try:
            alert = asn_alert.to_alert()
            alert["source"] = "ASN"
            self._patent_alerts.append(alert)
            logger.warning(f"PATENT ASN: {alert.get('type')} — {asn_alert.divergence_type.value}")
        except Exception as e:
            logger.debug(f"PATENT-SERVER: ASN alert error: {e}")

    # ── Données pour l'API ────────────────────────────────────────────────────

    def get_global_status(self) -> Dict:
        """Vue globale de tous les brevets pour le dashboard."""
        # Agréger QBSM sur tous les agents
        qbsm_totals = {"total_processes": 0, "collapsed_threat": 0, "in_superposition": 0}
        cbga_totals = {"tracked_processes": 0, "total_alerts": 0}
        rctc_totals = {"total_assertions": 0, "revoked": 0}

        for state in self._agent_states.values():
            if "qbsm" in state:
                for k in qbsm_totals:
                    qbsm_totals[k] += state["qbsm"].get(k, 0)
            if "cbga" in state:
                for k in cbga_totals:
                    cbga_totals[k] += state["cbga"].get(k, 0)
            if "rctc" in state:
                for k in rctc_totals:
                    rctc_totals[k] += state["rctc"].get(k, 0)

        asn_status = {}
        if self._asn:
            asn_status = {
                "baseline_learned": self._asn._baseline_learned,
                "total_packets": self._asn._total_packets,
                "unsigned_blocked": self._asn._unsigned_blocked,
                "beacon_sessions": len(self._asn.anomaly_sessions),
            }

        return {
            "agents_reporting": len(self._agent_states),
            "total_patent_alerts": len(self._patent_alerts),
            "recent_patent_alerts": self._patent_alerts[-10:],
            "qbsm": qbsm_totals,
            "cbga": cbga_totals,
            "rctc": rctc_totals,
            "asn": asn_status,
            "zksp": {"note": "distributed — verified at agent level"},
            "per_agent": list(self._agent_states.values()),
        }

    def get_patent_alerts(self, limit: int = 50, alert_type: Optional[str] = None) -> List[Dict]:
        alerts = self._patent_alerts
        if alert_type:
            alerts = [a for a in alerts if a.get("type") == alert_type]
        return alerts[-limit:]

    def get_qbsm_landscape(self) -> Dict:
        """Paysage quantique complet de tous les processus surveillés."""
        landscape = {"agents": {}}
        for agent_id, state in self._agent_states.items():
            if "qbsm" in state:
                landscape["agents"][agent_id] = state["qbsm"]
        return landscape

    def get_rctc_trust_tree(self) -> Dict:
        """Arbre de confiance agrégé."""
        return {
            "per_agent": {
                a: s.get("rctc", {})
                for a, s in self._agent_states.items()
                if "rctc" in s
            }
        }
