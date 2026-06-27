"""
Gravity Security — Network Access Control (NAC)
Basé sur le principe du Mathematical Chaos Engine de Cyber 2.0.

Principe :
- Chaque paquet sortant d'un agent AUTORISÉ est signé avec la clé chaotique courante
- Les agents récepteurs VÉRIFIENT la signature avant d'accepter le paquet
- Un paquet sans signature valide est REJETÉ — silencieusement, automatiquement
- Un malware sur une machine autorisée ne connaît pas la clé → son trafic est rejeté

Ce module gère la couche logicielle du NAC (inspection/filtrage applicatif).
Pour un filtrage bas niveau, intégrer avec WFP (Windows Filtering Platform).
"""

import socket
import struct
import logging
import threading
import time
from typing import Dict, Set, Callable, Optional
from dataclasses import dataclass

from ..chaos_engine import ChaosEngine

logger = logging.getLogger("gravity.nac")

GRAVITY_MAGIC = b"\xGR\xAV"  # Marqueur de paquet Gravity Security
GRAVITY_VERSION = 1


@dataclass
class AgentInfo:
    agent_id: str
    ip: str
    authorized: bool
    last_seen: float
    packets_sent: int = 0
    packets_blocked: int = 0


class NACFilter:
    """
    Filtre NAC applicatif — inspecte et signe les paquets inter-agents.

    En production, s'interface avec WFP (Windows) ou Netfilter (Linux)
    pour du filtrage au niveau kernel. Ici on implémente la logique
    d'inspection/signature qui s'applique à n'importe quelle couche.
    """

    def __init__(self, agent_id: str, shared_secret: str):
        self.agent_id = agent_id
        self.chaos = ChaosEngine(agent_id, shared_secret)
        self._authorized_agents: Dict[str, AgentInfo] = {}
        self._blocked_ips: Set[str] = set()
        self._alert_callback: Optional[Callable] = None
        self._stats = {"allowed": 0, "blocked": 0, "signed": 0}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    #  Gestion des agents autorisés                                      #
    # ------------------------------------------------------------------ #

    def authorize_agent(self, agent_id: str, ip: str):
        """Ajoute un agent à la liste des pairs autorisés."""
        with self._lock:
            self._authorized_agents[ip] = AgentInfo(
                agent_id=agent_id,
                ip=ip,
                authorized=True,
                last_seen=time.time(),
            )
            logger.info(f"Agent autorisé: {agent_id} ({ip})")

    def revoke_agent(self, ip: str):
        """Révoque l'autorisation d'un agent — bloque immédiatement son IP."""
        with self._lock:
            if ip in self._authorized_agents:
                del self._authorized_agents[ip]
            self._blocked_ips.add(ip)
            logger.warning(f"Agent révoqué: {ip}")

    def is_authorized(self, ip: str) -> bool:
        return ip in self._authorized_agents and ip not in self._blocked_ips

    # ------------------------------------------------------------------ #
    #  Signature / Vérification des paquets                              #
    # ------------------------------------------------------------------ #

    def sign_outgoing(self, data: bytes) -> bytes:
        """
        Signe un paquet sortant avec la clé chaotique courante.
        Structure : [MAGIC:4][VERSION:1][AGENT_ID_LEN:1][AGENT_ID][PAYLOAD][SIG:8]
        """
        agent_bytes = self.agent_id.encode("utf-8")
        header = (
            b"\xAA\xBB\xCC\xDD"  # Magic Gravity Security
            + struct.pack("B", GRAVITY_VERSION)
            + struct.pack("B", len(agent_bytes))
            + agent_bytes
        )
        packet = header + data
        signed = self.chaos.sign_packet(packet)
        self._stats["signed"] += 1
        return signed

    def verify_incoming(self, signed_packet: bytes, source_ip: str) -> tuple[bool, bytes]:
        """
        Vérifie un paquet entrant.
        Retourne (autorisé, payload) ou (False, b"") si rejeté.
        """
        # 1. IP dans la liste noire ?
        if source_ip in self._blocked_ips:
            self._block(source_ip, "IP blacklistée")
            return False, b""

        # 2. IP autorisée ?
        if not self.is_authorized(source_ip):
            self._block(source_ip, "Agent non autorisé — trafic NAC rejeté")
            return False, b""

        # 3. Signature chaotique valide ?
        if not self.chaos.verify_packet(signed_packet):
            self._block(source_ip, "Signature chaotique invalide — possible malware ou replay")
            return False, b""

        # Extraire le payload (retirer header + signature)
        try:
            offset = 4 + 1 + 1  # magic + version + len
            agent_id_len = signed_packet[5]
            payload = signed_packet[offset + agent_id_len:-8]  # retirer sig 8 octets
        except Exception:
            return False, b""

        # Mise à jour last_seen
        with self._lock:
            if source_ip in self._authorized_agents:
                self._authorized_agents[source_ip].last_seen = time.time()
                self._authorized_agents[source_ip].packets_sent += 1

        self._stats["allowed"] += 1
        return True, payload

    # ------------------------------------------------------------------ #
    #  Blocage & Alertes                                                 #
    # ------------------------------------------------------------------ #

    def _block(self, source_ip: str, reason: str):
        self._stats["blocked"] += 1
        if source_ip in self._authorized_agents:
            self._authorized_agents[source_ip].packets_blocked += 1
        logger.warning(f"[NAC BLOCAGE] {source_ip} — {reason}")
        if self._alert_callback:
            self._alert_callback({
                "type": "NAC_BLOCK",
                "source_ip": source_ip,
                "reason": reason,
                "timestamp": time.time(),
            })

    def on_alert(self, callback: Callable):
        """Enregistre un callback pour les événements de blocage."""
        self._alert_callback = callback

    # ------------------------------------------------------------------ #
    #  Statistiques                                                      #
    # ------------------------------------------------------------------ #

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                **self._stats,
                "authorized_agents": len(self._authorized_agents),
                "blocked_ips": len(self._blocked_ips),
            }

    def get_agents_status(self) -> Dict:
        with self._lock:
            return {
                ip: {
                    "agent_id": info.agent_id,
                    "authorized": info.authorized,
                    "last_seen": info.last_seen,
                    "packets_sent": info.packets_sent,
                    "packets_blocked": info.packets_blocked,
                    "online": (time.time() - info.last_seen) < 30,
                }
                for ip, info in self._authorized_agents.items()
            }
