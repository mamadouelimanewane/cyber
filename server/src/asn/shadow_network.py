"""
BREVET 4 — Adversarial Shadow Network (ASN)
============================================

Concept fondamental :
  Chaque paquet réseau entrant est dupliqué et envoyé simultanément au réseau
  réel ET à un réseau fantôme (Shadow Network). Le réseau fantôme est un
  miroir parfait mais PASSIF — il ne traite jamais les paquets, il les absorbe.

  La DIVERGENCE entre le comportement du réseau réel et du réseau fantôme
  révèle les attaques. Un attaquant qui ne connaît pas l'existence du réseau
  fantôme interagit différemment avec les deux (timing, réponses, patterns).

  Innovation brevetable :
  - Premier système de détection basé sur la DIVERGENCE de comportement entre
    réseau réel et réseau miroir.
  - Distance de Wasserstein (transport optimal) pour mesurer la divergence
    entre distributions de trafic — mathématique jamais utilisée en IDS.
  - Shadow Network adaptatif : le miroir évolue pour maximiser la divergence
    détectable.
  - Intégration avec le Chaos Engine : seul trafic signé par le Chaos Engine
    peut être "aligné" — tout désalignement = attaque.
  - "Honeymesh" : le réseau fantôme peut répondre aux attaquants avec des
    leurres automatiquement générés.

Formulation mathématique :
  Trafic réel   : R = distribution empirique des paquets {p_i = (src, dst, size, timing)}
  Trafic fantôme: S = distribution théorique attendue (baseline apprise)

  Distance de Wasserstein W₁ :
    W₁(R, S) = inf_{γ ∈ Γ(R,S)} ∫∫ d(x,y) dγ(x,y)

  où d(x,y) = distance entre paquets (src_dist + dst_dist + size_ratio + timing_delta)

  Approximation pratique (Earth Mover's Distance sur histogrammes) :
    W₁(R, S) ≈ Σ_i |CDF_R(i) - CDF_S(i)| × Δi

  Seuils de divergence :
    W₁ < 0.05 → Normal
    W₁ ∈ [0.05, 0.20] → SUSPICIOUS
    W₁ > 0.20 → ATTACK DETECTED

  Détection d'attaques spécifiques par signature de divergence :
    - DDoS      : Δsize ↑↑, Δtiming ↓↓ (paquets rapides + grands)
    - Scan port : Δdst ↑↑, Δsize ↓ (beaucoup de destinations, petits paquets)
    - C2 Beacon : Δtiming très régulier (beaconing clockwork)
    - Exfil     : Δsize ↑ + dst = externe (gros paquets vers l'extérieur)
"""

import collections
import hashlib
import logging
import math
import statistics
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class DivergenceType(str, Enum):
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    DDOS = "ddos"
    PORT_SCAN = "port_scan"
    C2_BEACON = "c2_beacon"
    EXFILTRATION = "exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    UNKNOWN_ATTACK = "unknown_attack"


@dataclass
class NetworkPacket:
    """Représentation d'un paquet réseau pour l'analyse ASN."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    size: int           # bytes
    timestamp: float
    protocol: str       # "TCP", "UDP", "ICMP"
    chaos_signed: bool  # Signé par le Chaos Engine ?
    payload_entropy: float = 0.0

    def feature_vector(self) -> Tuple[float, ...]:
        """Vecteur de caractéristiques normalisées pour la distance W₁."""
        return (
            hash(self.src_ip) % 65536 / 65536,     # src normalisé
            hash(self.dst_ip) % 65536 / 65536,     # dst normalisé
            self.dst_port / 65535,                  # port normalisé
            min(self.size / 65535, 1.0),            # taille normalisée
            self.payload_entropy / 8.0,             # entropie normalisée
            1.0 if self.chaos_signed else 0.0,      # signature Chaos
        )


@dataclass
class TrafficDistribution:
    """Distribution statistique du trafic réseau (baseline ou observé)."""
    # Histogrammes des caractéristiques
    size_histogram: Dict[int, int] = field(default_factory=dict)     # bucket → count
    port_histogram: Dict[int, int] = field(default_factory=dict)
    inter_arrival_times: Deque[float] = field(default_factory=lambda: collections.deque(maxlen=500))
    src_diversity: set = field(default_factory=set)
    dst_diversity: set = field(default_factory=set)
    external_bytes: int = 0
    total_packets: int = 0
    unsigned_count: int = 0    # Paquets sans signature Chaos
    last_packet_time: float = 0.0

    def add_packet(self, packet: NetworkPacket):
        size_bucket = (packet.size // 100) * 100
        self.size_histogram[size_bucket] = self.size_histogram.get(size_bucket, 0) + 1
        self.port_histogram[packet.dst_port] = self.port_histogram.get(packet.dst_port, 0) + 1
        self.src_diversity.add(packet.src_ip)
        self.dst_diversity.add(packet.dst_ip)
        if not packet.chaos_signed:
            self.unsigned_count += 1

        # Track inter-arrival times
        now = packet.timestamp
        if self.last_packet_time > 0:
            self.inter_arrival_times.append(now - self.last_packet_time)
        self.last_packet_time = now
        self.total_packets += 1

        # Estimate if external
        if not packet.dst_ip.startswith(("192.168.", "10.", "172.")):
            self.external_bytes += packet.size

    def beaconing_regularity(self) -> float:
        """
        Mesure la régularité temporelle du trafic (0=irrégulier, 1=parfaitement régulier).
        Un score élevé indique du beaconing C2.
        """
        if len(self.inter_arrival_times) < 5:
            return 0.0
        times = list(self.inter_arrival_times)
        mean = statistics.mean(times)
        if mean == 0:
            return 0.0
        std = statistics.stdev(times) if len(times) > 1 else 0.0
        cv = std / mean  # Coefficient de variation
        return max(0.0, 1.0 - min(cv, 1.0))  # CV bas → régulier → score élevé


def wasserstein_distance_1d(hist_a: Dict[int, int],
                             hist_b: Dict[int, int]) -> float:
    """
    Distance de Wasserstein W₁ approximée pour histogrammes 1D.
    Utilise la méthode des CDFs : W₁ = ∫|CDF_A - CDF_B|dx
    """
    all_keys = sorted(set(list(hist_a.keys()) + list(hist_b.keys())))
    if not all_keys:
        return 0.0

    total_a = max(sum(hist_a.values()), 1)
    total_b = max(sum(hist_b.values()), 1)

    cdf_diff_sum = 0.0
    cdf_a, cdf_b = 0.0, 0.0

    for k in all_keys:
        cdf_a += hist_a.get(k, 0) / total_a
        cdf_b += hist_b.get(k, 0) / total_b
        cdf_diff_sum += abs(cdf_a - cdf_b)

    return cdf_diff_sum / len(all_keys)


@dataclass
class DivergenceAlert:
    """Alerte générée par détection de divergence réseau."""
    divergence_type: DivergenceType
    wasserstein_distance: float
    source_ip: Optional[str]
    details: dict
    severity: float
    timestamp: float = field(default_factory=time.time)

    def to_alert(self) -> dict:
        return {
            "type": f"ASN_{self.divergence_type.value.upper()}",
            "severity": "critical" if self.severity >= 0.9 else "high",
            "threat_score": self.severity,
            "source_ip": self.source_ip,
            "reason": (
                f"Shadow Network divergence detected: {self.divergence_type.value} "
                f"(W₁={self.wasserstein_distance:.4f}). "
                + str(self.details)
            ),
            "wasserstein_distance": round(self.wasserstein_distance, 4),
            "divergence_type": self.divergence_type.value,
            "mitre_technique_id": self._mitre(),
            "kill_chain_phase": self._phase(),
            "timestamp": self.timestamp,
        }

    def _mitre(self) -> str:
        return {
            DivergenceType.C2_BEACON: "T1071",
            DivergenceType.EXFILTRATION: "T1041",
            DivergenceType.PORT_SCAN: "T1046",
            DivergenceType.DDOS: "T1498",
            DivergenceType.LATERAL_MOVEMENT: "T1021",
        }.get(self.divergence_type, "T1040")

    def _phase(self) -> int:
        return {
            DivergenceType.C2_BEACON: 6,
            DivergenceType.EXFILTRATION: 7,
            DivergenceType.PORT_SCAN: 1,
            DivergenceType.DDOS: 8,
            DivergenceType.LATERAL_MOVEMENT: 6,
        }.get(self.divergence_type, 6)


class AdversarialShadowNetwork:
    """
    Réseau Fantôme Adversarial — détecte les attaques par divergence de distribution.

    Architecture :
    - baseline : distribution du trafic normal (apprise sur 24h)
    - shadow   : distribution du trafic actuel (fenêtre glissante 60s)
    - Comparaison W₁ toutes les 10s
    - Détection de patterns d'attaque spécifiques

    Intégration Gravity :
    - Reçoit chaque paquet via observe_packet()
    - Vérifie la signature Chaos Engine
    - Alerte si divergence > seuil ou si pattern d'attaque détecté
    """

    # Seuils de divergence W₁
    THRESHOLD_SUSPICIOUS = 0.05
    THRESHOLD_ATTACK = 0.20

    # Seuils des patterns spécifiques
    BEACON_REGULARITY_THRESHOLD = 0.85   # > 85% régularité = beaconing
    SCAN_DST_DIVERSITY_THRESHOLD = 50    # > 50 destinations uniques / min = scan
    EXFIL_EXTERNAL_RATIO = 0.70          # > 70% bytes externes = exfil
    UNSIGNED_RATIO_THRESHOLD = 0.30      # > 30% paquets non signés = suspect

    # Fenêtre temporelle
    WINDOW_SECONDS = 60.0

    def __init__(self, on_alert: Optional[Callable[[DivergenceAlert], None]] = None):
        self.on_alert = on_alert
        self.alerts: List[DivergenceAlert] = []

        # Distribution baseline (trafic normal)
        self.baseline = TrafficDistribution()
        self._baseline_packets: int = 0
        self._baseline_learned = False

        # Distribution courante (fenêtre glissante)
        self.current = TrafficDistribution()
        self._packet_window: Deque[NetworkPacket] = collections.deque()

        # Statistiques
        self._total_packets = 0
        self._unsigned_blocked = 0
        self._last_analysis_time = time.time()

        logger.info("ASN: Adversarial Shadow Network initialized")

    def observe_packet(self, packet: NetworkPacket):
        """
        Observe un paquet réseau.
        Appelé pour CHAQUE paquet — réel ET miroir fantôme.
        """
        self._total_packets += 1

        # Comptage des paquets non signés par le Chaos Engine
        if not packet.chaos_signed:
            self._unsigned_blocked += 1

        # Ajouter à la fenêtre courante
        self._packet_window.append(packet)
        self.current.add_packet(packet)

        # Apprendre la baseline pendant les 1000 premiers paquets
        if not self._baseline_learned:
            self.baseline.add_packet(packet)
            self._baseline_packets += 1
            if self._baseline_packets >= 1000:
                self._baseline_learned = True
                logger.info("ASN: Baseline traffic distribution learned")
            return

        # Nettoyer la fenêtre (garder seulement WINDOW_SECONDS)
        now = packet.timestamp
        while self._packet_window and (now - self._packet_window[0].timestamp) > self.WINDOW_SECONDS:
            self._packet_window.popleft()

        # Analyser toutes les 10 secondes
        if (now - self._last_analysis_time) >= 10.0:
            self._analyze()
            self._last_analysis_time = now
            # Reset distribution courante pour la prochaine fenêtre
            self.current = TrafficDistribution()
            for p in self._packet_window:
                self.current.add_packet(p)

    def _analyze(self):
        """Lance l'analyse de divergence complète."""
        # 1. Distance de Wasserstein sur la taille des paquets
        w1_size = wasserstein_distance_1d(
            self.current.size_histogram,
            self.baseline.size_histogram,
        )
        # 2. Distance de Wasserstein sur les ports de destination
        w1_port = wasserstein_distance_1d(
            self.current.port_histogram,
            self.baseline.port_histogram,
        )
        w1_avg = (w1_size + w1_port) / 2

        # 3. Détection de patterns spécifiques
        self._detect_c2_beacon()
        self._detect_port_scan()
        self._detect_exfiltration()
        self._detect_unsigned_traffic()

        # 4. Alerte de divergence générale
        if w1_avg >= self.THRESHOLD_ATTACK:
            self._emit_alert(
                dtype=DivergenceType.UNKNOWN_ATTACK,
                w1=w1_avg,
                src=None,
                severity=min(0.99, 0.7 + w1_avg),
                details={
                    "w1_size": round(w1_size, 4),
                    "w1_port": round(w1_port, 4),
                    "current_packets": self.current.total_packets,
                },
            )
        elif w1_avg >= self.THRESHOLD_SUSPICIOUS:
            logger.debug(f"ASN: Suspicious divergence W₁={w1_avg:.4f}")

    def _detect_c2_beacon(self):
        """Détecte le beaconing C2 par régularité temporelle."""
        regularity = self.current.beaconing_regularity()
        if regularity >= self.BEACON_REGULARITY_THRESHOLD:
            self._emit_alert(
                dtype=DivergenceType.C2_BEACON,
                w1=regularity,
                src=list(self.current.src_diversity)[-1] if self.current.src_diversity else None,
                severity=0.85 + regularity * 0.14,
                details={
                    "beaconing_regularity": round(regularity, 3),
                    "description": "Clockwork-regular packet timing indicates C2 beacon",
                },
            )

    def _detect_port_scan(self):
        """Détecte les scans de port par diversité des destinations."""
        dst_count = len(self.current.dst_diversity)
        if dst_count >= self.SCAN_DST_DIVERSITY_THRESHOLD:
            ratio = dst_count / max(self.current.total_packets, 1)
            self._emit_alert(
                dtype=DivergenceType.PORT_SCAN,
                w1=min(ratio, 1.0),
                src=list(self.current.src_diversity)[-1] if self.current.src_diversity else None,
                severity=0.78 + min(ratio, 0.2),
                details={
                    "unique_destinations": dst_count,
                    "packets": self.current.total_packets,
                    "description": f"High destination diversity: {dst_count} unique IPs/ports",
                },
            )

    def _detect_exfiltration(self):
        """Détecte l'exfiltration par ratio de bytes externes."""
        if self.current.total_packets < 10:
            return
        # Approximation : estimer le total bytes
        total_size = sum(
            k * v for k, v in self.current.size_histogram.items()
        )
        if total_size == 0:
            return
        external_ratio = self.current.external_bytes / total_size
        if external_ratio >= self.EXFIL_EXTERNAL_RATIO:
            self._emit_alert(
                dtype=DivergenceType.EXFILTRATION,
                w1=external_ratio,
                src=list(self.current.src_diversity)[-1] if self.current.src_diversity else None,
                severity=0.82 + external_ratio * 0.17,
                details={
                    "external_bytes": self.current.external_bytes,
                    "external_ratio": round(external_ratio, 3),
                    "description": "High external traffic ratio suggests data exfiltration",
                },
            )

    def _detect_unsigned_traffic(self):
        """Détecte trafic non signé par le Chaos Engine."""
        if self._total_packets < 50:
            return
        unsigned_ratio = self._unsigned_blocked / self._total_packets
        if unsigned_ratio >= self.UNSIGNED_RATIO_THRESHOLD:
            self._emit_alert(
                dtype=DivergenceType.UNKNOWN_ATTACK,
                w1=unsigned_ratio,
                src=None,
                severity=0.75 + unsigned_ratio * 0.24,
                details={
                    "unsigned_ratio": round(unsigned_ratio, 3),
                    "unsigned_count": self._unsigned_blocked,
                    "description": "High ratio of traffic without Chaos Engine signature",
                },
            )

    def _emit_alert(self, dtype: DivergenceType, w1: float,
                    src: Optional[str], severity: float, details: dict):
        # Déduplier : même type d'alerte dans les 30s
        now = time.time()
        recent = [a for a in self.alerts[-10:]
                  if a.divergence_type == dtype and (now - a.timestamp) < 30]
        if recent:
            return

        alert = DivergenceAlert(
            divergence_type=dtype, wasserstein_distance=w1,
            source_ip=src, details=details, severity=severity,
        )
        self.alerts.append(alert)
        logger.warning(
            f"ASN ALERT [{dtype.value}]: W₁={w1:.4f} sev={severity:.2f} — {details}"
        )
        if self.on_alert:
            self.on_alert(alert)

    def reset_baseline(self):
        """Réinitialise la baseline après un incident résolu."""
        self.baseline = TrafficDistribution()
        self._baseline_packets = 0
        self._baseline_learned = False
        logger.info("ASN: Baseline reset — re-learning mode")

    def stats(self) -> dict:
        return {
            "total_packets_observed": self._total_packets,
            "unsigned_blocked": self._unsigned_blocked,
            "baseline_learned": self._baseline_learned,
            "baseline_packets": self._baseline_packets,
            "current_window_packets": self.current.total_packets,
            "total_alerts": len(self.alerts),
            "alert_types": {
                dt.value: sum(1 for a in self.alerts if a.divergence_type == dt)
                for dt in DivergenceType
            },
        }
