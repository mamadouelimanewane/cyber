"""
BREVET 1 — Quantum Behavioral Superposition Model (QBSM)
=========================================================

Concept fondamental :
  Un processus n'est pas "sûr" ou "malveillant" — il existe dans une SUPERPOSITION
  d'états de confiance, représentée par des amplitudes de probabilité complexes.
  Chaque observation (syscall, accès réseau, mutation) "effondre" partiellement
  cette superposition. La détection finale n'arrive que lorsque l'amplitude
  d'un état dépasse un seuil d'effondrement (comme la mesure en QM).

  Innovation brevetable :
  - Utilisation des amplitudes complexes (partie réelle + imaginaire) pour encoder
    à la fois la PROBABILITÉ de menace ET la COHÉRENCE temporelle des observations.
  - L'interférence constructive entre observations cohérentes renforce la détection.
  - L'interférence destructive entre observations contradictoires maintient
    la superposition (pas de faux positif précipité).
  - Premier système de sécurité utilisant le formalisme de la mécanique quantique
    pour la classification comportementale.

Formulation mathématique :
  État d'un processus : |ψ⟩ = α|SÛRE⟩ + β|MENACE⟩
  où α, β ∈ ℂ (nombres complexes) avec |α|² + |β|² = 1

  Observation d'événement e_i :
    Opérateur de mesure M_i appliqué à |ψ⟩
    |ψ'⟩ = M_i|ψ⟩ / ‖M_i|ψ⟩‖

  Probabilité de menace = |β|² (module au carré de l'amplitude menace)
  Effondrement si |β|² > θ_collapse (typiquement 0.85)

  Cohérence temporelle (phase) :
    φ = arg(β) encode la consistance temporelle des observations
    Observations cohérentes → même phase → interférence constructive → |β|² augmente
    Observations contradictoires → phases opposées → interférence destructive → doute

  Application sécurité :
    - Un malware cohérent dans son comportement → effondrement rapide vers MENACE
    - Un programme légitime avec pics occasionnels → superposition maintenue
    - Un malware polymorphe qui se contredit → détecté par son manque de cohérence
"""

import cmath
import hashlib
import logging
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class QuantumState(str, Enum):
    SUPERPOSITION = "superposition"   # pas encore décidé
    COLLAPSED_SAFE = "safe"           # effondré vers SÛRE
    COLLAPSED_THREAT = "threat"       # effondré vers MENACE
    DECOHERENT = "decoherent"         # observations trop contradictoires → revue manuelle


@dataclass
class ObservationOperator:
    """
    Opérateur quantique représentant une observation de sécurité.

    Chaque type d'événement a une matrice 2×2 dans la base {|SÛRE⟩, |MENACE⟩}.
    La matrice encode :
      - amplitude(SÛRE→SÛRE)    : quelle probabilité que ce soit bénin si déjà sûr
      - amplitude(SÛRE→MENACE)  : quelle probabilité que cela indique une menace
      - amplitude(MENACE→SÛRE)  : explication innocente si déjà suspect
      - amplitude(MENACE→MENACE): confirmation si déjà suspect

    Toutes les amplitudes sont complexes — la phase encode la certitude temporelle.
    """
    name: str
    # Matrice 2×2 : [[M_ss, M_st], [M_ts, M_tt]]
    # s=safe, t=threat
    M_ss: complex   # safe → safe
    M_st: complex   # safe → threat (une indication de menace sur un processus sûr)
    M_ts: complex   # threat → safe (une indication innocente sur un suspect)
    M_tt: complex   # threat → threat (confirmation de menace)
    weight: float = 1.0   # importance relative de cet opérateur

    def apply(self, alpha: complex, beta: complex) -> Tuple[complex, complex]:
        """
        Applique l'opérateur à l'état |ψ⟩ = α|SÛRE⟩ + β|MENACE⟩.
        Retourne (α', β') normalisés.
        """
        alpha_new = self.M_ss * alpha + self.M_ts * beta
        beta_new  = self.M_st * alpha + self.M_tt * beta

        # Normalisation : |α'|² + |β'|² = 1
        norm = math.sqrt(abs(alpha_new)**2 + abs(beta_new)**2)
        if norm < 1e-12:
            return complex(1, 0), complex(0, 0)

        return alpha_new / norm, beta_new / norm


# ── Bibliothèque d'opérateurs pré-définis ─────────────────────────────────────
# Phase φ = 0      → observation certaine (cohérente avec elle-même)
# Phase φ = π/4    → observation modérément certaine
# Phase φ = π/2    → observation très incertaine

def _op(name: str, safe_penalty: float, threat_boost: float,
        phase_certainty: float = 0.0, weight: float = 1.0) -> ObservationOperator:
    """
    Constructeur simplifié d'un opérateur de sécurité.
    safe_penalty  : combien l'observation réduit la confiance "sûre" [0, 1]
    threat_boost  : combien l'observation augmente la menace [0, 1]
    phase_certainty : φ en radians (0 = certain, π/2 = très incertain)
    """
    phase = cmath.exp(1j * phase_certainty)
    safe_stay  = complex(math.sqrt(1 - safe_penalty), 0)
    safe_leak  = complex(0, 0) if threat_boost == 0 else complex(math.sqrt(threat_boost), 0) * phase
    threat_stay = complex(math.sqrt(threat_boost + (1 - threat_boost) * 0.9), 0) * phase
    threat_expl = complex(math.sqrt(safe_penalty * 0.3), 0)  # petite chance d'explication innocente

    return ObservationOperator(
        name=name,
        M_ss=safe_stay, M_st=safe_leak,
        M_ts=threat_expl, M_tt=threat_stay,
        weight=weight,
    )


OPERATORS: Dict[str, ObservationOperator] = {
    # Injections mémoire — très certain, poids élevé
    "memory_injection": _op("memory_injection", 0.80, 0.95, phase_certainty=0.1, weight=2.0),
    # Tentative de dump credential
    "credential_access": _op("credential_access", 0.70, 0.90, phase_certainty=0.2, weight=1.8),
    # Ransomware — très certain
    "file_mass_encrypt": _op("file_mass_encrypt", 0.95, 0.99, phase_certainty=0.05, weight=3.0),
    # Connexion C2 — modérément certain (peut être légitime)
    "c2_beacon": _op("c2_beacon", 0.50, 0.75, phase_certainty=0.4, weight=1.5),
    # PowerShell encodé — modérément suspect
    "ps_encoded": _op("ps_encoded", 0.40, 0.65, phase_certainty=0.5, weight=1.2),
    # Honeytoken — très certain (faux positif quasi impossible)
    "honeytoken": _op("honeytoken", 0.99, 0.99, phase_certainty=0.01, weight=4.0),
    # Scan réseau interne
    "internal_scan": _op("internal_scan", 0.35, 0.60, phase_certainty=0.6, weight=1.0),
    # Mouvement latéral
    "lateral_movement": _op("lateral_movement", 0.65, 0.88, phase_certainty=0.15, weight=2.0),
    # DNA mutation
    "dna_mutation": _op("dna_mutation", 0.55, 0.80, phase_certainty=0.3, weight=1.6),
    # TZTE violation
    "tzte_violation": _op("tzte_violation", 0.60, 0.85, phase_certainty=0.2, weight=1.7),
    # Comportement normal — renforce la superposition vers SÛRE
    "normal_behavior": _op("normal_behavior", 0.05, 0.02, phase_certainty=0.8, weight=0.5),
    # LOLBin usage
    "lolbin": _op("lolbin", 0.45, 0.70, phase_certainty=0.45, weight=1.3),
}


@dataclass
class QuantumProcessState:
    """
    État quantique d'un processus — la superposition de confiance.

    |ψ⟩ = α|SÛRE⟩ + β|MENACE⟩

    Propriétés :
      P(SÛRE)  = |α|²
      P(MENACE) = |β|²
      Cohérence = arg(β) — phase de l'amplitude menace
      Intrication = corrélation avec d'autres processus du même groupe d'attaque
    """
    pid: int
    process_name: str
    alpha: complex = field(default_factory=lambda: complex(1.0, 0.0))  # commence SÛRE
    beta: complex  = field(default_factory=lambda: complex(0.0, 0.0))  # P(menace) = 0

    state: QuantumState = QuantumState.SUPERPOSITION
    collapse_time: Optional[float] = None
    observations: List[str] = field(default_factory=list)
    observation_times: List[float] = field(default_factory=list)

    # Intrication avec d'autres PIDs (même campagne d'attaque)
    entangled_pids: List[int] = field(default_factory=list)

    @property
    def p_safe(self) -> float:
        """Probabilité d'être sûr = |α|²"""
        return abs(self.alpha) ** 2

    @property
    def p_threat(self) -> float:
        """Probabilité de menace = |β|²"""
        return abs(self.beta) ** 2

    @property
    def coherence_phase(self) -> float:
        """Phase de l'amplitude menace — mesure la cohérence temporelle."""
        return cmath.phase(self.beta) if abs(self.beta) > 1e-10 else 0.0

    @property
    def decoherence_score(self) -> float:
        """
        Score de décohérence : mesure les contradictions dans les observations.
        Élevé = beaucoup d'observations contradictoires → comportement incohérent.
        """
        if len(self.observation_times) < 3:
            return 0.0
        # Variance des intervalles de temps entre observations
        intervals = [
            self.observation_times[i+1] - self.observation_times[i]
            for i in range(len(self.observation_times) - 1)
        ]
        mean = sum(intervals) / len(intervals)
        variance = sum((x - mean)**2 for x in intervals) / len(intervals)
        return min(1.0, variance / (mean**2 + 1e-10))

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "p_safe": round(self.p_safe, 4),
            "p_threat": round(self.p_threat, 4),
            "coherence_phase_rad": round(self.coherence_phase, 4),
            "decoherence_score": round(self.decoherence_score, 4),
            "quantum_state": self.state.value,
            "observations": self.observations[-10:],
            "entangled_pids": self.entangled_pids,
            "collapse_time": self.collapse_time,
        }


@dataclass
class QuantumCollapse:
    """Résultat d'un effondrement quantique — la décision finale."""
    pid: int
    process_name: str
    final_state: QuantumState
    p_threat_at_collapse: float
    coherence_phase: float
    decoherence_score: float
    triggering_observation: str
    total_observations: int
    entangled_pids: List[int]
    timestamp: float = field(default_factory=time.time)

    def to_alert(self) -> dict:
        if self.final_state != QuantumState.COLLAPSED_THREAT:
            return {}
        return {
            "type": "QBSM_COLLAPSE",
            "severity": "critical" if self.p_threat_at_collapse >= 0.95 else "high",
            "threat_score": self.p_threat_at_collapse,
            "process": self.process_name,
            "pid": self.pid,
            "reason": (
                f"Quantum state collapsed to THREAT for '{self.process_name}' "
                f"(P_threat={self.p_threat_at_collapse:.3f}, "
                f"coherence_φ={self.coherence_phase:.3f} rad, "
                f"decoherence={self.decoherence_score:.3f}). "
                f"Trigger: {self.triggering_observation}. "
                f"{self.total_observations} observations."
                + (f" Entangled PIDs: {self.entangled_pids}" if self.entangled_pids else "")
            ),
            "quantum_p_threat": self.p_threat_at_collapse,
            "quantum_coherence": self.coherence_phase,
            "quantum_decoherence": self.decoherence_score,
            "entangled_pids": self.entangled_pids,
            "mitre_technique_id": "T1059",
            "mitre_technique_name": "Behavioral Quantum Anomaly",
            "kill_chain_phase": 2,
            "timestamp": self.timestamp,
        }


class QuantumBehavioralSuperpositionModel:
    """
    Moteur QBSM — gère les états quantiques de tous les processus surveillés.

    Algorithme principal :
    1. Chaque processus démarre en superposition : |ψ⟩ = |SÛRE⟩ (α=1, β=0)
    2. Chaque observation applique un opérateur quantique sur l'état
    3. P(menace) = |β|² croît avec les observations malveillantes
    4. Effondrement si P(menace) > θ_collapse OU P(sûre) > θ_safe
    5. Intrication : si deux processus sont dans la même campagne d'attaque,
       l'effondrement de l'un influence l'autre (propagation quantique)

    Innovation clé : l'interférence quantique permet de détecter des attaques
    ÉTALÉES DANS LE TEMPS qui seraient invisibles à tout autre système :
    - Une observation malveillante isolée → ne collapse pas (bruit)
    - Plusieurs observations cohérentes (même phase) → interference constructive → collapse
    - Observations contradictoires → décohérence → alerte "comportement incohérent"
    """

    COLLAPSE_THREAT_THRESHOLD = 0.85   # P(menace) > 85% → COLLAPSED_THREAT
    COLLAPSE_SAFE_THRESHOLD = 0.98     # P(sûre) > 98% → COLLAPSED_SAFE
    DECOHERENCE_THRESHOLD = 0.90       # décohérence > 90% → DECOHERENT

    # Constante d'intrication : effondrement d'un processus influence les autres à ce taux
    ENTANGLEMENT_COUPLING = 0.3

    def __init__(self, on_collapse: Optional[Callable[[QuantumCollapse], None]] = None):
        self.on_collapse = on_collapse
        self._states: Dict[int, QuantumProcessState] = {}
        self.collapses: List[QuantumCollapse] = []
        # Groupes d'intrication : campaign_id → set of PIDs
        self._entanglement_groups: Dict[str, set] = {}

    def register_process(self, pid: int, process_name: str) -> QuantumProcessState:
        state = QuantumProcessState(pid=pid, process_name=process_name)
        self._states[pid] = state
        return state

    def _get_or_create(self, pid: int, process_name: str = "unknown") -> QuantumProcessState:
        if pid not in self._states:
            self.register_process(pid, process_name)
        return self._states[pid]

    def observe(self, pid: int, process_name: str,
                observation_type: str,
                weight_override: Optional[float] = None) -> Optional[QuantumCollapse]:
        """
        Applique une observation sur l'état quantique d'un processus.
        Retourne un QuantumCollapse si l'état s'effondre.
        """
        state = self._get_or_create(pid, process_name)

        if state.state != QuantumState.SUPERPOSITION:
            return None  # déjà effondré

        operator = OPERATORS.get(observation_type)
        if operator is None:
            logger.warning(f"QBSM: Unknown operator '{observation_type}'")
            return None

        # Appliquer l'opérateur (avec poids optionnel)
        if weight_override:
            # Modifie temporairement le poids
            orig = operator.weight
            operator = ObservationOperator(
                name=operator.name, M_ss=operator.M_ss, M_st=operator.M_st,
                M_ts=operator.M_ts, M_tt=operator.M_tt, weight=weight_override
            )

        new_alpha, new_beta = operator.apply(state.alpha, state.beta)

        # Pondération par le poids de l'opérateur
        w = operator.weight
        state.alpha = (state.alpha * (1 - w * 0.3) + new_alpha * w * 0.3)
        state.beta  = (state.beta  * (1 - w * 0.3) + new_beta  * w * 0.3)

        # Re-normaliser
        norm = math.sqrt(abs(state.alpha)**2 + abs(state.beta)**2)
        state.alpha /= norm
        state.beta  /= norm

        state.observations.append(observation_type)
        state.observation_times.append(time.time())

        logger.debug(
            f"QBSM: PID={pid} '{process_name}' obs='{observation_type}' "
            f"P_threat={state.p_threat:.3f} φ={state.coherence_phase:.3f}"
        )

        # Vérifier l'effondrement
        return self._check_collapse(state, observation_type)

    def _check_collapse(self, state: QuantumProcessState,
                        trigger: str) -> Optional[QuantumCollapse]:
        """Vérifie si l'état doit s'effondrer."""
        # Vérifier décohérence d'abord
        if (state.decoherence_score > self.DECOHERENCE_THRESHOLD
                and len(state.observations) > 10):
            state.state = QuantumState.DECOHERENT
            collapse = self._make_collapse(state, trigger)
            return collapse

        # Effondrement vers MENACE
        if state.p_threat >= self.COLLAPSE_THREAT_THRESHOLD:
            state.state = QuantumState.COLLAPSED_THREAT
            state.collapse_time = time.time()
            collapse = self._make_collapse(state, trigger)
            self._propagate_entanglement(state, boost=self.ENTANGLEMENT_COUPLING)
            return collapse

        # Effondrement vers SÛRE
        if state.p_safe >= self.COLLAPSE_SAFE_THRESHOLD:
            state.state = QuantumState.COLLAPSED_SAFE
            state.collapse_time = time.time()
            return self._make_collapse(state, trigger)

        return None

    def _make_collapse(self, state: QuantumProcessState,
                       trigger: str) -> QuantumCollapse:
        collapse = QuantumCollapse(
            pid=state.pid,
            process_name=state.process_name,
            final_state=state.state,
            p_threat_at_collapse=state.p_threat,
            coherence_phase=state.coherence_phase,
            decoherence_score=state.decoherence_score,
            triggering_observation=trigger,
            total_observations=len(state.observations),
            entangled_pids=list(state.entangled_pids),
        )
        self.collapses.append(collapse)

        if state.state == QuantumState.COLLAPSED_THREAT:
            logger.critical(
                f"QBSM COLLAPSE → MENACE: PID={state.pid} '{state.process_name}' "
                f"P={state.p_threat:.3f} φ={state.coherence_phase:.3f} trigger={trigger}"
            )
        elif state.state == QuantumState.DECOHERENT:
            logger.warning(
                f"QBSM DECOHERENT: PID={state.pid} '{state.process_name}' "
                f"(contradictions détectées — revue manuelle requise)"
            )

        if self.on_collapse:
            self.on_collapse(collapse)

        return collapse

    def entangle(self, pid1: int, pid2: int, campaign_id: str):
        """
        Intrication quantique : deux processus de la même campagne d'attaque.
        L'effondrement de l'un influence l'autre.
        """
        if campaign_id not in self._entanglement_groups:
            self._entanglement_groups[campaign_id] = set()
        self._entanglement_groups[campaign_id].add(pid1)
        self._entanglement_groups[campaign_id].add(pid2)

        s1 = self._get_or_create(pid1)
        s2 = self._get_or_create(pid2)
        if pid2 not in s1.entangled_pids:
            s1.entangled_pids.append(pid2)
        if pid1 not in s2.entangled_pids:
            s2.entangled_pids.append(pid1)

        logger.info(f"QBSM: PIDs {pid1}↔{pid2} intriqués dans campagne '{campaign_id}'")

    def _propagate_entanglement(self, collapsed_state: QuantumProcessState,
                                boost: float):
        """
        Propage l'effondrement aux processus intriqués.
        Un processus intriqué avec un processus MENACE voit sa P_threat boostée.
        """
        for peer_pid in collapsed_state.entangled_pids:
            peer = self._states.get(peer_pid)
            if peer and peer.state == QuantumState.SUPERPOSITION:
                # Boost quantique : augmente P_threat du pair
                peer.beta = peer.beta + complex(boost * (1 - peer.p_threat), 0)
                norm = math.sqrt(abs(peer.alpha)**2 + abs(peer.beta)**2)
                peer.alpha /= norm
                peer.beta  /= norm
                logger.info(
                    f"QBSM: Entanglement boost PID={peer_pid} "
                    f"new P_threat={peer.p_threat:.3f}"
                )
                self._check_collapse(peer, f"entanglement_from_{collapsed_state.pid}")

    def get_threat_landscape(self) -> dict:
        """Vue d'ensemble de tous les états quantiques."""
        states = [s.to_dict() for s in self._states.values()]
        collapsed_threats = [c.to_alert() for c in self.collapses
                             if c.final_state == QuantumState.COLLAPSED_THREAT]
        return {
            "total_processes": len(self._states),
            "in_superposition": sum(1 for s in self._states.values()
                                    if s.state == QuantumState.SUPERPOSITION),
            "collapsed_threat": sum(1 for s in self._states.values()
                                    if s.state == QuantumState.COLLAPSED_THREAT),
            "collapsed_safe": sum(1 for s in self._states.values()
                                  if s.state == QuantumState.COLLAPSED_SAFE),
            "decoherent": sum(1 for s in self._states.values()
                              if s.state == QuantumState.DECOHERENT),
            "entanglement_groups": len(self._entanglement_groups),
            "recent_collapses": collapsed_threats[-5:],
            "process_states": states,
        }

    def observe_from_alert(self, alert: dict) -> Optional[QuantumCollapse]:
        """Convertit une alerte Gravity en observation quantique."""
        type_to_obs = {
            "MEMORY_THREAT": "memory_injection",
            "HONEYTOKEN_TRIGGERED": "honeytoken",
            "DNA_MUTATION": "dna_mutation",
            "NAC_BLOCK": "c2_beacon",
            "SUSPICIOUS_PROCESS": "ps_encoded",
            "SIGNATURE_MATCH": "credential_access",
            "TZTE_VIOLATION": "tzte_violation",
            "CPL_VIOLATION": "memory_injection",
            "SYSCALL_ANOMALY": "lateral_movement",
            "RANSOMWARE_DETECTED": "file_mass_encrypt",
        }
        obs_type = type_to_obs.get(alert.get("type"), "normal_behavior")
        pid = alert.get("pid", 0)
        process_name = alert.get("process", "unknown")
        weight = alert.get("threat_score", 0.5) * 2  # score → poids

        return self.observe(pid, process_name, obs_type, weight_override=weight)
