"""
Gravity Patent Engine — Orchestrateur léger des 5 algorithmes brevetables.

Principe d'intégration ZERO OVERHEAD :
  - Reçoit les alertes EXISTANTES → les enrichit → les retourne enrichies
  - Pas de nouvelles boucles, pas de nouveaux threads lourds
  - Chaque algorithme s'active uniquement sur les alertes qui le concernent
  - Un seul point d'entrée : patent_engine.process(alert) → alert enrichie

Synergie avec l'existant :
  QBSM  ← toutes les alertes → collapse quantique si cohérence détectée
  CBGA  ← alertes processus → accumule le génome comportemental
  ZKSP  ← alertes TZTE/CPL → demande preuve ZK si violation détectée
  ASN   ← alertes NAC/réseau → enregistre les paquets dans le réseau fantôme
  RCTC  ← toutes les alertes → signe cryptographiquement chaque alerte
"""

import hashlib
import logging
import os
import time
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("gravity.patent")


class GravityPatentEngine:
    """
    Moteur unifié des algorithmes brevetables.
    S'intègre dans GravityAgent avec UNE seule ligne de code.
    """

    def __init__(self, agent_id: str, master_key: bytes,
                 on_patent_alert: Optional[Callable[[Dict], None]] = None):
        self.agent_id = agent_id
        self.master_key = master_key
        self.on_patent_alert = on_patent_alert

        # Chargement paresseux — les modules s'initialisent uniquement si disponibles
        self._qbsm = None
        self._cbga = None
        self._rctc = None
        self._asn = None
        self._zksp_prover = None

        # Assertion RCTC pour cet agent
        self._agent_assertion_id: Optional[str] = None

        # Stats légères
        self._processed = 0
        self._enriched = 0
        self._patent_alerts: List[Dict] = []

        self._init_modules()

    def _init_modules(self):
        """Initialise les modules — tolère les erreurs d'import gracieusement."""
        try:
            from qbsm.quantum_behavioral import QuantumBehavioralSuperpositionModel
            self._qbsm = QuantumBehavioralSuperpositionModel(
                on_collapse=self._on_qbsm_collapse
            )
            logger.info("PATENT: QBSM initialisé")
        except ImportError as e:
            logger.debug(f"PATENT: QBSM non disponible: {e}")

        try:
            from cbga.genome_alignment import CryptographicBehavioralGenomeAlignment
            self._cbga = CryptographicBehavioralGenomeAlignment(
                master_key=self.master_key,
                on_alert=self._on_cbga_alert,
            )
            logger.info("PATENT: CBGA initialisé")
        except ImportError as e:
            logger.debug(f"PATENT: CBGA non disponible: {e}")

        try:
            from rctc.recursive_trust import RecursiveCryptographicTrustChain, TrustAssertion
            self._rctc = RecursiveCryptographicTrustChain(
                master_key=self.master_key,
                on_violation=self._on_rctc_violation,
            )
            # Enregistrer cet agent dans la chaîne de confiance
            leaf = self._rctc.assert_trust(
                TrustAssertion.AGENT_IDENTITY,
                subject=self.agent_id,
                value=self.master_key.hex()[:32],
                parent_assertion_id="tpm-root",
                issuer_id="gravity-tpm",
            )
            if leaf:
                self._agent_assertion_id = leaf.assertion_id
            logger.info("PATENT: RCTC initialisé")
        except ImportError as e:
            logger.debug(f"PATENT: RCTC non disponible: {e}")

        try:
            from zksp.zero_knowledge_proof import ZeroKnowledgeSecurityProver
            self._zksp_prover = ZeroKnowledgeSecurityProver(self.master_key)
            logger.info("PATENT: ZKSP initialisé")
        except ImportError as e:
            logger.debug(f"PATENT: ZKSP non disponible: {e}")

        # ASN est côté serveur — l'agent envoie les méta-données réseau seulement

    # ── Point d'entrée unique ─────────────────────────────────────────────────

    def process(self, alert: Dict) -> Dict:
        """
        Enrichit une alerte existante avec les données de tous les modules brevets.
        Retourne l'alerte enrichie — NON modifiante si un module échoue.
        """
        self._processed += 1
        alert_type = alert.get("type", "")
        pid = alert.get("pid", 0)
        process_name = alert.get("process", "unknown")

        try:
            # 1. QBSM — observation quantique (toutes les alertes)
            if self._qbsm:
                collapse = self._qbsm.observe_from_alert(alert)
                state = self._qbsm._states.get(pid)
                if state:
                    alert["qbsm_p_threat"] = round(state.p_threat, 4)
                    alert["qbsm_state"] = state.state.value
                    alert["qbsm_coherence"] = round(state.coherence_phase, 3)
                if collapse and collapse.final_state.value == "threat":
                    alert["qbsm_collapsed"] = True
                    alert["qbsm_confidence"] = round(collapse.p_threat_at_collapse, 4)

            # 2. CBGA — accumulation du génome (alertes processus)
            if self._cbga and alert_type in {
                "SUSPICIOUS_PROCESS", "FILE_THREAT", "MEMORY_THREAT",
                "DNA_MUTATION", "SIGNATURE_MATCH", "NAC_BLOCK",
                "SYSCALL_ANOMALY", "RANSOMWARE_DETECTED",
            }:
                act = self._alert_to_genome_act(alert_type)
                if act and pid:
                    self._cbga.record_act(pid, process_name, act)
                    genome = self._cbga._genomes.get(pid)
                    if genome:
                        alert["cbga_genome_length"] = len(genome.sequence)
                        alert["cbga_genome_preview"] = genome.sequence[-10:]

            # 3. RCTC — signature cryptographique (toutes les alertes)
            if self._rctc and self._agent_assertion_id:
                self._rctc.sign_alert(alert, self._agent_assertion_id)

            self._enriched += 1

        except Exception as e:
            logger.debug(f"PATENT: Erreur enrichissement: {e}")

        return alert

    def process_network_event(self, src_ip: str, dst_ip: str,
                              dst_port: int, size: int,
                              chaos_signed: bool) -> Dict:
        """
        Enregistre un événement réseau pour l'ASN (Shadow Network).
        Retourne les méta-données à envoyer au serveur pour analyse ASN.
        """
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "size": size,
            "chaos_signed": chaos_signed,
            "timestamp": time.time(),
            "agent_id": self.agent_id,
        }

    def get_zksp_proof(self, pid: int, process_name: str,
                       acts: List[str], entropy: float,
                       policy_name: str) -> Optional[Dict]:
        """
        Génère une preuve ZK pour un processus.
        Appelé quand une vérification TZTE/CPL est requise.
        """
        if not self._zksp_prover:
            return None
        try:
            commitment, nonce = self._zksp_prover.commit(
                pid, process_name, acts, entropy, policy_name
            )
            return {
                "commitment": commitment.commitment,
                "policy_hash": commitment.policy_hash,
                "nonce_hash": commitment.nonce_hash,
                "pid": pid,
                "policy_name": policy_name,
                "_nonce": nonce,  # Garder en mémoire pour respond()
            }
        except Exception as e:
            logger.debug(f"PATENT: ZKSP commit failed: {e}")
            return None

    # ── Callbacks internes ────────────────────────────────────────────────────

    def _on_qbsm_collapse(self, collapse):
        """Appelé quand un état quantique s'effondre vers MENACE."""
        alert = collapse.to_alert()
        if alert:
            alert["agent_id"] = self.agent_id
            self._patent_alerts.append(alert)
            logger.warning(
                f"PATENT QBSM: PID={collapse.pid} '{collapse.process_name}' "
                f"effondré → MENACE (P={collapse.p_threat_at_collapse:.3f})"
            )
            if self.on_patent_alert:
                self.on_patent_alert(alert)

    def _on_cbga_alert(self, cbga_alert):
        """Appelé quand un génome comportemental matche un malware connu."""
        alert = cbga_alert.to_alert()
        alert["agent_id"] = self.agent_id
        self._patent_alerts.append(alert)
        logger.warning(
            f"PATENT CBGA: '{cbga_alert.process_name}' "
            f"~ '{cbga_alert.best_match.malware_name}' "
            f"sim={cbga_alert.best_match.similarity:.1%}"
        )
        if self.on_patent_alert:
            self.on_patent_alert(alert)

    def _on_rctc_violation(self, violation):
        """Appelé quand une chaîne de confiance est violée."""
        alert = violation.to_alert()
        alert["agent_id"] = self.agent_id
        self._patent_alerts.append(alert)
        if self.on_patent_alert:
            self.on_patent_alert(alert)

    def _alert_to_genome_act(self, alert_type: str) -> Optional[str]:
        """Convertit un type d'alerte en acte génomique."""
        mapping = {
            "FILE_THREAT": "file_read",
            "RANSOMWARE_DETECTED": "crypto_encrypt",
            "MEMORY_THREAT": "process_inject",
            "DNA_MUTATION": "process_inject",
            "SIGNATURE_MATCH": "credential_access",
            "NAC_BLOCK": "net_connect",
            "SUSPICIOUS_PROCESS": "execute_suspicious",
            "SYSCALL_ANOMALY": "memory_alloc_exec",
        }
        return mapping.get(alert_type)

    # ── État et stats ──────────────────────────────────────────────────────────

    def get_status(self) -> Dict:
        """Retourne l'état complet des modules brevets."""
        status = {
            "agent_id": self.agent_id,
            "processed": self._processed,
            "enriched": self._enriched,
            "patent_alerts": len(self._patent_alerts),
            "modules": {
                "qbsm": bool(self._qbsm),
                "cbga": bool(self._cbga),
                "rctc": bool(self._rctc),
                "zksp": bool(self._zksp_prover),
                "asn": False,  # côté serveur
            },
        }

        if self._qbsm:
            landscape = self._qbsm.get_threat_landscape()
            status["qbsm"] = {
                "total_processes": landscape["total_processes"],
                "in_superposition": landscape["in_superposition"],
                "collapsed_threat": landscape["collapsed_threat"],
                "collapsed_safe": landscape["collapsed_safe"],
                "decoherent": landscape["decoherent"],
            }

        if self._cbga:
            status["cbga"] = {
                "tracked_processes": len(self._cbga._genomes),
                "total_alerts": len(self._cbga.alerts),
                "reference_genomes": len(self._cbga.reference_genomes),
            }

        if self._rctc:
            tree = self._rctc.get_trust_tree()
            status["rctc"] = {
                "total_assertions": tree["total_assertions"],
                "revoked": tree["revoked_count"],
                "violations": tree["violations"],
            }

        if self._zksp_prover:
            status["zksp"] = {"available": True}

        status["recent_patent_alerts"] = self._patent_alerts[-5:]
        return status
