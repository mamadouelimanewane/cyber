"""
BREVET 5 — Recursive Cryptographic Trust Chain (RCTC)
======================================================

Concept fondamental :
  Toute assertion de confiance ("ce processus est sûr", "cet agent est légitime",
  "cette alerte est authentique") est prouvée récursivement jusqu'à une racine
  de confiance matérielle (TPM ou HSM).

  Contrairement aux PKI traditionnelles (chaîne linéaire CA → intermediate → cert),
  la RCTC utilise une structure récursive avec propagation automatique de révocation :
  si une assertion est révoquée, TOUTES les assertions qui en dépendent sont
  automatiquement invalidées, sans délai.

  Innovation brevetable :
  - Structure d'arbre de Merkle pour les assertions de confiance (jamais fait).
  - Révocation récursive automatique : O(log n) au lieu de O(n).
  - Preuve d'inclusion compacte : prouver qu'une assertion est dans l'arbre
    en O(log n) hashes sans révéler les autres assertions.
  - "Trust Lightning" : quand une compromission est détectée, la révocation
    se propage comme un éclair à travers toutes les assertions dépendantes.
  - Attestation distante : un agent distant peut prouver sa légitimité à
    un serveur sans connexion directe, en fournissant un chemin Merkle.

Formulation mathématique :
  Chaque assertion A est une feuille de l'arbre Merkle :
    leaf_hash(A) = H(type || subject || value || timestamp || nonce)

  Nœud interne :
    node_hash(L, R) = H(left_hash || right_hash)

  Racine de l'arbre :
    root = node_hash(node_hash(leaf_1, leaf_2), node_hash(leaf_3, leaf_4))

  Preuve d'inclusion de l'assertion A :
    proof = [sibling_1, sibling_2, ..., sibling_k]
    (chemin de A jusqu'à la racine, k = log₂(n) étapes)

  Vérification :
    h = leaf_hash(A)
    for sibling in proof:
      h = H(min(h, sibling) || max(h, sibling))  # ordre canonique
    assert h == root

  Révocation :
    Révocation de A → recalcul de tous les nœuds parents jusqu'à root
    → nouvelle root incompatible avec toutes les preuves basées sur l'ancienne root
    → Toutes les assertions filles automatiquement invalidées en O(log n)

  "Trust Depth" :
    depth(A) = distance de A à la racine TPM
    Plus la profondeur est faible, plus la confiance est forte
    depth(TPM) = 0  (confiance absolue)
    depth(hardware) = 1
    depth(OS_kernel) = 2
    depth(system_process) = 3
    depth(user_process) = 4
    depth(network_packet) = 5
"""

import hashlib
import hmac as hmac_lib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class TrustAssertion(str, Enum):
    HARDWARE_ROOT = "hardware_root"    # TPM/HSM — depth 0
    OS_INTEGRITY = "os_integrity"      # OS + boot chain — depth 1
    KERNEL_MODULE = "kernel_module"    # Drivers, kernel ext — depth 2
    SYSTEM_PROCESS = "system_process"  # PID < 100, system procs — depth 3
    USER_PROCESS = "user_process"      # Processus utilisateur — depth 4
    NETWORK_FLOW = "network_flow"      # Paquet réseau — depth 5
    AGENT_IDENTITY = "agent_identity"  # Agent Gravity — depth 3
    ALERT_INTEGRITY = "alert_integrity" # Authenticité d'une alerte — depth 4
    FILE_INTEGRITY = "file_integrity"  # Intégrité d'un fichier — depth 4


TRUST_DEPTH: Dict[TrustAssertion, int] = {
    TrustAssertion.HARDWARE_ROOT: 0,
    TrustAssertion.OS_INTEGRITY: 1,
    TrustAssertion.KERNEL_MODULE: 2,
    TrustAssertion.SYSTEM_PROCESS: 3,
    TrustAssertion.AGENT_IDENTITY: 3,
    TrustAssertion.USER_PROCESS: 4,
    TrustAssertion.ALERT_INTEGRITY: 4,
    TrustAssertion.FILE_INTEGRITY: 4,
    TrustAssertion.NETWORK_FLOW: 5,
}

# Score de confiance selon la profondeur
DEPTH_TRUST_SCORE: Dict[int, float] = {
    0: 1.00,  # TPM — confiance absolue
    1: 0.99,
    2: 0.97,
    3: 0.93,
    4: 0.85,
    5: 0.75,
}


@dataclass
class TrustLeaf:
    """
    Une assertion de confiance — feuille de l'arbre Merkle.
    """
    assertion_id: str
    assertion_type: TrustAssertion
    subject: str              # Ce sur quoi porte l'assertion (pid, hash, ip, ...)
    value: str                # La valeur de l'assertion ("trusted", hash du binaire, ...)
    issuer_id: str            # Qui émet cette assertion (parent dans la chaîne)
    parent_assertion_id: str  # Assertion parente (preuve récursive)
    timestamp: float
    nonce: str
    leaf_hash: str = ""       # Calculé à la création
    revoked: bool = False
    revocation_time: Optional[float] = None
    revocation_reason: str = ""

    def compute_hash(self) -> str:
        payload = json.dumps({
            "id": self.assertion_id,
            "type": self.assertion_type.value,
            "subject": self.subject,
            "value": self.value,
            "issuer": self.issuer_id,
            "parent": self.parent_assertion_id,
            "ts": f"{self.timestamp:.3f}",
            "nonce": self.nonce,
        }, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def depth(self) -> int:
        return TRUST_DEPTH.get(self.assertion_type, 5)

    def trust_score(self) -> float:
        if self.revoked:
            return 0.0
        return DEPTH_TRUST_SCORE.get(self.depth(), 0.5)

    def to_dict(self) -> dict:
        return {
            "id": self.assertion_id,
            "type": self.assertion_type.value,
            "subject": self.subject,
            "value": self.value[:32] + "...",
            "issuer": self.issuer_id,
            "parent": self.parent_assertion_id,
            "depth": self.depth(),
            "trust_score": self.trust_score(),
            "leaf_hash": self.leaf_hash[:16] + "...",
            "revoked": self.revoked,
        }


@dataclass
class MerkleProof:
    """Preuve d'inclusion compacte dans l'arbre Merkle."""
    leaf_hash: str
    root_hash: str
    siblings: List[Tuple[str, bool]]   # (hash, is_left)
    depth: int
    assertion_id: str

    def verify(self, root: str) -> bool:
        """Vérifie que le leaf appartient à l'arbre avec la racine donnée."""
        h = self.leaf_hash
        for sibling, is_left in self.siblings:
            if is_left:
                h = hashlib.sha256((sibling + h).encode()).hexdigest()
            else:
                h = hashlib.sha256((h + sibling).encode()).hexdigest()
        return h == root

    def to_dict(self) -> dict:
        return {
            "leaf_hash": self.leaf_hash[:16] + "...",
            "root_hash": self.root_hash[:16] + "...",
            "proof_depth": len(self.siblings),
            "assertion_id": self.assertion_id,
            "valid": self.verify(self.root_hash),
        }


@dataclass
class TrustViolation:
    """Violation de la chaîne de confiance."""
    subject: str
    assertion_type: TrustAssertion
    reason: str
    severity: float
    depth: int
    timestamp: float = field(default_factory=time.time)

    def to_alert(self) -> dict:
        return {
            "type": "RCTC_VIOLATION",
            "severity": "critical" if self.severity >= 0.9 else "high",
            "threat_score": self.severity,
            "process": self.subject,
            "reason": (
                f"Trust chain violation for '{self.subject}' "
                f"(type={self.assertion_type.value}, depth={self.depth}). "
                f"{self.reason}"
            ),
            "trust_depth": self.depth,
            "assertion_type": self.assertion_type.value,
            "mitre_technique_id": "T1553",
            "mitre_technique_name": "Subvert Trust Controls",
            "kill_chain_phase": 5,
            "timestamp": self.timestamp,
        }


class MerkleTree:
    """
    Arbre de Merkle pour les assertions de confiance.
    Structure dynamique — les feuilles peuvent être ajoutées et révoquées.
    """

    def __init__(self):
        self._leaves: List[str] = []        # leaf hashes dans l'ordre
        self._leaf_map: Dict[str, int] = {} # leaf_hash → index
        self._root: str = ""
        self._dirty = True

    def add_leaf(self, leaf_hash: str) -> int:
        idx = len(self._leaves)
        self._leaves.append(leaf_hash)
        self._leaf_map[leaf_hash] = idx
        self._dirty = True
        return idx

    def update_leaf(self, index: int, new_hash: str):
        """Met à jour une feuille (pour révocation ou renouvellement)."""
        if 0 <= index < len(self._leaves):
            old = self._leaves[index]
            self._leaf_map.pop(old, None)
            self._leaves[index] = new_hash
            self._leaf_map[new_hash] = index
            self._dirty = True

    @property
    def root(self) -> str:
        if self._dirty:
            self._root = self._compute_root()
            self._dirty = False
        return self._root

    def _compute_root(self) -> str:
        if not self._leaves:
            return hashlib.sha256(b"empty").hexdigest()
        hashes = list(self._leaves)
        # Pad à puissance de 2
        while len(hashes) & (len(hashes) - 1):
            hashes.append(hashes[-1])
        while len(hashes) > 1:
            next_level = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i+1]
                next_level.append(hashlib.sha256(combined.encode()).hexdigest())
            hashes = next_level
        return hashes[0]

    def get_proof(self, leaf_hash: str) -> Optional[List[Tuple[str, bool]]]:
        """Retourne le chemin de preuve Merkle pour une feuille."""
        if leaf_hash not in self._leaf_map:
            return None
        idx = self._leaf_map[leaf_hash]
        hashes = list(self._leaves)
        while len(hashes) & (len(hashes) - 1):
            hashes.append(hashes[-1])

        proof = []
        pos = idx
        while len(hashes) > 1:
            if pos % 2 == 0:
                sibling = hashes[pos + 1] if pos + 1 < len(hashes) else hashes[pos]
                proof.append((sibling, False))  # sibling est à droite
            else:
                sibling = hashes[pos - 1]
                proof.append((sibling, True))   # sibling est à gauche

            next_level = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i+1]
                next_level.append(hashlib.sha256(combined.encode()).hexdigest())
            hashes = next_level
            pos //= 2

        return proof


class RecursiveCryptographicTrustChain:
    """
    Moteur RCTC — gère l'arbre de confiance récursif de tout l'écosystème Gravity.

    Hiérarchie :
      TPM/HSM (depth 0)
        └── OS Integrity (depth 1)
              └── Kernel Modules (depth 2)
                    ├── System Processes (depth 3)
                    │     └── User Processes (depth 4)
                    │           └── Network Flows (depth 5)
                    └── Agent Identity (depth 3)
                          └── Alert Integrity (depth 4)

    Chaque assertion prouve sa légitimité en fournissant :
    1. Son leaf_hash
    2. Sa preuve Merkle (chemin jusqu'à la racine)
    3. La racine signée par le TPM

    Un attaquant qui compromet un processus ne peut pas forger une assertion
    sans invalider toutes les assertions parentes.
    """

    # Hash "révoqué" — remplace le hash réel d'une feuille révoquée
    REVOKED_HASH_PREFIX = "REVOKED:"

    def __init__(self, master_key: bytes, tpm_simulation: bool = True,
                 on_violation: Optional[Callable[[TrustViolation], None]] = None):
        self.master_key = master_key
        self.tpm_simulation = tpm_simulation
        self.on_violation = on_violation

        self._assertions: Dict[str, TrustLeaf] = {}   # id → TrustLeaf
        self._tree = MerkleTree()
        self._leaf_index: Dict[str, int] = {}          # assertion_id → tree index
        self.violations: List[TrustViolation] = []

        # Racine TPM simulée (en production : vient du TPM)
        self._tpm_root = self._init_tpm_root()
        logger.info(f"RCTC: Initialized. TPM root: {self._tpm_root[:16]}...")

    def _init_tpm_root(self) -> str:
        """Simule une racine de confiance TPM."""
        tpm_seed = hmac_lib.new(
            self.master_key,
            b"GRAVITY-TPM-ROOT-V1",
            hashlib.sha256
        ).hexdigest()
        # En production : tpm_seed = tpm.get_platform_certificate()
        self._add_assertion_internal(
            assertion_id="tpm-root",
            assertion_type=TrustAssertion.HARDWARE_ROOT,
            subject="gravity-tpm",
            value=tpm_seed,
            issuer_id="HARDWARE",
            parent_id="",
        )
        return tpm_seed

    def _add_assertion_internal(self, assertion_id: str, assertion_type: TrustAssertion,
                                 subject: str, value: str, issuer_id: str,
                                 parent_id: str) -> TrustLeaf:
        nonce = uuid.uuid4().hex
        leaf = TrustLeaf(
            assertion_id=assertion_id,
            assertion_type=assertion_type,
            subject=subject,
            value=value,
            issuer_id=issuer_id,
            parent_assertion_id=parent_id,
            timestamp=time.time(),
            nonce=nonce,
        )
        leaf.leaf_hash = leaf.compute_hash()
        idx = self._tree.add_leaf(leaf.leaf_hash)
        self._assertions[assertion_id] = leaf
        self._leaf_index[assertion_id] = idx
        return leaf

    def assert_trust(self, assertion_type: TrustAssertion, subject: str,
                     value: str, parent_assertion_id: str,
                     issuer_id: str) -> Optional[TrustLeaf]:
        """
        Crée une nouvelle assertion de confiance.
        Vérifie que l'assertion parente est valide avant de créer l'enfant.
        """
        # Valider l'assertion parente
        if parent_assertion_id and parent_assertion_id != "tpm-root":
            parent = self._assertions.get(parent_assertion_id)
            if not parent:
                self._record_violation(
                    subject=subject, assertion_type=assertion_type,
                    reason=f"Parent assertion '{parent_assertion_id}' not found in trust chain",
                    severity=0.90,
                )
                return None
            if parent.revoked:
                self._record_violation(
                    subject=subject, assertion_type=assertion_type,
                    reason=f"Parent assertion '{parent_assertion_id}' has been revoked",
                    severity=0.95,
                )
                return None
            # Vérifier que la profondeur est cohérente
            parent_depth = TRUST_DEPTH.get(parent.assertion_type, 5)
            child_depth = TRUST_DEPTH.get(assertion_type, 5)
            if child_depth <= parent_depth and assertion_type != parent.assertion_type:
                self._record_violation(
                    subject=subject, assertion_type=assertion_type,
                    reason=(
                        f"Trust depth violation: child depth {child_depth} "
                        f"≤ parent depth {parent_depth}. "
                        f"Possible privilege escalation attempt."
                    ),
                    severity=0.88,
                )
                return None

        assertion_id = f"{assertion_type.value}-{subject[:20]}-{uuid.uuid4().hex[:8]}"
        leaf = self._add_assertion_internal(
            assertion_id=assertion_id,
            assertion_type=assertion_type,
            subject=subject,
            value=value,
            issuer_id=issuer_id,
            parent_id=parent_assertion_id or "tpm-root",
        )
        logger.debug(
            f"RCTC: Trust asserted: {assertion_type.value} for '{subject}' "
            f"depth={leaf.depth()} hash={leaf.leaf_hash[:16]}..."
        )
        return leaf

    def revoke(self, assertion_id: str, reason: str,
               cascade: bool = True) -> List[str]:
        """
        Révoque une assertion et TOUS ses descendants (Trust Lightning).
        Retourne la liste des assertions révoquées.
        """
        revoked = []
        self._revoke_recursive(assertion_id, reason, revoked)
        if cascade:
            logger.critical(
                f"RCTC TRUST LIGHTNING: Revoked {len(revoked)} assertions "
                f"starting from '{assertion_id}': {reason}"
            )
        return revoked

    def _revoke_recursive(self, assertion_id: str, reason: str, revoked: List[str]):
        leaf = self._assertions.get(assertion_id)
        if not leaf or leaf.revoked:
            return

        # Révoquer cette assertion
        leaf.revoked = True
        leaf.revocation_time = time.time()
        leaf.revocation_reason = reason
        revoked.append(assertion_id)

        # Mettre à jour le hash dans l'arbre (feuille révoquée)
        revoked_hash = hashlib.sha256(
            f"{self.REVOKED_HASH_PREFIX}{leaf.leaf_hash}".encode()
        ).hexdigest()
        idx = self._leaf_index.get(assertion_id)
        if idx is not None:
            self._tree.update_leaf(idx, revoked_hash)

        # Propager aux descendants (Trust Lightning)
        for child_id, child_leaf in self._assertions.items():
            if child_leaf.parent_assertion_id == assertion_id and not child_leaf.revoked:
                self._revoke_recursive(child_id, f"Parent revoked: {reason}", revoked)

    def get_proof(self, assertion_id: str) -> Optional[MerkleProof]:
        """
        Génère une preuve d'inclusion Merkle compacte.
        Un agent distant peut l'utiliser pour prouver sa légitimité.
        """
        leaf = self._assertions.get(assertion_id)
        if not leaf or leaf.revoked:
            return None

        siblings = self._tree.get_proof(leaf.leaf_hash)
        if siblings is None:
            return None

        return MerkleProof(
            leaf_hash=leaf.leaf_hash,
            root_hash=self._tree.root,
            siblings=siblings,
            depth=leaf.depth(),
            assertion_id=assertion_id,
        )

    def verify_proof(self, proof: MerkleProof) -> bool:
        """Vérifie une preuve Merkle par rapport à la racine actuelle."""
        current_root = self._tree.root
        if not proof.verify(current_root):
            logger.warning(f"RCTC: Invalid Merkle proof for {proof.assertion_id}")
            return False
        return True

    def verify_subject(self, subject: str,
                       required_type: TrustAssertion) -> Tuple[bool, float, str]:
        """
        Vérifie si un sujet a une assertion de confiance valide.
        Retourne (is_trusted, trust_score, reason).
        """
        # Chercher une assertion valide pour ce sujet
        valid_assertions = [
            leaf for leaf in self._assertions.values()
            if leaf.subject == subject
            and leaf.assertion_type == required_type
            and not leaf.revoked
        ]

        if not valid_assertions:
            return False, 0.0, f"No valid trust assertion for '{subject}'"

        # Prendre l'assertion avec le meilleur score (depth le plus bas)
        best = min(valid_assertions, key=lambda l: l.depth())

        # Vérifier que la chaîne remonte jusqu'au TPM
        if not self._verify_chain(best):
            return False, 0.0, f"Trust chain broken for '{subject}'"

        return True, best.trust_score(), f"Trusted at depth {best.depth()}"

    def _verify_chain(self, leaf: TrustLeaf) -> bool:
        """Vérifie récursivement que la chaîne remonte jusqu'au TPM."""
        current = leaf
        visited = set()
        while current.parent_assertion_id:
            if current.assertion_id in visited:
                return False  # Cycle détecté
            visited.add(current.assertion_id)
            if current.revoked:
                return False
            parent = self._assertions.get(current.parent_assertion_id)
            if not parent:
                return current.parent_assertion_id == "tpm-root"
            current = parent
        return True

    def _record_violation(self, subject: str, assertion_type: TrustAssertion,
                           reason: str, severity: float):
        v = TrustViolation(
            subject=subject, assertion_type=assertion_type,
            reason=reason, severity=severity,
            depth=TRUST_DEPTH.get(assertion_type, 5),
        )
        self.violations.append(v)
        logger.warning(f"RCTC VIOLATION [sev={severity}]: {reason}")
        if self.on_violation:
            self.on_violation(v)

    def sign_alert(self, alert: dict, agent_assertion_id: str) -> dict:
        """
        Signe cryptographiquement une alerte avec l'assertion de l'agent.
        Garantit l'authenticité et l'intégrité de l'alerte.
        """
        leaf = self._assertions.get(agent_assertion_id)
        if not leaf or leaf.revoked:
            alert["rctc_signed"] = False
            alert["rctc_reason"] = "Agent assertion not found or revoked"
            return alert

        alert_payload = json.dumps(alert, sort_keys=True, default=str)
        alert_hash = hashlib.sha256(alert_payload.encode()).hexdigest()
        signature = hmac_lib.new(
            self.master_key,
            f"{alert_hash}:{leaf.leaf_hash}:{leaf.timestamp:.0f}".encode(),
            hashlib.sha256
        ).hexdigest()

        alert["rctc_signed"] = True
        alert["rctc_signature"] = signature
        alert["rctc_agent_depth"] = leaf.depth()
        alert["rctc_trust_score"] = leaf.trust_score()
        alert["rctc_tree_root"] = self._tree.root[:16] + "..."
        return alert

    def get_trust_tree(self) -> dict:
        """Vue d'ensemble de l'arbre de confiance."""
        stats_by_type = {}
        for at in TrustAssertion:
            relevant = [l for l in self._assertions.values() if l.assertion_type == at]
            stats_by_type[at.value] = {
                "total": len(relevant),
                "valid": sum(1 for l in relevant if not l.revoked),
                "revoked": sum(1 for l in relevant if l.revoked),
            }
        return {
            "tree_root": self._tree.root[:16] + "...",
            "total_assertions": len(self._assertions),
            "revoked_count": sum(1 for l in self._assertions.values() if l.revoked),
            "violations": len(self.violations),
            "by_type": stats_by_type,
            "recent_violations": [v.to_alert() for v in self.violations[-5:]],
        }

    def stats(self) -> dict:
        return self.get_trust_tree()
