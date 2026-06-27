"""
BREVET 2 — Cryptographic Behavioral Genome Alignment (CBGA)
============================================================

Concept fondamental :
  Chaque processus possède un "génome comportemental" — une séquence ordonnée
  d'actes système (syscalls, accès fichiers, connexions réseau).
  Comme en bioinformatique, deux génomes peuvent être ALIGNÉS pour mesurer
  leur similitude. Un alignement parfait avec un génome malveillant connu =
  détection. Un alignement partiel = score de parenté avec la menace.

  Innovation brevetable :
  - Application de l'algorithme Smith-Waterman (alignement local de séquences)
    au domaine de la cybersécurité comportementale.
  - Matrice de substitution BLOSUM-SECURITY : coûts de substitution entre
    actes système calculés par leur proximité sémantique en termes de risque.
  - Génome cryptographiquement signé : impossible de falsifier le génome d'un
    processus légitime sans invalider la signature.
  - "Phylogénie des malwares" : construction d'un arbre évolutif des variants
    de malware basé sur la distance de leurs génomes.

Formulation mathématique :
  Génome G = [g_1, g_2, ..., g_n] où g_i ∈ Σ (alphabet des actes système)

  Score d'alignement Smith-Waterman :
    H(i, j) = max(
      0,
      H(i-1, j-1) + score(g_i, g_j),  ← match/mismatch
      H(i-1, j)   - gap_open,          ← gap dans G1
      H(i, j-1)   - gap_open,          ← gap dans G2
    )

  score(a, b) = BLOSUM_SECURITY[a][b]  (matrice de substitution)

  Distance génomique :
    d(G1, G2) = 1 - (2 * SW(G1, G2)) / (SW(G1, G1) + SW(G2, G2))

  Génome cryptographique :
    hash_genome = HMAC-SHA256(master_key, '|'.join(G))
    La chaîne de hachage rend la falsification détectable.
"""

import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Alphabet des actes système ─────────────────────────────────────────────────
# Chaque lettre représente une catégorie d'acte système

GENOME_ALPHABET = {
    "F": "file_read",
    "W": "file_write",
    "D": "file_delete",
    "R": "file_rename",
    "E": "file_enumerate",
    "N": "net_connect",
    "S": "net_send",
    "V": "net_receive",
    "P": "process_create",
    "I": "process_inject",
    "M": "memory_alloc_exec",
    "C": "crypto_encrypt",
    "K": "credential_access",
    "G": "registry_write",
    "H": "hook_install",
    "L": "lateral_move",
    "X": "execute_suspicious",
    "O": "normal_operation",
}

# Reverse map
ACT_TO_GENE: Dict[str, str] = {v: k for k, v in GENOME_ALPHABET.items()}

# ── Matrice de substitution BLOSUM-SECURITY ────────────────────────────────────
# Inspirée de BLOSUM62 (bioinformatique) mais pour les actes système.
# Score positif = actes similaires (même famille de risque)
# Score négatif = actes très différents
# Diagonal = match parfait (score le plus élevé)

_GENES = list(GENOME_ALPHABET.keys())

# Score de base : match = +5, mismatch = -2 par défaut
BLOSUM_SECURITY: Dict[str, Dict[str, int]] = {g: {g2: -2 for g2 in _GENES} for g in _GENES}

# Ajustements sémantiques
def _set_score(a: str, b: str, score: int):
    BLOSUM_SECURITY[a][b] = score
    BLOSUM_SECURITY[b][a] = score

# Match parfait
for g in _GENES:
    BLOSUM_SECURITY[g][g] = 5

# Famille des écritures destructrices (W, D, R, C) — similaires entre elles
_set_score("W", "D", 3)
_set_score("W", "R", 3)
_set_score("W", "C", 2)
_set_score("D", "R", 4)
_set_score("D", "C", 2)
_set_score("C", "R", 3)

# Famille des accès credential / injection
_set_score("K", "I", 3)
_set_score("K", "M", 2)
_set_score("I", "M", 4)
_set_score("I", "P", 2)

# Famille réseau (N, S, V, L)
_set_score("N", "S", 4)
_set_score("N", "V", 3)
_set_score("N", "L", 2)
_set_score("S", "V", 3)
_set_score("S", "L", 2)

# Famille suspecte (H, X, G, I)
_set_score("H", "X", 3)
_set_score("H", "G", 2)
_set_score("X", "G", 2)
_set_score("X", "I", 3)

# Normal vs suspect : pénalité forte
for safe in ["F", "O"]:
    for dangerous in ["I", "M", "C", "K", "H", "X", "L"]:
        _set_score(safe, dangerous, -4)


# ── Génomes de référence malware ───────────────────────────────────────────────
# Séquences typiques observées dans des malwares réels

MALWARE_GENOMES: Dict[str, Dict] = {
    "Ransomware_LockBit": {
        "genome": "EFWCRWCRWCRWCRWCRWCR",  # Enum → Read → Encrypt → Rename (en boucle)
        "mitre": "T1486",
        "phase": 8,
        "severity": 0.99,
        "description": "LockBit-style mass encryption pattern",
    },
    "Mimikatz_Credential_Dump": {
        "genome": "PIMKI KS",  # Process inject → Memory → Cred access → Send
        "mitre": "T1003",
        "phase": 4,
        "severity": 0.97,
        "description": "Credential dumping via process injection",
    },
    "Cobalt_Strike_Beacon": {
        "genome": "PMNSVNS",  # Process → Memory → Net → Send/Recv loop
        "mitre": "T1071",
        "phase": 6,
        "severity": 0.92,
        "description": "Cobalt Strike beacon C2 communication pattern",
    },
    "Keylogger_Generic": {
        "genome": "HHHHWSN",  # Hook install (×4) → Write → Send → Net
        "mitre": "T1056.001",
        "phase": 5,
        "severity": 0.88,
        "description": "Keylogger hook installation and data exfiltration",
    },
    "APT_Lateral_Move": {
        "genome": "NLIPKLSV",  # Net → Lateral → Inject → Process → Cred → Send
        "mitre": "T1021",
        "phase": 6,
        "severity": 0.95,
        "description": "APT lateral movement with credential reuse",
    },
    "Supply_Chain_Backdoor": {
        "genome": "OFOFGNMXS",  # Normal → file → reg write → mem exec → send
        "mitre": "T1195",
        "phase": 1,
        "severity": 0.96,
        "description": "Supply chain compromise with dormant backdoor",
    },
    "Rootkit_Persistence": {
        "genome": "IMGXGXP",  # Inject → Mem → Guard hook → Reg × 2 → Process create
        "mitre": "T1547",
        "phase": 3,
        "severity": 0.94,
        "description": "Rootkit-style registry persistence with guard hooks",
    },
}


def smith_waterman(seq1: str, seq2: str,
                   gap_open: int = -4, gap_extend: int = -1) -> Tuple[int, int, int]:
    """
    Algorithme de Smith-Waterman pour alignement local optimal.
    Retourne (score_max, position_i, position_j).

    Complexité : O(n×m) — n, m longueurs des séquences.
    """
    n, m = len(seq1), len(seq2)
    # Matrice H[i][j] = score optimal de l'alignement se terminant en (i, j)
    H = [[0] * (m + 1) for _ in range(n + 1)]
    max_score = 0
    max_i, max_j = 0, 0

    for i in range(1, n + 1):
        for j in range(1, m + 1):
            g1 = seq1[i - 1].upper()
            g2 = seq2[j - 1].upper()
            match = BLOSUM_SECURITY.get(g1, {}).get(g2, -2) if g1 in BLOSUM_SECURITY else -2
            diag = H[i-1][j-1] + match
            up   = H[i-1][j] + gap_open
            left = H[i][j-1] + gap_open
            H[i][j] = max(0, diag, up, left)
            if H[i][j] > max_score:
                max_score = H[i][j]
                max_i, max_j = i, j

    return max_score, max_i, max_j


def genome_distance(g1: str, g2: str) -> float:
    """
    Distance génomique normalisée entre deux génomes comportementaux.
    0.0 = identiques, 1.0 = complètement différents.
    """
    sw_12, _, _ = smith_waterman(g1, g2)
    sw_11, _, _ = smith_waterman(g1, g1)
    sw_22, _, _ = smith_waterman(g2, g2)
    denom = sw_11 + sw_22
    if denom == 0:
        return 1.0
    similarity = (2 * sw_12) / denom
    return max(0.0, 1.0 - similarity)


@dataclass
class GenomeMatch:
    """Résultat d'un alignement contre un génome malware de référence."""
    malware_name: str
    similarity: float          # 0.0 → 1.0 (1.0 = identique)
    sw_score: int
    alignment_position: Tuple[int, int]
    mitre: str
    phase: int
    severity: float
    description: str

    def to_dict(self) -> dict:
        return {
            "malware_name": self.malware_name,
            "similarity": round(self.similarity, 4),
            "sw_score": self.sw_score,
            "alignment_position": self.alignment_position,
            "mitre": self.mitre,
            "severity": self.severity,
        }


@dataclass
class ProcessGenome:
    """Génome comportemental cryptographique d'un processus."""
    pid: int
    process_name: str
    sequence: str = ""              # Séquence de gènes (lettres de l'alphabet)
    signed_hash: str = ""           # HMAC de la séquence — preuve de non-falsification
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    total_acts: int = 0

    def add_act(self, act_type: str):
        gene = ACT_TO_GENE.get(act_type, "O")
        self.sequence += gene
        self.total_acts += 1
        self.last_updated = time.time()
        # Garder uniquement les 200 derniers gènes (fenêtre glissante)
        if len(self.sequence) > 200:
            self.sequence = self.sequence[-200:]

    def sign(self, master_key: bytes) -> str:
        msg = f"{self.pid}:{self.process_name}:{self.sequence}"
        self.signed_hash = hmac.new(master_key, msg.encode(), hashlib.sha256).hexdigest()
        return self.signed_hash

    def verify(self, master_key: bytes) -> bool:
        msg = f"{self.pid}:{self.process_name}:{self.sequence}"
        expected = hmac.new(master_key, msg.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signed_hash)

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "genome_length": len(self.sequence),
            "genome_preview": self.sequence[-30:],
            "signed_hash": self.signed_hash[:16] + "...",
            "total_acts": self.total_acts,
        }


@dataclass
class GenomeAlert:
    pid: int
    process_name: str
    best_match: GenomeMatch
    genome_snapshot: str
    timestamp: float = field(default_factory=time.time)

    def to_alert(self) -> dict:
        return {
            "type": "GENOME_MATCH",
            "severity": "critical" if self.best_match.severity >= 0.9 else "high",
            "threat_score": self.best_match.similarity * self.best_match.severity,
            "process": self.process_name,
            "pid": self.pid,
            "reason": (
                f"Behavioral genome of '{self.process_name}' matches "
                f"'{self.best_match.malware_name}' "
                f"(similarity={self.best_match.similarity:.1%}, "
                f"SW_score={self.best_match.sw_score}). "
                f"{self.best_match.description}"
            ),
            "malware_match": self.best_match.to_dict(),
            "genome_snapshot": self.genome_snapshot[-30:],
            "mitre_technique_id": self.best_match.mitre,
            "kill_chain_phase": self.best_match.phase,
            "timestamp": self.timestamp,
        }


class CryptographicBehavioralGenomeAlignment:
    """
    Moteur CBGA — aligne les génomes comportementaux des processus contre
    une base de génomes malware de référence.

    Workflow :
    1. Chaque processus accumule son génome en temps réel (actes → gènes)
    2. Toutes les N observations, alignement contre tous les génomes de référence
    3. Si similarité > seuil → alerte avec identification du malware
    4. Le génome est cryptographiquement signé → falsification impossible
    5. Phylogénie : construction de l'arbre évolutif des variants détectés
    """

    SIMILARITY_THRESHOLD_HIGH = 0.65      # > 65% = alerte HIGH
    SIMILARITY_THRESHOLD_CRITICAL = 0.85  # > 85% = alerte CRITICAL
    SCAN_EVERY_N_ACTS = 10                # Aligner tous les 10 actes

    def __init__(
        self,
        master_key: bytes,
        on_alert: Optional[Callable[[GenomeAlert], None]] = None,
        reference_genomes: Optional[Dict[str, Dict]] = None,
    ):
        self.master_key = master_key
        self.on_alert = on_alert
        self.reference_genomes = reference_genomes or MALWARE_GENOMES

        self._genomes: Dict[int, ProcessGenome] = {}
        self.alerts: List[GenomeAlert] = []
        # Phylogénie : malware_name → liste de génomes suspects alignés
        self._phylogeny: Dict[str, List[str]] = {}

    def _get_or_create(self, pid: int, name: str) -> ProcessGenome:
        if pid not in self._genomes:
            self._genomes[pid] = ProcessGenome(pid=pid, process_name=name)
        return self._genomes[pid]

    def record_act(self, pid: int, process_name: str, act_type: str):
        """Enregistre un acte système et met à jour le génome du processus."""
        genome = self._get_or_create(pid, process_name)
        genome.add_act(act_type)
        genome.sign(self.master_key)

        # Aligner périodiquement
        if genome.total_acts % self.SCAN_EVERY_N_ACTS == 0:
            self._align_against_references(genome)

    def _align_against_references(self, genome: ProcessGenome):
        """Aligne le génome du processus contre tous les génomes de référence."""
        if len(genome.sequence) < 5:
            return

        best_match: Optional[GenomeMatch] = None
        best_sim = 0.0

        for malware_name, ref_data in self.reference_genomes.items():
            ref_genome = ref_data["genome"].replace(" ", "")
            sw_score, pos_i, pos_j = smith_waterman(genome.sequence, ref_genome)

            # Normaliser par rapport au score auto-alignement de la référence
            ref_self_score, _, _ = smith_waterman(ref_genome, ref_genome)
            if ref_self_score == 0:
                continue

            similarity = sw_score / ref_self_score

            if similarity > best_sim:
                best_sim = similarity
                best_match = GenomeMatch(
                    malware_name=malware_name,
                    similarity=similarity,
                    sw_score=sw_score,
                    alignment_position=(pos_i, pos_j),
                    mitre=ref_data["mitre"],
                    phase=ref_data["phase"],
                    severity=ref_data["severity"],
                    description=ref_data["description"],
                )

        if best_match and best_sim >= self.SIMILARITY_THRESHOLD_HIGH:
            self._emit_alert(genome, best_match)
            self._update_phylogeny(best_match.malware_name, genome.sequence)

    def _emit_alert(self, genome: ProcessGenome, match: GenomeMatch):
        # Déduplier : même PID + même malware dans les 60s
        now = time.time()
        recent = [a for a in self.alerts[-20:]
                  if a.pid == genome.pid
                  and a.best_match.malware_name == match.malware_name
                  and (now - a.timestamp) < 60]
        if recent:
            return

        alert = GenomeAlert(
            pid=genome.pid,
            process_name=genome.process_name,
            best_match=match,
            genome_snapshot=genome.sequence,
        )
        self.alerts.append(alert)
        logger.warning(
            f"CBGA ALERT: PID={genome.pid} '{genome.process_name}' "
            f"→ '{match.malware_name}' sim={match.similarity:.1%} "
            f"SW={match.sw_score}"
        )
        if self.on_alert:
            self.on_alert(alert)

    def _update_phylogeny(self, malware_name: str, genome_seq: str):
        """Maintient l'arbre phylogénétique des variants détectés."""
        if malware_name not in self._phylogeny:
            self._phylogeny[malware_name] = []
        self._phylogeny[malware_name].append(genome_seq[-20:])

    def get_phylogeny(self) -> dict:
        """Retourne l'arbre évolutif des malwares détectés."""
        result = {}
        for malware, genomes in self._phylogeny.items():
            if len(genomes) < 2:
                result[malware] = {"variants": len(genomes), "distances": []}
                continue
            # Calculer les distances entre variants
            distances = []
            for i in range(len(genomes) - 1):
                d = genome_distance(genomes[i], genomes[i+1])
                distances.append(round(d, 3))
            result[malware] = {
                "variants": len(genomes),
                "avg_mutation_distance": round(sum(distances) / len(distances), 3) if distances else 0,
                "distances": distances,
            }
        return result

    def scan_process(self, pid: int, process_name: str,
                     genome_sequence: str) -> Optional[GenomeAlert]:
        """Scan direct d'une séquence génomique arbitraire."""
        temp_genome = ProcessGenome(pid=pid, process_name=process_name,
                                    sequence=genome_sequence)
        temp_genome.sign(self.master_key)
        self._align_against_references(temp_genome)
        relevant = [a for a in self.alerts if a.pid == pid]
        return relevant[-1] if relevant else None

    def stats(self) -> dict:
        return {
            "tracked_processes": len(self._genomes),
            "reference_genomes": len(self.reference_genomes),
            "total_alerts": len(self.alerts),
            "phylogeny": self.get_phylogeny(),
        }
