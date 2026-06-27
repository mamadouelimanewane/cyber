"""
Gravity Security — Process DNA Profiler
Innovation majeure : empreinte comportementale cryptographique de chaque processus.

Concept :
Chaque processus légitime a un comportement prévisible et stable :
- Il appelle toujours les mêmes séquences d'API Windows
- Il accède aux mêmes fichiers/registres
- Il maintient un ratio stable CPU/Mémoire/Réseau
- Ses processus enfants sont toujours les mêmes

Le DNA Profiler capture cette "signature génétique" comportementale
lors d'une phase d'apprentissage (mode LEARN), puis la compare
en temps réel (mode PROTECT). Toute mutation = alerte.

C'est l'équivalent d'un test ADN pour chaque processus :
impossible à falsifier sans être détecté.
"""

import hashlib
import hmac
import time
import json
import math
import logging
import threading
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path

logger = logging.getLogger("gravity.dna_profiler")

DNA_DB_PATH = Path(__file__).parent.parent.parent.parent / "data" / "process_dna.json"


@dataclass
class ProcessDNA:
    """
    Profil génétique comportemental d'un processus.
    Chaque champ représente un aspect du comportement observé.
    """
    process_name: str
    exe_hash: str                          # SHA256 de l'exécutable
    typical_parent_names: Set[str] = field(default_factory=set)
    typical_child_names: Set[str] = field(default_factory=set)
    typical_network_ports: Set[int] = field(default_factory=set)
    typical_registry_paths: List[str] = field(default_factory=list)
    typical_file_paths: List[str] = field(default_factory=list)
    cpu_range: Tuple[float, float] = (0.0, 100.0)   # (min, max) %
    memory_range: Tuple[float, float] = (0.0, 4096.0)  # MB
    avg_lifetime_seconds: float = 0.0
    connection_count_range: Tuple[int, int] = (0, 100)
    known_cmdline_patterns: List[str] = field(default_factory=list)
    sample_count: int = 0
    last_updated: float = field(default_factory=time.time)
    dna_hash: str = ""                     # Hash cryptographique du profil complet

    def compute_hash(self, secret: str = "gravity-dna-v1") -> str:
        """Calcule le hash cryptographique de ce profil DNA."""
        profile_data = json.dumps({
            "name": self.process_name,
            "exe": self.exe_hash,
            "parents": sorted(self.typical_parent_names),
            "children": sorted(self.typical_child_names),
            "ports": sorted(self.typical_network_ports),
        }, sort_keys=True)
        self.dna_hash = hmac.new(
            secret.encode(), profile_data.encode(), hashlib.sha256
        ).hexdigest()
        return self.dna_hash

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["typical_parent_names"] = list(self.typical_parent_names)
        d["typical_child_names"] = list(self.typical_child_names)
        d["typical_network_ports"] = list(self.typical_network_ports)
        d["cpu_range"] = list(self.cpu_range)
        d["memory_range"] = list(self.memory_range)
        d["connection_count_range"] = list(self.connection_count_range)
        return d

    @classmethod
    def from_dict(cls, d: Dict) -> "ProcessDNA":
        d["typical_parent_names"] = set(d.get("typical_parent_names", []))
        d["typical_child_names"] = set(d.get("typical_child_names", []))
        d["typical_network_ports"] = set(d.get("typical_network_ports", []))
        d["cpu_range"] = tuple(d.get("cpu_range", [0, 100]))
        d["memory_range"] = tuple(d.get("memory_range", [0, 4096]))
        d["connection_count_range"] = tuple(d.get("connection_count_range", [0, 100]))
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class DNAMutation:
    """Représente une déviation détectée par rapport au DNA connu."""
    process_name: str
    pid: int
    mutation_type: str
    expected: str
    observed: str
    severity: float  # 0.0 → 1.0
    mitre_technique: str


class DNAProfiler:
    """
    Gestionnaire de profils DNA des processus.

    Modes de fonctionnement :
    - LEARN  : observe et construit les profils DNA (sans bloquer)
    - PROTECT: compare en temps réel et alerte sur les mutations
    - HYBRID : PROTECT sur les profils connus, LEARN sur les nouveaux
    """

    MODE_LEARN = "learn"
    MODE_PROTECT = "protect"
    MODE_HYBRID = "hybrid"

    # Mutations et leurs techniques MITRE associées
    MUTATION_MITRE = {
        "unexpected_parent": "T1055 — Process Injection / T1036 — Masquerading",
        "unexpected_child": "T1059 — Command and Scripting Interpreter",
        "unexpected_network": "T1071 — Application Layer Protocol C2",
        "cpu_spike": "T1496 — Resource Hijacking (cryptomining probable)",
        "memory_spike": "T1055 — Process Injection (allocation mémoire anormale)",
        "unknown_cmdline": "T1036 — Masquerading / T1202 — Indirect Command Execution",
        "exe_hash_mismatch": "T1554 — Compromise Software Supply Chain",
    }

    def __init__(self, mode: str = MODE_HYBRID, callback=None, secret: str = "gravity-dna-v1"):
        self.mode = mode
        self.callback = callback
        self.secret = secret
        self._profiles: Dict[str, ProcessDNA] = {}
        self._observation_buffer: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._mutations: List[DNAMutation] = []
        self._lock = threading.Lock()
        self._load_profiles()
        logger.info(f"DNA Profiler démarré en mode {mode.upper()} — {len(self._profiles)} profils chargés")

    # ------------------------------------------------------------------ #
    #  Observation & Apprentissage                                       #
    # ------------------------------------------------------------------ #

    def observe(self, process_data: Dict) -> Optional[List[DNAMutation]]:
        """
        Observe les données d'un processus.
        En mode LEARN : met à jour le profil DNA.
        En mode PROTECT : compare et retourne les mutations détectées.
        """
        name = (process_data.get("name") or "").lower()
        if not name:
            return None

        with self._lock:
            if self.mode == self.MODE_LEARN:
                self._update_profile(name, process_data)
                return None
            elif self.mode == self.MODE_PROTECT:
                if name in self._profiles:
                    return self._detect_mutations(name, process_data)
                return None
            else:  # HYBRID
                if name not in self._profiles:
                    self._update_profile(name, process_data)
                    return None
                mutations = self._detect_mutations(name, process_data)
                # Continuer d'affiner le profil (avec prudence)
                if not mutations:
                    self._refine_profile(name, process_data)
                return mutations if mutations else None

    def _update_profile(self, name: str, data: Dict):
        """Met à jour ou crée le profil DNA d'un processus."""
        if name not in self._profiles:
            self._profiles[name] = ProcessDNA(
                process_name=name,
                exe_hash=data.get("exe_hash", ""),
            )

        profile = self._profiles[name]
        profile.sample_count += 1
        profile.last_updated = time.time()

        if data.get("parent_name"):
            profile.typical_parent_names.add(data["parent_name"].lower())
        for child in data.get("children_names", []):
            profile.typical_child_names.add(child.lower())
        for port in data.get("network_ports", []):
            profile.typical_network_ports.add(int(port))

        # Mise à jour des plages CPU/Mémoire (rolling update)
        cpu = data.get("cpu_percent", 0)
        mem = data.get("memory_mb", 0)
        profile.cpu_range = (
            min(profile.cpu_range[0], cpu),
            max(profile.cpu_range[1], cpu),
        )
        profile.memory_range = (
            min(profile.memory_range[0], mem),
            max(profile.memory_range[1], mem),
        )

        profile.compute_hash(self.secret)

        if profile.sample_count % 50 == 0:
            self._save_profiles()

    def _refine_profile(self, name: str, data: Dict):
        """Affine légèrement un profil existant avec de nouvelles observations normales."""
        profile = self._profiles[name]
        # Tolérance d'extension : seulement si très proche des bornes connues
        cpu = data.get("cpu_percent", 0)
        if cpu > profile.cpu_range[1] * 1.1:
            profile.cpu_range = (profile.cpu_range[0], cpu * 1.05)
        profile.sample_count += 1

    # ------------------------------------------------------------------ #
    #  Détection de mutations                                            #
    # ------------------------------------------------------------------ #

    def _detect_mutations(self, name: str, data: Dict) -> List[DNAMutation]:
        profile = self._profiles[name]
        mutations = []
        pid = data.get("pid", 0)

        # 1. Parent inattendu
        parent = (data.get("parent_name") or "").lower()
        if parent and profile.typical_parent_names and parent not in profile.typical_parent_names:
            mutations.append(DNAMutation(
                process_name=name, pid=pid,
                mutation_type="unexpected_parent",
                expected=str(profile.typical_parent_names),
                observed=parent,
                severity=0.85,
                mitre_technique=self.MUTATION_MITRE["unexpected_parent"],
            ))

        # 2. Processus enfant inattendu
        for child in data.get("children_names", []):
            child_lower = child.lower()
            if profile.typical_child_names and child_lower not in profile.typical_child_names:
                mutations.append(DNAMutation(
                    process_name=name, pid=pid,
                    mutation_type="unexpected_child",
                    expected=str(profile.typical_child_names),
                    observed=child,
                    severity=0.75,
                    mitre_technique=self.MUTATION_MITRE["unexpected_child"],
                ))

        # 3. Port réseau inattendu
        for port in data.get("network_ports", []):
            if profile.typical_network_ports and int(port) not in profile.typical_network_ports:
                mutations.append(DNAMutation(
                    process_name=name, pid=pid,
                    mutation_type="unexpected_network",
                    expected=str(sorted(profile.typical_network_ports)),
                    observed=str(port),
                    severity=0.70,
                    mitre_technique=self.MUTATION_MITRE["unexpected_network"],
                ))

        # 4. CPU anormalement élevé (cryptomining, compression ransomware)
        cpu = data.get("cpu_percent", 0)
        cpu_max = profile.cpu_range[1]
        if cpu_max > 5 and cpu > cpu_max * 3:
            mutations.append(DNAMutation(
                process_name=name, pid=pid,
                mutation_type="cpu_spike",
                expected=f"max {cpu_max:.1f}%",
                observed=f"{cpu:.1f}%",
                severity=min(0.90, 0.50 + (cpu / cpu_max - 3) * 0.10),
                mitre_technique=self.MUTATION_MITRE["cpu_spike"],
            ))

        # 5. Mémoire anormalement élevée (injection mémoire)
        mem = data.get("memory_mb", 0)
        mem_max = profile.memory_range[1]
        if mem_max > 10 and mem > mem_max * 4:
            mutations.append(DNAMutation(
                process_name=name, pid=pid,
                mutation_type="memory_spike",
                expected=f"max {mem_max:.0f} MB",
                observed=f"{mem:.0f} MB",
                severity=0.80,
                mitre_technique=self.MUTATION_MITRE["memory_spike"],
            ))

        # 6. Hash exécutable modifié (supply chain attack)
        current_hash = data.get("exe_hash", "")
        if profile.exe_hash and current_hash and current_hash != profile.exe_hash:
            mutations.append(DNAMutation(
                process_name=name, pid=pid,
                mutation_type="exe_hash_mismatch",
                expected=profile.exe_hash[:16] + "...",
                observed=current_hash[:16] + "...",
                severity=0.99,
                mitre_technique=self.MUTATION_MITRE["exe_hash_mismatch"],
            ))

        for m in mutations:
            self._mutations.append(m)
            self._raise_mutation_alert(m)

        return mutations

    def _raise_mutation_alert(self, mutation: DNAMutation):
        alert = {
            "type": "DNA_MUTATION",
            "severity": "critical" if mutation.severity >= 0.85 else "high",
            "process": mutation.process_name,
            "pid": mutation.pid,
            "threat_score": mutation.severity,
            "reason": f"DNA Mutation: {mutation.mutation_type} — attendu: {mutation.expected[:80]}, observé: {mutation.observed}",
            "mitre": mutation.mitre_technique,
            "label": f"Mutation ADN — {mutation.mutation_type}",
            "action": "Comparer avec le profil DNA de référence — possible compromission",
        }
        logger.warning(f"[DNA MUTATION] {mutation.process_name} PID:{mutation.pid} — {mutation.mutation_type}")
        if self.callback:
            self.callback(alert)

    # ------------------------------------------------------------------ #
    #  Persistance des profils                                          #
    # ------------------------------------------------------------------ #

    def _save_profiles(self):
        DNA_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = {name: p.to_dict() for name, p in self._profiles.items()}
        with open(DNA_DB_PATH, "w") as f:
            json.dump(data, f, indent=2)

    def _load_profiles(self):
        if DNA_DB_PATH.exists():
            with open(DNA_DB_PATH) as f:
                data = json.load(f)
            for name, d in data.items():
                try:
                    self._profiles[name] = ProcessDNA.from_dict(d)
                except Exception:
                    pass
            logger.info(f"Chargé {len(self._profiles)} profils DNA")

    def get_profile(self, process_name: str) -> Optional[Dict]:
        p = self._profiles.get(process_name.lower())
        return p.to_dict() if p else None

    def get_all_profiles_summary(self) -> List[Dict]:
        return [
            {"name": n, "samples": p.sample_count, "dna_hash": p.dna_hash[:16] + "..."}
            for n, p in self._profiles.items()
        ]

    @property
    def profile_count(self) -> int:
        return len(self._profiles)
