"""
Syscall Sequence Fingerprinting (SSF)
Models process syscall sequences as Markov chains.
Detects zero-day malware by statistical anomaly in syscall patterns.
"""
import collections
import hashlib
import json
import logging
import math
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Syscall categories for Windows ────────────────────────────────────────────
# Grouped into semantic families for the Markov model

SYSCALL_FAMILIES = {
    # Process & thread manipulation
    "PROC_CREATE":   ["CreateProcess", "NtCreateProcess", "CreateThread", "NtCreateThread"],
    "PROC_INJECT":   ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                      "NtCreateThreadEx", "RtlCreateUserThread"],
    "PROC_HOLLOW":   ["NtUnmapViewOfSection", "ZwMapViewOfSection", "NtResumeThread",
                      "NtSuspendThread"],
    # Memory operations
    "MEM_ALLOC":     ["VirtualAlloc", "VirtualAllocEx", "HeapAlloc", "NtAllocateVirtualMemory"],
    "MEM_PROTECT":   ["VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory"],
    "MEM_EXEC":      ["CreateFiber", "SwitchToFiber", "QueueUserAPC", "NtQueueApcThread"],
    # File I/O
    "FILE_READ":     ["ReadFile", "NtReadFile", "ZwReadFile"],
    "FILE_WRITE":    ["WriteFile", "NtWriteFile", "ZwWriteFile"],
    "FILE_DELETE":   ["DeleteFile", "NtDeleteFile", "ZwDeleteFile"],
    "FILE_RENAME":   ["MoveFile", "MoveFileEx", "SetFileInformationByHandle"],
    "FILE_ENUM":     ["FindFirstFile", "FindNextFile", "NtQueryDirectoryFile"],
    # Crypto (ransomware signature)
    "CRYPTO":        ["CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt",
                      "CryptGenKey", "BCryptGenerateSymmetricKey"],
    # Network
    "NET_CONNECT":   ["connect", "WSAConnect", "NtDeviceIoControlFile"],
    "NET_SEND":      ["send", "WSASend", "sendto"],
    "NET_RECV":      ["recv", "WSARecv", "recvfrom"],
    "NET_DNS":       ["DnsQuery", "getaddrinfo", "gethostbyname"],
    # Registry
    "REG_READ":      ["RegQueryValueEx", "NtQueryValueKey", "ZwQueryValueKey"],
    "REG_WRITE":     ["RegSetValueEx", "NtSetValueKey", "ZwSetValueKey"],
    "REG_CREATE":    ["RegCreateKeyEx", "NtCreateKey", "ZwCreateKey"],
    # Credential access
    "CRED_ACCESS":   ["LsaOpenPolicy", "SamConnect", "NetUserGetInfo",
                      "CredRead", "CryptUnprotectData", "LsaCallAuthenticationPackage"],
    # Hook / keylogger
    "HOOK":          ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
                      "SetWinEventHook", "RegisterHotKey"],
    # Persistence
    "PERSIST":       ["RegSetValueEx", "CreateService", "ChangeServiceConfig",
                      "SchTasks", "SchtasksCreate", "AddPrintProvidor"],
    # Defense evasion
    "EVASION":       ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                      "NtQueryInformationProcess", "RtlAdjustPrivilege",
                      "ObOpenObjectByName"],
}

# Reverse map: syscall_name → family
SYSCALL_TO_FAMILY: Dict[str, str] = {}
for family, calls in SYSCALL_FAMILIES.items():
    for call in calls:
        SYSCALL_TO_FAMILY[call.lower()] = family


@dataclass
class SyscallAnomaly:
    pid: int
    process_name: str
    sequence: List[str]
    surprisal: float          # -log2(P(sequence)) — higher = more anomalous
    anomalous_transition: str  # the specific transition that was unexpected
    suspected_behavior: str
    severity: float
    mitre_technique: str
    mitre_name: str
    timestamp: float = field(default_factory=time.time)

    def to_alert(self) -> dict:
        return {
            "type": "SYSCALL_ANOMALY",
            "severity": "critical" if self.severity >= 0.9 else "high",
            "threat_score": self.severity,
            "process": self.process_name,
            "pid": self.pid,
            "reason": (
                f"Anomalous syscall sequence in '{self.process_name}' "
                f"(surprisal={self.surprisal:.1f} bits). "
                f"Behavior: {self.suspected_behavior}. "
                f"Key transition: {self.anomalous_transition}"
            ),
            "syscall_sequence": self.sequence[-10:],
            "surprisal_bits": round(self.surprisal, 2),
            "mitre_technique_id": self.mitre_technique,
            "mitre_technique_name": self.mitre_name,
            "kill_chain_phase": 2,
            "timestamp": self.timestamp,
        }


class MarkovSyscallModel:
    """
    Order-3 Markov chain: P(syscall_t | syscall_{t-1}, syscall_{t-2}, syscall_{t-3})
    Uses Laplace smoothing to avoid zero probabilities.
    """

    ORDER = 3
    LAPLACE_ALPHA = 1e-6   # very small — we want rare sequences to be flagged

    def __init__(self):
        # trigram → {next_call → count}
        self._transitions: Dict[tuple, Dict[str, float]] = collections.defaultdict(
            lambda: collections.defaultdict(float)
        )
        self._totals: Dict[tuple, float] = collections.defaultdict(float)
        self._families: set = set(SYSCALL_FAMILIES.keys())
        self._trained = False

    def train(self, sequences: List[List[str]]):
        """Train on lists of syscall family sequences."""
        for seq in sequences:
            if len(seq) < self.ORDER + 1:
                continue
            for i in range(self.ORDER, len(seq)):
                trigram = tuple(seq[i - self.ORDER: i])
                next_call = seq[i]
                self._transitions[trigram][next_call] += 1
                self._totals[trigram] += 1
        self._trained = True
        logger.info(f"SSF Markov: trained on {len(sequences)} sequences, "
                    f"{len(self._transitions)} trigrams")

    def probability(self, trigram: tuple, next_call: str) -> float:
        """P(next_call | trigram) with Laplace smoothing."""
        total = self._totals.get(trigram, 0)
        count = self._transitions.get(trigram, {}).get(next_call, 0)
        vocab = len(self._families)
        # Laplace smoothing
        return (count + self.LAPLACE_ALPHA) / (total + self.LAPLACE_ALPHA * vocab)

    def surprisal(self, sequence: List[str]) -> Tuple[float, str]:
        """
        Compute total surprisal = -sum(log2(P(call_i | trigram_i))).
        Returns (surprisal_bits, most_anomalous_transition).
        """
        if len(sequence) <= self.ORDER:
            return 0.0, ""

        total_surprisal = 0.0
        max_step_surprisal = 0.0
        worst_transition = ""

        for i in range(self.ORDER, len(sequence)):
            trigram = tuple(sequence[i - self.ORDER: i])
            next_call = sequence[i]
            p = self.probability(trigram, next_call)
            step = -math.log2(p)
            total_surprisal += step
            if step > max_step_surprisal:
                max_step_surprisal = step
                worst_transition = f"{' → '.join(trigram)} → {next_call}"

        return total_surprisal, worst_transition

    def to_dict(self) -> dict:
        return {
            "transitions": {
                str(k): dict(v) for k, v in self._transitions.items()
            },
            "totals": {str(k): v for k, v in self._totals.items()},
        }

    @classmethod
    def from_dict(cls, d: dict) -> "MarkovSyscallModel":
        model = cls()
        for k_str, v in d.get("transitions", {}).items():
            k = tuple(k_str.strip("()").replace("'", "").split(", "))
            model._transitions[k] = collections.defaultdict(float, v)
        for k_str, v in d.get("totals", {}).items():
            k = tuple(k_str.strip("()").replace("'", "").split(", "))
            model._totals[k] = v
        model._trained = bool(model._transitions)
        return model


# ── Built-in malware behavior patterns ────────────────────────────────────────

# Known malicious sequences (families, not raw syscalls)
MALWARE_SIGNATURES = {
    "process_injection": {
        "sequence": ["MEM_ALLOC", "MEM_PROTECT", "PROC_INJECT", "PROC_INJECT"],
        "mitre": "T1055",
        "name": "Process Injection",
        "phase": 4,
        "severity": 0.95,
    },
    "process_hollowing": {
        "sequence": ["PROC_CREATE", "PROC_HOLLOW", "MEM_ALLOC", "FILE_WRITE"],
        "mitre": "T1055.012",
        "name": "Process Hollowing",
        "phase": 4,
        "severity": 0.97,
    },
    "ransomware_pattern": {
        "sequence": ["FILE_ENUM", "FILE_READ", "CRYPTO", "FILE_WRITE", "FILE_RENAME"],
        "mitre": "T1486",
        "name": "Data Encrypted for Impact",
        "phase": 8,
        "severity": 0.99,
    },
    "credential_access": {
        "sequence": ["PROC_INJECT", "CRED_ACCESS", "NET_SEND"],
        "mitre": "T1003",
        "name": "Credential Dumping",
        "phase": 4,
        "severity": 0.92,
    },
    "keylogger": {
        "sequence": ["HOOK", "HOOK", "FILE_WRITE"],
        "mitre": "T1056.001",
        "name": "Keylogging",
        "phase": 5,
        "severity": 0.88,
    },
    "c2_beacon": {
        "sequence": ["NET_DNS", "NET_CONNECT", "NET_SEND", "NET_RECV"],
        "mitre": "T1071",
        "name": "Application Layer Protocol C2",
        "phase": 6,
        "severity": 0.80,
    },
    "defense_evasion": {
        "sequence": ["EVASION", "EVASION", "MEM_PROTECT", "MEM_EXEC"],
        "mitre": "T1562",
        "name": "Impair Defenses",
        "phase": 5,
        "severity": 0.85,
    },
}


def normalize_to_family(syscall_name: str) -> str:
    return SYSCALL_TO_FAMILY.get(syscall_name.lower(), "OTHER")


def check_malware_signatures(sequence: List[str]) -> Optional[dict]:
    """Check if a syscall family sequence matches known malware patterns."""
    seq_str = " ".join(sequence)
    for _, sig in MALWARE_SIGNATURES.items():
        pattern = " ".join(sig["sequence"])
        if pattern in seq_str:
            return sig
    return None


class SyscallSequenceFingerprinter:
    """
    Per-process syscall sequence collector and anomaly detector.
    In production: hook ETW (Event Tracing for Windows) or use a kernel driver.
    In simulation: receives syscall events from a feed.
    """

    # Surprisal thresholds (bits)
    THRESHOLD_SUSPICIOUS = 30.0
    THRESHOLD_HIGH = 60.0
    THRESHOLD_CRITICAL = 100.0

    # Sliding window per process
    WINDOW_SIZE = 50

    def __init__(
        self,
        model: Optional[MarkovSyscallModel] = None,
        on_anomaly: Optional[Callable[[SyscallAnomaly], None]] = None,
        model_path: str = "data/syscall_model.json",
    ):
        self.model = model or self._build_default_model()
        self.on_anomaly = on_anomaly
        self.model_path = model_path
        self.anomalies: List[SyscallAnomaly] = []

        # pid → deque of family names (rolling window)
        self._process_windows: Dict[int, Deque[str]] = {}
        # pid → process name
        self._process_names: Dict[int, str] = {}

        self._load_model()

    def _build_default_model(self) -> MarkovSyscallModel:
        """Build a default model from known-good behavioral patterns."""
        model = MarkovSyscallModel()
        # Benign patterns: browser, office, file explorer, etc.
        benign_patterns = [
            ["FILE_READ", "FILE_READ", "FILE_WRITE", "FILE_READ", "NET_SEND"],
            ["REG_READ", "REG_READ", "FILE_READ", "FILE_WRITE"],
            ["NET_DNS", "NET_CONNECT", "NET_SEND", "NET_RECV", "NET_RECV"],
            ["MEM_ALLOC", "FILE_READ", "FILE_WRITE", "MEM_ALLOC"],
            ["PROC_CREATE", "FILE_READ", "REG_READ", "NET_DNS"],
            ["REG_READ", "FILE_ENUM", "FILE_READ", "FILE_WRITE", "FILE_READ"],
            ["NET_DNS", "NET_CONNECT", "NET_RECV", "FILE_WRITE"],
            ["MEM_ALLOC", "MEM_ALLOC", "FILE_READ", "FILE_READ", "FILE_WRITE"],
        ] * 50  # Repeat to build probabilities

        model.train(benign_patterns)
        return model

    def _load_model(self):
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path) as f:
                    self.model = MarkovSyscallModel.from_dict(json.load(f))
                logger.info("SSF: Loaded Markov model from disk")
            except Exception as e:
                logger.warning(f"SSF: Could not load model: {e} — using default")

    def save_model(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, "w") as f:
            json.dump(self.model.to_dict(), f)
        logger.info("SSF: Markov model saved")

    def record_syscall(self, pid: int, process_name: str, syscall_name: str):
        """
        Record a syscall event for a process.
        Call this from your ETW hook or simulation loop.
        """
        family = normalize_to_family(syscall_name)
        self._process_names[pid] = process_name

        if pid not in self._process_windows:
            self._process_windows[pid] = collections.deque(maxlen=self.WINDOW_SIZE)

        window = self._process_windows[pid]
        window.append(family)

        # Check for known malware signatures first (fast path)
        sequence = list(window)
        sig_match = check_malware_signatures(sequence)
        if sig_match:
            self._emit_anomaly(
                pid=pid, process_name=process_name,
                sequence=sequence,
                surprisal=200.0,  # Maximum — direct signature match
                worst_transition=f"Matched pattern: {' → '.join(sig_match['sequence'])}",
                behavior=sig_match["name"],
                severity=sig_match["severity"],
                mitre=sig_match["mitre"],
                mitre_name=sig_match["name"],
            )
            return

        # Markov model check (slower path, catches novel malware)
        if len(sequence) >= MarkovSyscallModel.ORDER + 1:
            surprisal, worst = self.model.surprisal(sequence)
            normalized_surprisal = surprisal / max(len(sequence), 1)

            if normalized_surprisal >= self.THRESHOLD_CRITICAL / 10:
                behavior = "Unknown malicious behavior (Markov anomaly)"
                mitre, mitre_name = "T1059", "Command and Scripting Interpreter"
                self._emit_anomaly(
                    pid=pid, process_name=process_name,
                    sequence=sequence, surprisal=surprisal,
                    worst_transition=worst, behavior=behavior,
                    severity=min(0.99, 0.6 + normalized_surprisal / 20),
                    mitre=mitre, mitre_name=mitre_name,
                )

    def _emit_anomaly(self, pid: int, process_name: str, sequence: List[str],
                      surprisal: float, worst_transition: str, behavior: str,
                      severity: float, mitre: str, mitre_name: str):
        # Deduplicate: same pid, same behavior within 30s
        now = time.time()
        recent = [a for a in self.anomalies[-10:]
                  if a.pid == pid and a.suspected_behavior == behavior
                  and (now - a.timestamp) < 30]
        if recent:
            return

        anomaly = SyscallAnomaly(
            pid=pid, process_name=process_name,
            sequence=sequence[-10:], surprisal=surprisal,
            anomalous_transition=worst_transition,
            suspected_behavior=behavior,
            severity=severity, mitre_technique=mitre, mitre_name=mitre_name,
        )
        self.anomalies.append(anomaly)
        logger.warning(
            f"SSF ANOMALY: PID={pid} '{process_name}' | {behavior} | "
            f"surprisal={surprisal:.1f} bits | {worst_transition}"
        )
        if self.on_anomaly:
            self.on_anomaly(anomaly)

    def simulate_attack(self, pid: int, process_name: str, attack_type: str):
        """Simulate a known attack for testing purposes."""
        sig = MALWARE_SIGNATURES.get(attack_type)
        if not sig:
            logger.warning(f"SSF: Unknown attack type {attack_type}")
            return
        for family in sig["sequence"]:
            # Use a representative syscall from the family
            representative = SYSCALL_FAMILIES.get(family, ["unknown"])[0]
            self.record_syscall(pid, process_name, representative)

    def stats(self) -> dict:
        return {
            "monitored_processes": len(self._process_windows),
            "total_anomalies": len(self.anomalies),
            "recent_anomalies": [a.to_alert() for a in self.anomalies[-5:]],
            "model_trigrams": len(self.model._transitions),
        }
