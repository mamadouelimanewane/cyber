"""
Gravity Security — Memory Guardian
Détecte les malwares fileless qui vivent uniquement en mémoire RAM.

40% des cyberattaques modernes n'écrivent JAMAIS sur le disque.
Les antivirus traditionnels sont aveugles face à ces menaces.

Ce module scanne les régions mémoire des processus en cours d'exécution
pour détecter : shellcodes, ROP chains, injections de DLL réfléchissantes,
et autres techniques d'exécution en mémoire.
"""

import ctypes
import struct
import logging
import threading
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger("gravity.memory_guardian")

# Patterns de shellcodes connus (encodés en hex)
# Ces séquences d'octets correspondent à des prologs de shellcodes communs
SHELLCODE_PATTERNS = [
    # x64 common shellcode prolog
    (b"\xfc\x48\x83\xe4\xf0\xe8", "x64 shellcode prolog (align+call)"),
    (b"\xfc\xe8\x89\x00\x00\x00", "x86 Metasploit shellcode prolog"),
    (b"\xfc\xe8\x82\x00\x00\x00", "x86 Meterpreter reverse_tcp prolog"),
    # NOP sleds
    (b"\x90" * 16, "NOP sled (16+ octets)"),
    # INT3 breakpoint chains (debugging/exploitation)
    (b"\xcc" * 8, "INT3 breakpoint chain"),
    # Common ROP gadget sequences
    (b"\x58\x5a\x59\x5b", "POP RAX/RDX/RCX/RBX sequence — ROP chain probable"),
    # Heaven's Gate (32→64 bit transition)
    (b"\xea\x00\x00\x00\x00\x33\x00", "Heaven's Gate — WoW64 transition exploit"),
    # Process hollowing markers
    (b"\x4d\x5a\x90\x00\x03\x00\x00\x00", "PE header in memory — DLL injection probable"),
    # Reflective DLL injection
    (b"\x55\x8b\xec\x83\xec\x10\x56\x57", "Reflective DLL injection stub"),
]

# Drapeaux de protection mémoire Windows suspects
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

SUSPICIOUS_PROTECTIONS = {
    PAGE_EXECUTE_READWRITE: "RWX — lecture+écriture+exécution simultanées (injection classique)",
    PAGE_EXECUTE_WRITECOPY: "RWXC — copie sur écriture exécutable",
}


@dataclass
class MemoryThreat:
    pid: int
    process_name: str
    region_base: int
    region_size: int
    protection: int
    pattern_found: str
    threat_score: float
    technique: str


class MemoryGuardian:
    """
    Surveillant mémoire — analyse les espaces mémoire des processus
    pour détecter les techniques d'exécution en mémoire sans fichier.

    Fonctionne en mode read-only : ne modifie rien, observe seulement.
    La réponse (suspension/kill du processus) est déléguée à l'agent principal.
    """

    # Processus système à ne jamais scanner (risque BSOD)
    PROTECTED_PROCESSES = {
        "system", "smss.exe", "csrss.exe", "wininit.exe",
        "winlogon.exe", "services.exe", "lsass.exe",
    }

    def __init__(self, callback=None):
        self.callback = callback
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._scanned_pids = set()
        self._threats: List[MemoryThreat] = []

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._thread.start()
        logger.info("Memory Guardian démarré")

    def stop(self):
        self._running = False

    def _scan_loop(self):
        while self._running:
            try:
                self._scan_all_processes()
            except Exception as e:
                logger.debug(f"Scan mémoire: {e}")
            time.sleep(10)

    def _scan_all_processes(self):
        try:
            import psutil
        except ImportError:
            return

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                name = (proc.info["name"] or "").lower()
                if name in self.PROTECTED_PROCESSES or pid <= 4:
                    continue
                threats = self.scan_process(pid, name)
                for threat in threats:
                    self._threats.append(threat)
                    self._raise_alert(threat)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def scan_process(self, pid: int, process_name: str) -> List[MemoryThreat]:
        """Scanne les régions mémoire d'un processus donné."""
        threats = []
        try:
            import ctypes
            import ctypes.wintypes as wt

            PROCESS_VM_READ = 0x0010
            PROCESS_QUERY_INFORMATION = 0x0400

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
            )
            if not handle:
                return []

            try:
                threats.extend(self._enumerate_memory_regions(handle, pid, process_name))
            finally:
                kernel32.CloseHandle(handle)
        except Exception as e:
            logger.debug(f"Impossible de scanner PID {pid}: {e}")
        return threats

    def _enumerate_memory_regions(self, handle, pid: int, process_name: str) -> List[MemoryThreat]:
        """Énumère et analyse les régions mémoire via VirtualQueryEx."""
        threats = []
        try:
            import ctypes
            import ctypes.wintypes as wt

            kernel32 = ctypes.windll.kernel32

            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wt.DWORD),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wt.DWORD),
                    ("Protect", wt.DWORD),
                    ("Type", wt.DWORD),
                ]

            MEM_COMMIT = 0x1000
            mbi = MEMORY_BASIC_INFORMATION()
            address = 0
            mbi_size = ctypes.sizeof(MEMORY_BASIC_INFORMATION)

            while True:
                result = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size)
                if not result:
                    break

                if mbi.State == MEM_COMMIT and mbi.RegionSize > 0:
                    threat = self._analyze_region(handle, pid, process_name, mbi)
                    if threat:
                        threats.append(threat)

                address += mbi.RegionSize
                if address >= 0x7FFFFFFFFFFF:  # Limite espace utilisateur 64-bit
                    break
        except Exception:
            pass
        return threats

    def _analyze_region(self, handle, pid: int, process_name: str, mbi) -> Optional[MemoryThreat]:
        """Analyse une région mémoire spécifique."""
        protection = mbi.Protect
        score = 0.0
        technique = ""

        # 1. Vérification des protections suspectes
        if protection in SUSPICIOUS_PROTECTIONS:
            score += 0.50
            technique = SUSPICIOUS_PROTECTIONS[protection]

        # 2. Lecture et scan du contenu si exécutable
        if protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY):
            content, success = self._read_memory(handle, mbi.BaseAddress, min(mbi.RegionSize, 4096))
            if success and content:
                pattern_found, pattern_score = self._scan_shellcode_patterns(content)
                if pattern_score > 0:
                    score = min(1.0, score + pattern_score)
                    technique = pattern_found

        if score >= 0.50:
            return MemoryThreat(
                pid=pid,
                process_name=process_name,
                region_base=mbi.BaseAddress or 0,
                region_size=mbi.RegionSize,
                protection=protection,
                pattern_found=technique,
                threat_score=round(score, 3),
                technique=self._classify_technique(technique),
            )
        return None

    def _read_memory(self, handle, address, size: int) -> Tuple[bytes, bool]:
        """Lit la mémoire d'un processus distant."""
        try:
            import ctypes
            buf = (ctypes.c_char * size)()
            bytes_read = ctypes.c_size_t(0)
            success = ctypes.windll.kernel32.ReadProcessMemory(
                handle, ctypes.c_void_p(address), buf, size, ctypes.byref(bytes_read)
            )
            if success:
                return bytes(buf[:bytes_read.value]), True
        except Exception:
            pass
        return b"", False

    def _scan_shellcode_patterns(self, data: bytes) -> Tuple[str, float]:
        """Recherche des patterns de shellcodes dans les données."""
        for pattern, description in SHELLCODE_PATTERNS:
            if pattern in data:
                score = 0.70 if b"\x90" * 16 == pattern else 0.85
                return description, score
        return "", 0.0

    def _classify_technique(self, technique_desc: str) -> str:
        """Mappe la technique sur MITRE ATT&CK."""
        mapping = {
            "shellcode": "T1055 — Process Injection",
            "Meterpreter": "T1059.001 — PowerShell / Meterpreter",
            "ROP": "T1574 — Hijack Execution Flow (ROP Chain)",
            "NOP": "T1055 — Process Injection (NOP Sled)",
            "Heaven": "T1055.011 — Extra Window Memory Injection",
            "PE header": "T1055.001 — DLL Injection",
            "Reflective": "T1055.001 — Reflective DLL Injection",
            "RWX": "T1055 — Process Injection (RWX Memory)",
            "INT3": "T1055 — Process Injection (Anti-debug)",
        }
        for keyword, mitre in mapping.items():
            if keyword.lower() in technique_desc.lower():
                return mitre
        return "T1055 — Process Injection (générique)"

    def _raise_alert(self, threat: MemoryThreat):
        alert = {
            "type": "MEMORY_THREAT",
            "severity": "critical" if threat.threat_score >= 0.8 else "high",
            "pid": threat.pid,
            "process": threat.process_name,
            "threat_score": threat.threat_score,
            "reason": threat.pattern_found,
            "mitre": threat.technique,
            "region_base": hex(threat.region_base),
            "region_size": threat.region_size,
        }
        logger.warning(
            f"[MÉMOIRE] {threat.process_name} PID:{threat.pid} — "
            f"{threat.pattern_found} @ {hex(threat.region_base)} "
            f"(score={threat.threat_score:.2f})"
        )
        if self.callback:
            self.callback(alert)

    def get_threats(self) -> List[Dict]:
        return [
            {
                "pid": t.pid, "process": t.process_name,
                "score": t.threat_score, "technique": t.technique,
                "reason": t.pattern_found,
            }
            for t in self._threats
        ]


# ------------------------------------------------------------------ #
#  Analyse statique de shellcode (sans OS Windows)                  #
# ------------------------------------------------------------------ #

def analyze_shellcode_bytes(data: bytes) -> Dict:
    """
    Analyse statique d'un buffer pour identifier du shellcode.
    Utilisable sur toute plateforme (sans accès mémoire Windows).
    """
    results = {"is_shellcode": False, "confidence": 0.0, "patterns": [], "stats": {}}

    # Statistiques de base
    if not data:
        return results

    import math
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = -sum((f/n) * math.log2(f/n) for f in freq if f > 0)

    null_bytes = freq[0] / n
    exec_ratio = sum(1 for b in data if 0x50 <= b <= 0x5F or 0x48 <= b <= 0x4F) / n

    results["stats"] = {
        "entropy": round(entropy, 3),
        "size": n,
        "null_byte_ratio": round(null_bytes, 3),
        "register_op_ratio": round(exec_ratio, 3),
    }

    score = 0.0
    patterns_found = []

    # Entropie élevée → code packed/chiffré
    if entropy > 6.5:
        score += 0.25
        patterns_found.append(f"Entropie élevée ({entropy:.2f})")

    # Peu de null bytes → shellcode (pas de PE header)
    if null_bytes < 0.05:
        score += 0.15
        patterns_found.append("Faible densité null bytes")

    # Patterns connus
    for pattern, desc in SHELLCODE_PATTERNS:
        if pattern in data:
            score = min(1.0, score + 0.45)
            patterns_found.append(desc)

    results["patterns"] = patterns_found
    results["confidence"] = round(min(1.0, score), 3)
    results["is_shellcode"] = score >= 0.50

    return results
