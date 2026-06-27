"""
Gravity Security — Scanner Comportemental
Détecte les comportements malveillants basés sur l'entropie, les imports PE,
et les patterns d'exécution — sans nécessiter de signatures connues.
"""

import os
import math
import struct
import hashlib
import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

logger = logging.getLogger("gravity.scanner.behavioral")


@dataclass
class ScanResult:
    file_path: str
    threat_score: float
    is_threat: bool
    reasons: List[str]
    file_hash: str
    entropy: float
    file_size: int


class BehavioralScanner:
    """
    Scanner comportemental basé sur :
    1. Entropie de Shannon (fichiers packés/chiffrés → entropie élevée)
    2. Analyse des imports PE (Windows Executable)
    3. Détection de patterns dans les strings
    4. Heuristiques de structure de fichier
    """

    THREAT_THRESHOLD = 0.65

    # Imports PE dangereux (DLL:fonction)
    DANGEROUS_IMPORTS = {
        "kernel32.dll": [
            "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
            "CreateRemoteThread", "OpenProcess", "NtUnmapViewOfSection",
            "SetWindowsHookEx", "CreateToolhelp32Snapshot",
        ],
        "wininet.dll": ["InternetOpen", "InternetConnect", "HttpSendRequest"],
        "ws2_32.dll": ["connect", "send", "recv", "WSAStartup"],
        "advapi32.dll": [
            "RegSetValueEx", "RegCreateKeyEx", "AdjustTokenPrivileges",
            "LookupPrivilegeValue", "OpenProcessToken",
        ],
        "ntdll.dll": [
            "NtCreateThread", "NtWriteVirtualMemory", "NtAllocateVirtualMemory",
            "ZwUnmapViewOfSection", "RtlCreateUserThread",
        ],
        "user32.dll": ["SetWindowsHookEx", "GetAsyncKeyState", "keybd_event"],
    }

    # Strings suspectes dans les binaires
    SUSPICIOUS_STRINGS = [
        b"cmd.exe", b"powershell", b"wscript", b"cscript",
        b"http://", b"https://", b"ftp://",
        b"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        b"SeDebugPrivilege", b"VirtualAlloc",
        b"CreateRemoteThread", b"WriteProcessMemory",
        b"mimikatz", b"lsass", b"SAM\\SAM",
        b"bitcoin", b"ransom", b"encrypt",
        b"eval(", b"exec(", b"base64_decode",
    ]

    def __init__(self):
        self._scan_cache: Dict[str, ScanResult] = {}

    # ------------------------------------------------------------------ #
    #  Scan principal                                                    #
    # ------------------------------------------------------------------ #

    def scan_file(self, file_path: str) -> ScanResult:
        """Analyse un fichier et retourne un score de menace."""
        if not os.path.exists(file_path):
            return self._empty_result(file_path, "Fichier introuvable")

        # Cache basé sur le hash
        file_hash = self._hash_file(file_path)
        if file_hash in self._scan_cache:
            return self._scan_cache[file_hash]

        try:
            with open(file_path, "rb") as f:
                data = f.read(10 * 1024 * 1024)  # Max 10 MB
        except (PermissionError, OSError) as e:
            return self._empty_result(file_path, str(e))

        score = 0.0
        reasons = []
        file_size = len(data)

        # 1. Entropie de Shannon
        entropy = self._shannon_entropy(data)
        if entropy > 7.2:
            score += 0.35
            reasons.append(f"Entropie très élevée ({entropy:.2f}/8.0) — possible packer/chiffrement")
        elif entropy > 6.8:
            score += 0.15
            reasons.append(f"Entropie élevée ({entropy:.2f}/8.0)")

        # 2. Analyse PE (Windows Executable)
        if data[:2] == b"MZ":
            pe_score, pe_reasons = self._analyze_pe(data)
            score = min(1.0, score + pe_score)
            reasons.extend(pe_reasons)

        # 3. Strings suspectes
        str_score, str_reasons = self._check_suspicious_strings(data)
        score = min(1.0, score + str_score)
        reasons.extend(str_reasons)

        # 4. Taille suspecte (très petits exécutables = droppers/stagers)
        if data[:2] == b"MZ" and file_size < 10_000:
            score = min(1.0, score + 0.20)
            reasons.append(f"Exécutable suspect très petit ({file_size} octets)")

        is_threat = score >= self.THREAT_THRESHOLD
        result = ScanResult(
            file_path=file_path,
            threat_score=round(score, 3),
            is_threat=is_threat,
            reasons=reasons,
            file_hash=file_hash,
            entropy=round(entropy, 3),
            file_size=file_size,
        )
        self._scan_cache[file_hash] = result

        if is_threat:
            logger.warning(f"[MENACE] {file_path} — score {score:.2f} — {' | '.join(reasons)}")

        return result

    def scan_directory(self, directory: str, extensions: Optional[List[str]] = None) -> List[ScanResult]:
        """Scanne récursivement un répertoire."""
        if extensions is None:
            extensions = [".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".scr"]

        results = []
        for root, _, files in os.walk(directory):
            for fname in files:
                if any(fname.lower().endswith(ext) for ext in extensions):
                    path = os.path.join(root, fname)
                    result = self.scan_file(path)
                    if result.is_threat:
                        results.append(result)
        return results

    # ------------------------------------------------------------------ #
    #  Entropie de Shannon                                               #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        n = len(data)
        entropy = 0.0
        for f in freq:
            if f > 0:
                p = f / n
                entropy -= p * math.log2(p)
        return entropy

    # ------------------------------------------------------------------ #
    #  Analyse PE                                                        #
    # ------------------------------------------------------------------ #

    def _analyze_pe(self, data: bytes) -> Tuple[float, List[str]]:
        score = 0.0
        reasons = []

        try:
            # Offset vers le header PE
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 4 > len(data):
                return 0.0, []
            if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return 0.0, []

            # Compter les sections PE
            num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
            if num_sections > 10:
                score += 0.15
                reasons.append(f"Nombre de sections PE anormal ({num_sections})")

            # Chercher les imports via les strings (approche simplifiée)
            data_str = data.lower()
            dangerous_count = 0
            for dll, funcs in self.DANGEROUS_IMPORTS.items():
                dll_bytes = dll.encode().lower()
                if dll_bytes in data_str:
                    for func in funcs:
                        if func.lower().encode() in data_str:
                            dangerous_count += 1

            if dangerous_count >= 5:
                score += 0.40
                reasons.append(f"{dangerous_count} imports dangereux détectés (injection/keylogging/réseau)")
            elif dangerous_count >= 2:
                score += 0.20
                reasons.append(f"{dangerous_count} imports suspects détectés")

        except Exception:
            pass

        return score, reasons

    # ------------------------------------------------------------------ #
    #  Strings suspectes                                                 #
    # ------------------------------------------------------------------ #

    def _check_suspicious_strings(self, data: bytes) -> Tuple[float, List[str]]:
        score = 0.0
        reasons = []
        data_lower = data.lower()

        hits = []
        for s in self.SUSPICIOUS_STRINGS:
            if s.lower() in data_lower:
                hits.append(s.decode(errors="replace"))

        if len(hits) >= 5:
            score += 0.30
            reasons.append(f"Nombreuses strings suspectes: {', '.join(hits[:5])}")
        elif len(hits) >= 2:
            score += 0.15
            reasons.append(f"Strings suspectes: {', '.join(hits[:3])}")

        return score, reasons

    # ------------------------------------------------------------------ #
    #  Utilitaires                                                       #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _hash_file(path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        except (OSError, PermissionError):
            return ""
        return h.hexdigest()

    @staticmethod
    def _empty_result(path: str, reason: str) -> ScanResult:
        return ScanResult(
            file_path=path,
            threat_score=0.0,
            is_threat=False,
            reasons=[reason],
            file_hash="",
            entropy=0.0,
            file_size=0,
        )
