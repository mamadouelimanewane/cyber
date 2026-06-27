"""
Gravity Security — Scanner de Signatures
Base de signatures YARA-like simplifiée pour les menaces connues.
Complète le scanner comportemental pour les IOC (Indicators of Compromise) connus.
"""

import re
import hashlib
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger("gravity.scanner.signatures")


@dataclass
class Signature:
    name: str
    description: str
    severity: str  # "critical", "high", "medium", "low"
    hashes: List[str]
    byte_patterns: List[bytes]
    string_patterns: List[str]


# Base de signatures embarquée (exemples de patterns malveillants connus)
BUILTIN_SIGNATURES: List[Signature] = [
    Signature(
        name="Mimikatz",
        description="Outil d'extraction de credentials Windows",
        severity="critical",
        hashes=[],
        byte_patterns=[b"mimikatz", b"sekurlsa", b"kerberos::"],
        string_patterns=[r"sekurlsa", r"lsadump", r"privilege::debug"],
    ),
    Signature(
        name="Meterpreter_Stager",
        description="Stager Meterpreter (Metasploit)",
        severity="critical",
        hashes=[],
        byte_patterns=[b"\xfc\xe8\x8f\x00\x00\x00", b"\xfc\xe8\x82\x00\x00\x00"],
        string_patterns=[r"meterpreter", r"reverse_tcp"],
    ),
    Signature(
        name="PowerShell_Encoded",
        description="Commande PowerShell encodée en Base64 — technique d'obfuscation courante",
        severity="high",
        hashes=[],
        byte_patterns=[],
        string_patterns=[
            r"-[Ee]nc(odedCommand)?\s+[A-Za-z0-9+/]{50,}={0,2}",
            r"powershell.*-[Ee]\s+[A-Za-z0-9+/]{30,}",
        ],
    ),
    Signature(
        name="Ransomware_Extension_Rename",
        description="Pattern de renommage en masse — comportement typique ransomware",
        severity="critical",
        hashes=[],
        byte_patterns=[b"vssadmin delete shadows", b"wbadmin delete catalog"],
        string_patterns=[r"vssadmin.*delete.*shadows", r"bcdedit.*recoveryenabled.*no"],
    ),
    Signature(
        name="Keylogger_Hook",
        description="Installation de hook clavier/souris Windows",
        severity="high",
        hashes=[],
        byte_patterns=[b"SetWindowsHookEx", b"GetAsyncKeyState"],
        string_patterns=[r"SetWindowsHookEx", r"WH_KEYBOARD_LL"],
    ),
    Signature(
        name="Process_Injection",
        description="Injection de code dans un processus distant",
        severity="critical",
        hashes=[],
        byte_patterns=[b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread"],
        string_patterns=[r"VirtualAllocEx.*WriteProcessMemory.*CreateRemoteThread"],
    ),
    Signature(
        name="C2_Beacon",
        description="Pattern de communication Command & Control",
        severity="high",
        hashes=[],
        byte_patterns=[],
        string_patterns=[
            r"(\.onion|\.bit)\b",
            r"User-Agent.*python-requests",
            r"sleep\(\d+\).*http",
        ],
    ),
    Signature(
        name="Reverse_Shell",
        description="Shell inversé — connexion sortante vers attaquant",
        severity="critical",
        hashes=[],
        byte_patterns=[b"bash -i >& /dev/tcp/", b"nc -e /bin/sh"],
        string_patterns=[
            r"bash\s+-i\s+>&\s+/dev/tcp/",
            r"python.*socket.*connect.*subprocess",
            r"nc\.exe.*-e.*cmd",
        ],
    ),
]


class SignatureScanner:
    """
    Scanner de signatures pour les menaces connues.
    Complète le BehavioralScanner avec des IOC précis.
    """

    def __init__(self):
        self._signatures = list(BUILTIN_SIGNATURES)
        self._hash_db: Dict[str, str] = {}  # hash → nom menace
        self._build_hash_db()

    def _build_hash_db(self):
        for sig in self._signatures:
            for h in sig.hashes:
                self._hash_db[h.lower()] = sig.name

    def add_signature(self, sig: Signature):
        """Ajoute une signature personnalisée."""
        self._signatures.append(sig)
        for h in sig.hashes:
            self._hash_db[h.lower()] = sig.name

    def scan_bytes(self, data: bytes, context: str = "") -> List[Dict]:
        """Scanne des données brutes contre toutes les signatures."""
        detections = []
        data_lower = data.lower()
        data_str = data.decode("utf-8", errors="replace")

        for sig in self._signatures:
            matched = False

            # Patterns d'octets
            for pattern in sig.byte_patterns:
                if pattern.lower() in data_lower:
                    matched = True
                    break

            # Patterns de strings (regex)
            if not matched:
                for pattern in sig.string_patterns:
                    if re.search(pattern, data_str, re.I | re.M):
                        matched = True
                        break

            if matched:
                detections.append({
                    "signature": sig.name,
                    "description": sig.description,
                    "severity": sig.severity,
                    "context": context,
                })
                logger.warning(f"[SIGNATURE] {sig.name} ({sig.severity}) détecté dans: {context}")

        return detections

    def scan_file(self, file_path: str) -> List[Dict]:
        """Scanne un fichier contre la base de signatures."""
        # Vérification hash d'abord
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                data = f.read(10 * 1024 * 1024)
                h.update(data)
            file_hash = h.hexdigest()
        except (OSError, PermissionError):
            return []

        detections = []
        if file_hash in self._hash_db:
            detections.append({
                "signature": self._hash_db[file_hash],
                "description": "Hash SHA256 correspondant à une menace connue",
                "severity": "critical",
                "context": file_path,
            })

        detections.extend(self.scan_bytes(data, file_path))
        return detections

    def scan_command(self, cmdline: str) -> List[Dict]:
        """Scanne une ligne de commande (pour ProcessMonitor)."""
        return self.scan_bytes(cmdline.encode("utf-8", errors="replace"), f"cmdline:{cmdline[:80]}")

    @property
    def signature_count(self) -> int:
        return len(self._signatures)
