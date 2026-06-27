"""
Cryptographic Process Lineage (CPL)
Every process spawn creates a parent→child HMAC ticket.
A process without a valid lineage ticket is flagged immediately.
"""
import hashlib
import hmac
import json
import logging
import math
import os
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class LineageTicket:
    parent_pid: int
    child_pid: int
    child_exe: str
    parent_dna_hash: str
    issued_at: float
    expiry: float          # ticket valid for 60s post-spawn
    signature: str

    def is_valid(self) -> bool:
        return time.time() < self.expiry

    def to_dict(self) -> dict:
        return {
            "parent_pid": self.parent_pid,
            "child_pid": self.child_pid,
            "child_exe": self.child_exe,
            "parent_dna_hash": self.parent_dna_hash,
            "issued_at": self.issued_at,
            "expiry": self.expiry,
            "signature": self.signature,
        }


@dataclass
class LineageViolation:
    pid: int
    exe: str
    parent_pid: int
    parent_exe: str
    reason: str
    severity: float
    timestamp: float = field(default_factory=time.time)
    mitre_technique: str = "T1055"  # Process Injection
    mitre_name: str = "Process Injection"

    def to_alert(self) -> dict:
        return {
            "type": "CPL_VIOLATION",
            "severity": "critical" if self.severity >= 0.9 else "high",
            "threat_score": self.severity,
            "process": self.exe,
            "reason": self.reason,
            "pid": self.pid,
            "parent_pid": self.parent_pid,
            "parent_exe": self.parent_exe,
            "mitre_technique_id": self.mitre_technique,
            "mitre_technique_name": self.mitre_name,
            "kill_chain_phase": 4,
            "timestamp": self.timestamp,
        }


class ProcessLineageEngine:
    """
    Maintains a cryptographic chain of custody for all process spawns.
    Detects orphaned processes, injection, and hollowing.
    """

    # Processes that legitimately spawn without a tracked parent (OS-level)
    BOOTSTRAP_PROCESSES = {
        "system", "system idle process", "smss.exe", "csrss.exe",
        "wininit.exe", "services.exe", "lsass.exe", "svchost.exe",
        "explorer.exe", "dwm.exe", "winlogon.exe", "spoolsv.exe",
        "taskhostw.exe", "sihost.exe", "fontdrvhost.exe",
    }

    # High-risk processes that should ALWAYS have a valid ticket
    HIGH_RISK_PROCESSES = {
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
        "bitsadmin.exe", "wmic.exe", "msiexec.exe", "installutil.exe",
        "regasm.exe", "regsvcs.exe", "msbuild.exe", "cmstp.exe",
    }

    def __init__(self, master_key: bytes):
        self.master_key = master_key
        # pid → LineageTicket
        self._tickets: Dict[int, LineageTicket] = {}
        # pid → list of children pids
        self._children: Dict[int, List[int]] = defaultdict(list)
        # pid → parent pid
        self._parent_map: Dict[int, int] = {}
        # Violations detected
        self.violations: List[LineageViolation] = []
        self._known_pids: set = set()

    def _derive_ticket_key(self, window: int) -> bytes:
        """Key rotates every 60 seconds."""
        key_material = self.master_key + struct.pack(">Q", window)
        return hashlib.pbkdf2_hmac("sha256", key_material, b"CPL-LINEAGE", 1)

    def _sign(self, parent_pid: int, child_pid: int, child_exe: str,
              parent_dna_hash: str, expiry: float) -> str:
        window = int(time.time()) // 60
        key = self._derive_ticket_key(window)
        msg = f"{parent_pid}:{child_pid}:{child_exe}:{parent_dna_hash}:{expiry:.0f}"
        return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()

    def _verify_signature(self, ticket: LineageTicket) -> bool:
        window = int(ticket.issued_at) // 60
        for w in [window, window - 1, window + 1]:  # ±1 window tolerance
            key = self._derive_ticket_key(w)
            msg = f"{ticket.parent_pid}:{ticket.child_pid}:{ticket.child_exe}:{ticket.parent_dna_hash}:{ticket.expiry:.0f}"
            expected = hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()
            if hmac.compare_digest(expected, ticket.signature):
                return True
        return False

    def issue_ticket(self, parent_pid: int, child_pid: int,
                     child_exe: str, parent_dna_hash: str) -> LineageTicket:
        """Called when we observe a legitimate process spawn."""
        now = time.time()
        expiry = now + 60.0
        sig = self._sign(parent_pid, child_pid, child_exe, parent_dna_hash, expiry)
        ticket = LineageTicket(
            parent_pid=parent_pid,
            child_pid=child_pid,
            child_exe=child_exe,
            parent_dna_hash=parent_dna_hash,
            issued_at=now,
            expiry=expiry,
            signature=sig,
        )
        self._tickets[child_pid] = ticket
        self._children[parent_pid].append(child_pid)
        self._parent_map[child_pid] = parent_pid
        self._known_pids.add(child_pid)
        logger.debug(f"CPL ticket issued: {parent_pid}→{child_pid} ({child_exe})")
        return ticket

    def register_bootstrap(self, pid: int, exe_name: str):
        """Register OS-level bootstrap processes that need no parent ticket."""
        self._known_pids.add(pid)
        logger.debug(f"CPL bootstrap registered: {pid} ({exe_name})")

    def validate_process(self, pid: int, exe: str,
                         parent_pid: int, parent_exe: str) -> Optional[LineageViolation]:
        """
        Check if a process has a valid lineage ticket.
        Returns a violation if the process is suspicious.
        """
        exe_lower = exe.lower()
        parent_lower = parent_exe.lower()

        # Bootstrap processes are always valid
        if exe_lower in self.BOOTSTRAP_PROCESSES:
            self._known_pids.add(pid)
            return None

        # Already known and ticketed
        if pid in self._tickets:
            ticket = self._tickets[pid]
            if ticket.is_valid() and self._verify_signature(ticket):
                return None
            # Expired ticket — warn but don't flag as critical
            if not ticket.is_valid():
                self._known_pids.add(pid)
                return None

        # Known non-ticketed process (registered before CPL was active)
        if pid in self._known_pids:
            return None

        # NEW process without a ticket
        severity = 0.0
        reason = ""

        if exe_lower in self.HIGH_RISK_PROCESSES:
            # High-risk tool without ticket = very suspicious
            severity = 0.88
            reason = (
                f"High-risk process '{exe}' spawned without valid CPL ticket. "
                f"Parent: {parent_exe} (PID {parent_pid}). "
                f"Possible LOLBin abuse or process hollowing."
            )
        elif parent_pid not in self._known_pids and parent_pid > 0:
            # Parent is also unknown = double orphan
            severity = 0.75
            reason = (
                f"Orphaned process '{exe}' (PID {pid}) — unknown parent chain. "
                f"Parent '{parent_exe}' (PID {parent_pid}) also unregistered. "
                f"Possible process injection or rootkit activity."
            )
        else:
            # Unknown process but low-risk name — register quietly
            self._known_pids.add(pid)
            return None

        violation = LineageViolation(
            pid=pid, exe=exe,
            parent_pid=parent_pid, parent_exe=parent_exe,
            reason=reason, severity=severity,
        )
        self.violations.append(violation)
        logger.warning(f"CPL VIOLATION: {reason}")
        return violation

    def scan_process_list(self, processes: list) -> List[LineageViolation]:
        """
        Scan a list of psutil-style process dicts for lineage violations.
        processes: [{"pid", "name", "ppid", "parent_name"}, ...]
        """
        violations = []

        # First pass: register all known PIDs
        for proc in processes:
            if proc.get("name", "").lower() in self.BOOTSTRAP_PROCESSES:
                self.register_bootstrap(proc["pid"], proc["name"])

        # Second pass: validate lineage
        for proc in processes:
            name = proc.get("name", "unknown")
            pid = proc.get("pid", 0)
            ppid = proc.get("ppid", 0)
            parent_name = proc.get("parent_name", "unknown")

            v = self.validate_process(pid, name, ppid, parent_name)
            if v:
                violations.append(v)

        return violations

    def get_lineage_chain(self, pid: int) -> List[int]:
        """Return the full ancestry chain for a given PID."""
        chain = [pid]
        current = pid
        seen = set()
        while current in self._parent_map and current not in seen:
            seen.add(current)
            current = self._parent_map[current]
            chain.append(current)
        return chain

    def stats(self) -> dict:
        return {
            "tracked_pids": len(self._known_pids),
            "active_tickets": sum(1 for t in self._tickets.values() if t.is_valid()),
            "total_violations": len(self.violations),
            "recent_violations": [v.to_alert() for v in self.violations[-5:]],
        }
