"""
Temporal Zero-Trust Execution (TZTE)
Every sensitive action (network write, process spawn, file write outside home dir)
requires a cryptographic ticket valid for 30 seconds.
No ticket = action is flagged/blocked.
"""
import hashlib
import hmac as hmac_lib
import logging
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class ActionType(str, Enum):
    PROCESS_SPAWN = "PROCESS_SPAWN"
    NETWORK_CONNECT = "NETWORK_CONNECT"
    NETWORK_SEND = "NETWORK_SEND"
    FILE_WRITE_EXTERNAL = "FILE_WRITE_EXTERNAL"
    REGISTRY_WRITE = "REGISTRY_WRITE"
    SERVICE_CREATE = "SERVICE_CREATE"
    SCHEDULED_TASK = "SCHEDULED_TASK"
    LOAD_DRIVER = "LOAD_DRIVER"
    INJECT_MEMORY = "INJECT_MEMORY"


# Ticket lifetime in seconds
TICKET_LIFETIME = 30.0

# Actions that ALWAYS require a ticket (zero exceptions)
STRICT_ACTIONS: Set[ActionType] = {
    ActionType.INJECT_MEMORY,
    ActionType.LOAD_DRIVER,
    ActionType.SERVICE_CREATE,
}

# Actions that require a ticket only for non-whitelisted processes
CONDITIONAL_ACTIONS: Set[ActionType] = {
    ActionType.PROCESS_SPAWN,
    ActionType.NETWORK_CONNECT,
    ActionType.NETWORK_SEND,
    ActionType.FILE_WRITE_EXTERNAL,
    ActionType.REGISTRY_WRITE,
    ActionType.SCHEDULED_TASK,
}

# Process whitelist — these can act without tickets for CONDITIONAL_ACTIONS
# (they still need tickets for STRICT_ACTIONS)
TRUSTED_PROCESSES: Set[str] = {
    "explorer.exe", "svchost.exe", "services.exe", "lsass.exe",
    "winlogon.exe", "csrss.exe", "wininit.exe", "smss.exe",
    "dwm.exe", "taskhostw.exe", "sihost.exe", "fontdrvhost.exe",
    "spoolsv.exe", "searchindexer.exe", "wsmprovhost.exe",
    # Common browsers (have their own update mechanisms)
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    # System updaters
    "wuauclt.exe", "musnotification.exe",
}


@dataclass
class ExecutionTicket:
    ticket_id: str
    action: ActionType
    process_name: str
    pid: int
    dna_hash: str            # Process DNA hash at time of issuance
    target: str              # What is being accessed (path, IP, etc.)
    issued_at: float
    expires_at: float
    signature: str

    def is_valid(self) -> bool:
        return time.time() <= self.expires_at

    def to_dict(self) -> dict:
        return {
            "ticket_id": self.ticket_id,
            "action": self.action.value,
            "process_name": self.process_name,
            "pid": self.pid,
            "dna_hash": self.dna_hash,
            "target": self.target,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signature": self.signature,
        }


@dataclass
class TZTEViolation:
    pid: int
    process_name: str
    action: ActionType
    target: str
    reason: str
    severity: float
    dna_hash: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_alert(self) -> dict:
        mitre_map = {
            ActionType.INJECT_MEMORY: ("T1055", "Process Injection", 4),
            ActionType.LOAD_DRIVER: ("T1543", "Create or Modify System Process", 3),
            ActionType.SERVICE_CREATE: ("T1543.003", "Windows Service", 3),
            ActionType.PROCESS_SPAWN: ("T1059", "Command Execution", 2),
            ActionType.NETWORK_CONNECT: ("T1071", "Application Layer Protocol", 6),
            ActionType.SCHEDULED_TASK: ("T1053.005", "Scheduled Task", 3),
            ActionType.REGISTRY_WRITE: ("T1547.001", "Registry Run Keys", 3),
            ActionType.FILE_WRITE_EXTERNAL: ("T1083", "File and Directory Discovery", 5),
            ActionType.NETWORK_SEND: ("T1041", "Exfiltration Over C2 Channel", 7),
        }
        tech = mitre_map.get(self.action, ("T1059", "Command Execution", 2))
        return {
            "type": "TZTE_VIOLATION",
            "severity": "critical" if self.severity >= 0.9 else "high",
            "threat_score": self.severity,
            "process": self.process_name,
            "pid": self.pid,
            "reason": self.reason,
            "action": self.action.value,
            "target": self.target,
            "dna_hash": self.dna_hash,
            "mitre_technique_id": tech[0],
            "mitre_technique_name": tech[1],
            "kill_chain_phase": tech[2],
            "timestamp": self.timestamp,
        }


class TZTEDaemon:
    """
    Temporal Zero-Trust Execution daemon.

    Workflow:
      1. Process requests an action ticket from the daemon
      2. Daemon checks: is the process DNA hash whitelisted?
      3. If yes: issues a 30-second HMAC ticket
      4. Process presents ticket when performing the action
      5. Daemon (or interceptor) verifies the ticket
      6. No valid ticket → TZTE violation logged

    In production: integrate with a Windows minifilter driver
    or ETW consumer for real enforcement.
    """

    def __init__(self, master_key: bytes, on_violation: Optional[Callable] = None):
        self.master_key = master_key
        self.on_violation = on_violation

        # Active tickets: ticket_id → ExecutionTicket
        self._tickets: Dict[str, ExecutionTicket] = {}
        # pid → set of granted action types
        self._granted: Dict[int, Dict[ActionType, float]] = {}
        # Known safe (pid, dna_hash) combinations
        self._trusted_pids: Dict[int, str] = {}  # pid → dna_hash
        # Violations
        self.violations: List[TZTEViolation] = []

        # Cleanup thread for expired tickets
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="TZTE-Cleanup"
        )
        self._cleanup_thread.start()
        logger.info("TZTE Daemon initialized")

    def _derive_ticket_key(self, window: int) -> bytes:
        """Key rotates every 30 seconds."""
        material = self.master_key + struct.pack(">Q", window)
        return hashlib.pbkdf2_hmac("sha256", material, b"TZTE-EXEC", 1)

    def _sign_ticket(self, ticket_id: str, action: ActionType, pid: int,
                     dna_hash: str, target: str, expires_at: float) -> str:
        window = int(time.time()) // 30
        key = self._derive_ticket_key(window)
        msg = f"{ticket_id}:{action.value}:{pid}:{dna_hash}:{target}:{expires_at:.0f}"
        return hmac_lib.new(key, msg.encode(), hashlib.sha256).hexdigest()

    def _verify_ticket_sig(self, ticket: ExecutionTicket) -> bool:
        window = int(ticket.issued_at) // 30
        for w in [window, window - 1, window + 1]:
            key = self._derive_ticket_key(w)
            msg = (
                f"{ticket.ticket_id}:{ticket.action.value}:{ticket.pid}:"
                f"{ticket.dna_hash}:{ticket.target}:{ticket.expires_at:.0f}"
            )
            expected = hmac_lib.new(key, msg.encode(), hashlib.sha256).hexdigest()
            if hmac_lib.compare_digest(expected, ticket.signature):
                return True
        return False

    def register_trusted_process(self, pid: int, dna_hash: str, process_name: str):
        """Register a process as trusted after DNA profiling confirms identity."""
        self._trusted_pids[pid] = dna_hash
        logger.debug(f"TZTE: Trusted process registered: PID={pid} '{process_name}'")

    def request_ticket(self, pid: int, process_name: str,
                       action: ActionType, target: str,
                       dna_hash: str = "") -> Optional[ExecutionTicket]:
        """
        Request an execution ticket for a sensitive action.
        Returns ticket if granted, None if denied.
        """
        proc_lower = process_name.lower()

        # STRICT actions: always require valid DNA hash
        if action in STRICT_ACTIONS:
            if not dna_hash or pid not in self._trusted_pids:
                self._record_violation(
                    pid=pid, process_name=process_name,
                    action=action, target=target,
                    reason=(
                        f"STRICT action '{action.value}' requested by untrusted process "
                        f"'{process_name}'. No DNA registration found."
                    ),
                    severity=0.97, dna_hash=dna_hash,
                )
                return None

        # CONDITIONAL actions: trusted system processes get auto-tickets
        if action in CONDITIONAL_ACTIONS and proc_lower in TRUSTED_PROCESSES:
            pass  # Fall through to issue ticket

        # Check DNA hash matches registered hash
        registered_dna = self._trusted_pids.get(pid)
        if registered_dna and dna_hash and registered_dna != dna_hash:
            self._record_violation(
                pid=pid, process_name=process_name,
                action=action, target=target,
                reason=(
                    f"DNA hash mismatch for PID {pid} '{process_name}'. "
                    f"Registered: {registered_dna[:16]}... "
                    f"Presented: {dna_hash[:16]}... "
                    f"Possible process hollowing or identity spoofing."
                ),
                severity=0.99, dna_hash=dna_hash,
            )
            return None

        # Issue ticket
        now = time.time()
        ticket = ExecutionTicket(
            ticket_id=str(uuid.uuid4()),
            action=action,
            process_name=process_name,
            pid=pid,
            dna_hash=dna_hash,
            target=target,
            issued_at=now,
            expires_at=now + TICKET_LIFETIME,
            signature="",
        )
        ticket.signature = self._sign_ticket(
            ticket.ticket_id, action, pid, dna_hash, target, ticket.expires_at
        )
        self._tickets[ticket.ticket_id] = ticket
        logger.debug(
            f"TZTE: Ticket issued for PID={pid} '{process_name}' "
            f"action={action.value} target={target}"
        )
        return ticket

    def verify_ticket(self, ticket_id: str, pid: int,
                      action: ActionType, target: str) -> bool:
        """
        Verify a presented ticket at action execution time.
        Called by the interceptor/driver when an action is attempted.
        """
        ticket = self._tickets.get(ticket_id)

        if ticket is None:
            self._record_violation(
                pid=pid, process_name="unknown",
                action=action, target=target,
                reason=f"No ticket found for ID {ticket_id}. Ticketless execution attempt.",
                severity=0.85,
            )
            return False

        if not ticket.is_valid():
            self._record_violation(
                pid=pid, process_name=ticket.process_name,
                action=action, target=target,
                reason=f"Expired ticket presented by '{ticket.process_name}' PID={pid}.",
                severity=0.70, dna_hash=ticket.dna_hash,
            )
            return False

        if ticket.pid != pid or ticket.action != action:
            self._record_violation(
                pid=pid, process_name=ticket.process_name,
                action=action, target=target,
                reason=(
                    f"Ticket mismatch: ticket is for PID={ticket.pid}/"
                    f"action={ticket.action.value}, "
                    f"but used by PID={pid}/action={action.value}. "
                    f"Possible ticket theft."
                ),
                severity=0.95, dna_hash=ticket.dna_hash,
            )
            return False

        if not self._verify_ticket_sig(ticket):
            self._record_violation(
                pid=pid, process_name=ticket.process_name,
                action=action, target=target,
                reason=f"Invalid ticket signature for PID={pid}. Forged ticket detected.",
                severity=0.99, dna_hash=ticket.dna_hash,
            )
            return False

        # Valid — consume ticket (single use)
        del self._tickets[ticket_id]
        return True

    def check_action_without_ticket(self, pid: int, process_name: str,
                                    action: ActionType, target: str) -> TZTEViolation:
        """
        Directly flag an action that occurred without presenting a ticket.
        Used when the interceptor catches an action with no associated ticket_id.
        """
        severity_map = {
            ActionType.INJECT_MEMORY: 0.99,
            ActionType.LOAD_DRIVER: 0.97,
            ActionType.SERVICE_CREATE: 0.90,
            ActionType.SCHEDULED_TASK: 0.85,
            ActionType.PROCESS_SPAWN: 0.80,
            ActionType.NETWORK_CONNECT: 0.70,
            ActionType.NETWORK_SEND: 0.75,
            ActionType.REGISTRY_WRITE: 0.72,
            ActionType.FILE_WRITE_EXTERNAL: 0.65,
        }
        v = self._record_violation(
            pid=pid, process_name=process_name,
            action=action, target=target,
            reason=(
                f"Unticketted action '{action.value}' by '{process_name}' (PID={pid}) "
                f"on target '{target}'. Zero-trust policy violation."
            ),
            severity=severity_map.get(action, 0.75),
        )
        return v

    def _record_violation(self, pid: int, process_name: str, action: ActionType,
                           target: str, reason: str, severity: float,
                           dna_hash: str = "") -> TZTEViolation:
        v = TZTEViolation(
            pid=pid, process_name=process_name,
            action=action, target=target,
            reason=reason, severity=severity, dna_hash=dna_hash,
        )
        self.violations.append(v)
        logger.warning(f"TZTE VIOLATION [sev={severity:.2f}]: {reason}")
        if self.on_violation:
            self.on_violation(v)
        return v

    def _cleanup_loop(self):
        while True:
            now = time.time()
            expired = [tid for tid, t in list(self._tickets.items()) if not t.is_valid()]
            for tid in expired:
                self._tickets.pop(tid, None)
            time.sleep(30)

    def stats(self) -> dict:
        return {
            "trusted_processes": len(self._trusted_pids),
            "active_tickets": len(self._tickets),
            "total_violations": len(self.violations),
            "recent_violations": [v.to_alert() for v in self.violations[-5:]],
        }
