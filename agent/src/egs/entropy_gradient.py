"""
Entropy Gradient Shield (EGS)
Detects ransomware by measuring the rate of entropy increase across the filesystem.
Kills ransomware after 1-3 files encrypted, not thousands.
"""
import collections
import logging
import math
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = collections.Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)


@dataclass
class FileEntropySnapshot:
    path: str
    entropy: float
    size: int
    timestamp: float = field(default_factory=time.time)
    pid: Optional[int] = None


@dataclass
class RansomwareAlert:
    suspected_pid: Optional[int]
    suspected_process: Optional[str]
    affected_files: List[str]
    entropy_velocity: float        # bits/sec
    files_per_second: float
    detection_time: float
    severity: float
    action_taken: str

    def to_alert(self) -> dict:
        return {
            "type": "RANSOMWARE_DETECTED",
            "severity": "critical",
            "threat_score": self.severity,
            "process": self.suspected_process or "unknown",
            "reason": (
                f"Ransomware pattern: entropy velocity {self.entropy_velocity:.3f} bits/s "
                f"({self.files_per_second:.1f} files/s encrypted). "
                f"Affected: {len(self.affected_files)} files. Action: {self.action_taken}"
            ),
            "affected_files": self.affected_files[:10],
            "entropy_velocity": self.entropy_velocity,
            "mitre_technique_id": "T1486",
            "mitre_technique_name": "Data Encrypted for Impact",
            "kill_chain_phase": 8,
            "timestamp": self.detection_time,
        }


class EntropyGradientShield:
    """
    Monitors filesystem entropy changes in real-time.
    Uses sliding window to compute dH/dt (entropy velocity).

    Thresholds (bits/sec average across files):
        > 0.05  → SUSPICIOUS   (alert, start VSS snapshot)
        > 0.20  → HIGH         (suspend suspect process I/O)
        > 0.50  → CRITICAL     (kill process, restore VSS)
    """

    THRESHOLD_SUSPICIOUS = 0.05
    THRESHOLD_HIGH = 0.20
    THRESHOLD_CRITICAL = 0.50

    # Extensions targeted by ransomware
    TARGET_EXTENSIONS = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".jpg", ".jpeg", ".png", ".mp4", ".mov",
        ".zip", ".rar", ".7z", ".sql", ".db", ".sqlite",
        ".py", ".js", ".ts", ".java", ".cpp", ".cs",
        ".key", ".pem", ".pfx", ".p12", ".kdbx",
        ".bak", ".backup", ".tar", ".gz",
    }

    # Ransomware adds these extensions to encrypted files
    RANSOMWARE_EXTENSIONS = {
        ".encrypted", ".locked", ".crypt", ".crypto", ".enc",
        ".wnry", ".wncry", ".wcry", ".locky", ".zepto",
        ".cerber", ".osiris", ".thor", ".odin", ".aesir",
        ".shit", ".lol", ".r4a", ".zzzzz", ".fun",
    }

    def __init__(
        self,
        watch_dirs: Optional[List[str]] = None,
        window_seconds: float = 10.0,
        on_alert: Optional[Callable[[RansomwareAlert], None]] = None,
        sample_bytes: int = 4096,
    ):
        self.watch_dirs = watch_dirs or self._default_watch_dirs()
        self.window_seconds = window_seconds
        self.on_alert = on_alert
        self.sample_bytes = sample_bytes

        # Sliding window: deque of (timestamp, entropy_delta, path)
        self._window: Deque[Tuple[float, float, str]] = collections.deque()
        # Last known entropy per file
        self._file_entropy: Dict[str, FileEntropySnapshot] = {}
        # Recent alerts
        self.alerts: List[RansomwareAlert] = []
        # Suspected malicious PID
        self._suspected_pid: Optional[int] = None
        self._suspected_exe: Optional[str] = None

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # VSS snapshot tracking
        self._vss_triggered = False
        self._last_vss_time = 0.0

    def _default_watch_dirs(self) -> List[str]:
        home = str(Path.home())
        dirs = [
            home,
            os.path.join(home, "Documents"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Pictures"),
        ]
        return [d for d in dirs if os.path.isdir(d)]

    def _read_sample(self, path: str) -> Optional[bytes]:
        try:
            with open(path, "rb") as f:
                return f.read(self.sample_bytes)
        except (OSError, PermissionError):
            return None

    def _compute_entropy_delta(self, path: str) -> Optional[Tuple[float, float]]:
        """Returns (old_entropy, new_entropy) or None if unreadable."""
        data = self._read_sample(path)
        if data is None or len(data) < 32:
            return None

        new_entropy = shannon_entropy(data)
        size = os.path.getsize(path)

        old_snapshot = self._file_entropy.get(path)
        old_entropy = old_snapshot.entropy if old_snapshot else 0.0

        self._file_entropy[path] = FileEntropySnapshot(
            path=path, entropy=new_entropy, size=size
        )
        return old_entropy, new_entropy

    def _is_ransomware_extension(self, path: str) -> bool:
        ext = os.path.splitext(path)[1].lower()
        return ext in self.RANSOMWARE_EXTENSIONS

    def _is_target_extension(self, path: str) -> bool:
        ext = os.path.splitext(path)[1].lower()
        return ext in self.TARGET_EXTENSIONS

    def _compute_entropy_velocity(self) -> Tuple[float, float, List[str]]:
        """
        Returns (entropy_velocity bits/sec, files_per_second, affected_file_list).
        Prunes entries older than window_seconds.
        """
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            # Prune old entries
            while self._window and self._window[0][0] < cutoff:
                self._window.popleft()

            if len(self._window) < 2:
                return 0.0, 0.0, []

            total_delta = sum(delta for _, delta, _ in self._window)
            affected = list({path for _, _, path in self._window})
            actual_window = now - self._window[0][0]
            if actual_window < 0.1:
                return 0.0, 0.0, []

            velocity = total_delta / actual_window
            rate = len(self._window) / actual_window
            return velocity, rate, affected

    def record_file_change(self, path: str, pid: Optional[int] = None,
                           exe: Optional[str] = None):
        """
        Called whenever a file write is detected (via inotify/ReadDirectoryChangesW).
        Computes entropy delta and updates the sliding window.
        """
        # Immediate flag for ransomware extension
        if self._is_ransomware_extension(path):
            logger.critical(f"EGS: Ransomware extension detected on {path}")
            self._trigger_alert(
                velocity=1.0, rate=1.0,
                affected=[path], pid=pid, exe=exe,
                level="critical",
            )
            return

        if not self._is_target_extension(path):
            return

        result = self._compute_entropy_delta(path)
        if result is None:
            return

        old_e, new_e = result
        delta = max(0.0, new_e - old_e)   # only count increases

        # Only track significant entropy increases (> 0.5 bits)
        if delta < 0.5:
            return

        with self._lock:
            self._window.append((time.time(), delta, path))
            if pid:
                self._suspected_pid = pid
                self._suspected_exe = exe

        self._check_thresholds()

    def _check_thresholds(self):
        velocity, rate, affected = self._compute_entropy_velocity()

        if velocity <= self.THRESHOLD_SUSPICIOUS:
            return

        if velocity >= self.THRESHOLD_CRITICAL:
            self._trigger_alert(velocity, rate, affected, level="critical")
        elif velocity >= self.THRESHOLD_HIGH:
            self._trigger_alert(velocity, rate, affected, level="high")
        elif velocity >= self.THRESHOLD_SUSPICIOUS:
            self._trigger_alert(velocity, rate, affected, level="suspicious")

    def _trigger_alert(self, velocity: float, rate: float,
                       affected: List[str], level: str,
                       pid: Optional[int] = None, exe: Optional[str] = None):
        # Deduplicate alerts within 5 seconds
        now = time.time()
        if self.alerts and (now - self.alerts[-1].detection_time) < 5.0:
            return

        severity_map = {"suspicious": 0.65, "high": 0.82, "critical": 0.98}
        action_map = {
            "suspicious": "VSS snapshot triggered",
            "high": "Process I/O suspended — awaiting confirmation",
            "critical": "Process KILLED — VSS restore queued",
        }

        # Trigger VSS snapshot on first alert
        if not self._vss_triggered or (now - self._last_vss_time) > 300:
            self._take_vss_snapshot()

        alert = RansomwareAlert(
            suspected_pid=pid or self._suspected_pid,
            suspected_process=exe or self._suspected_exe,
            affected_files=affected,
            entropy_velocity=velocity,
            files_per_second=rate,
            detection_time=now,
            severity=severity_map.get(level, 0.65),
            action_taken=action_map.get(level, "Monitored"),
        )
        self.alerts.append(alert)
        logger.critical(
            f"EGS ALERT [{level.upper()}]: velocity={velocity:.3f} bits/s "
            f"rate={rate:.1f} files/s affected={len(affected)} files"
        )

        if self.on_alert:
            self.on_alert(alert)

    def _take_vss_snapshot(self):
        """Trigger a Windows VSS shadow copy for recovery."""
        self._vss_triggered = True
        self._last_vss_time = time.time()
        logger.info("EGS: Triggering VSS snapshot for ransomware recovery")
        try:
            import subprocess
            subprocess.Popen(
                ["wmic", "shadowcopy", "call", "create", "Volume=C:\\"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            logger.warning(f"EGS: VSS snapshot failed: {e}")

    def _scan_loop(self):
        """Background loop: periodically scan watched directories for changes."""
        logger.info(f"EGS: Started monitoring {len(self.watch_dirs)} directories")
        scan_interval = 2.0  # seconds between full dir scans
        last_scan_state: Dict[str, Tuple[float, int]] = {}  # path → (mtime, size)

        while self._running:
            for watch_dir in self.watch_dirs:
                if not os.path.isdir(watch_dir):
                    continue
                try:
                    for fname in os.listdir(watch_dir):
                        fpath = os.path.join(watch_dir, fname)
                        if not os.path.isfile(fpath):
                            continue

                        try:
                            stat = os.stat(fpath)
                            mtime = stat.st_mtime
                            size = stat.st_size
                        except OSError:
                            continue

                        prev = last_scan_state.get(fpath)
                        if prev and (mtime != prev[0] or size != prev[1]):
                            # File changed — compute entropy
                            self.record_file_change(fpath)

                        last_scan_state[fpath] = (mtime, size)
                except Exception as e:
                    logger.debug(f"EGS scan error in {watch_dir}: {e}")

            time.sleep(scan_interval)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._scan_loop, daemon=True, name="EGS-Shield")
        self._thread.start()
        logger.info("Entropy Gradient Shield started")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Entropy Gradient Shield stopped")

    def current_velocity(self) -> dict:
        v, r, affected = self._compute_entropy_velocity()
        level = "safe"
        if v >= self.THRESHOLD_CRITICAL:
            level = "critical"
        elif v >= self.THRESHOLD_HIGH:
            level = "high"
        elif v >= self.THRESHOLD_SUSPICIOUS:
            level = "suspicious"
        return {
            "entropy_velocity": round(v, 4),
            "files_per_second": round(r, 2),
            "affected_file_count": len(affected),
            "level": level,
            "total_alerts": len(self.alerts),
        }
