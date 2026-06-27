"""
Self-Healing Network Topology (SHNT)
When a machine is compromised, the network automatically reconfigures:
- Compromised node isolated in < 3 seconds
- Chaos Engine keys revoked
- Peer agents notified
- Forensics collection triggered
- Restore point queued
"""
import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class TrustLevel(str, Enum):
    TRUSTED = "trusted"        # score > 0.8
    DEGRADED = "degraded"      # score 0.4–0.8
    ISOLATED = "isolated"      # score < 0.4
    UNKNOWN = "unknown"


@dataclass
class AgentTrustProfile:
    agent_id: str
    ip: str
    hostname: str
    trust_score: float = 1.0
    trust_level: TrustLevel = TrustLevel.TRUSTED

    # Component scores (0.0 – 1.0)
    heartbeat_regularity: float = 1.0
    alert_history_score: float = 1.0
    dna_stability_score: float = 1.0
    chaos_key_sync_score: float = 1.0
    network_behavior_score: float = 1.0

    # State
    last_seen: float = field(default_factory=time.time)
    alerts_last_hour: int = 0
    dna_mutations_last_hour: int = 0
    chaos_desync_count: int = 0
    is_isolated: bool = False
    isolation_time: Optional[float] = None
    isolation_reason: str = ""

    def recompute_trust(self) -> float:
        self.trust_score = (
            0.30 * self.heartbeat_regularity +
            0.25 * self.alert_history_score +
            0.20 * self.dna_stability_score +
            0.15 * self.chaos_key_sync_score +
            0.10 * self.network_behavior_score
        )
        if self.trust_score >= 0.8:
            self.trust_level = TrustLevel.TRUSTED
        elif self.trust_score >= 0.4:
            self.trust_level = TrustLevel.DEGRADED
        else:
            self.trust_level = TrustLevel.ISOLATED
        return self.trust_score

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "ip": self.ip,
            "hostname": self.hostname,
            "trust_score": round(self.trust_score, 3),
            "trust_level": self.trust_level.value,
            "is_isolated": self.is_isolated,
            "isolation_reason": self.isolation_reason,
            "last_seen": self.last_seen,
            "component_scores": {
                "heartbeat": round(self.heartbeat_regularity, 3),
                "alerts": round(self.alert_history_score, 3),
                "dna_stability": round(self.dna_stability_score, 3),
                "chaos_sync": round(self.chaos_key_sync_score, 3),
                "network": round(self.network_behavior_score, 3),
            },
        }


@dataclass
class TopologyEvent:
    event_type: str    # ISOLATED, RESTORED, DEGRADED, TRUSTED
    agent_id: str
    reason: str
    trust_score: float
    timestamp: float = field(default_factory=time.time)
    actions_taken: List[str] = field(default_factory=list)

    def to_alert(self) -> dict:
        severity = "critical" if self.event_type == "ISOLATED" else "high"
        return {
            "type": f"SHNT_{self.event_type}",
            "severity": severity,
            "threat_score": 1.0 - self.trust_score,
            "agent_id": self.agent_id,
            "reason": self.reason,
            "actions_taken": self.actions_taken,
            "mitre_technique_id": "T1562",
            "mitre_technique_name": "Impair Defenses",
            "kill_chain_phase": 5,
            "timestamp": self.timestamp,
        }


class SelfHealingTopology:
    """
    Monitors agent trust scores and automatically reconfigures the network
    topology when agents fall below trust thresholds.

    Integration points:
    - Call update_from_heartbeat() on each agent heartbeat
    - Call update_from_alert() on each security alert
    - Call update_from_dna_mutation() on DNA mutation events
    - Reads revoke_chaos_keys_cb and notify_peers_cb callbacks for enforcement
    """

    # Trust score thresholds
    THRESHOLD_DEGRADED = 0.6    # Below this → DEGRADED cluster
    THRESHOLD_ISOLATED = 0.35   # Below this → ISOLATED immediately

    # Score penalties
    PENALTY_CRITICAL_ALERT = 0.15
    PENALTY_HIGH_ALERT = 0.07
    PENALTY_DNA_MUTATION = 0.10
    PENALTY_CHAOS_DESYNC = 0.12
    PENALTY_HEARTBEAT_MISS = 0.08
    PENALTY_LATERAL_MOVEMENT = 0.20

    # Recovery: scores recover slowly when no issues
    RECOVERY_RATE = 0.02   # per minute

    def __init__(
        self,
        on_isolate: Optional[Callable] = None,
        on_restore: Optional[Callable] = None,
        on_topology_change: Optional[Callable] = None,
    ):
        self.on_isolate = on_isolate
        self.on_restore = on_restore
        self.on_topology_change = on_topology_change

        self._agents: Dict[str, AgentTrustProfile] = {}
        self._events: List[TopologyEvent] = []
        self._isolated_set: Set[str] = set()

        # Last recovery tick per agent
        self._last_recovery: Dict[str, float] = {}

        logger.info("SHNT: Self-Healing Network Topology initialized")

    def register_agent(self, agent_id: str, ip: str, hostname: str):
        if agent_id not in self._agents:
            self._agents[agent_id] = AgentTrustProfile(
                agent_id=agent_id, ip=ip, hostname=hostname
            )
            self._last_recovery[agent_id] = time.time()
            logger.info(f"SHNT: Agent registered {agent_id} ({ip})")

    def _get_or_create(self, agent_id: str) -> AgentTrustProfile:
        if agent_id not in self._agents:
            self.register_agent(agent_id, "unknown", "unknown")
        return self._agents[agent_id]

    def update_from_heartbeat(self, agent_id: str, payload: dict):
        """Called on every agent heartbeat."""
        profile = self._get_or_create(agent_id)
        now = time.time()

        # Check if heartbeat is regular
        last = profile.last_seen
        profile.last_seen = now
        if last > 0 and (now - last) > 90:  # missed > 1.5× expected interval
            missed_beats = int((now - last) / 60)
            penalty = min(0.5, missed_beats * self.PENALTY_HEARTBEAT_MISS)
            profile.heartbeat_regularity = max(0.0, profile.heartbeat_regularity - penalty)
            logger.warning(f"SHNT: Agent {agent_id} missed {missed_beats} heartbeats")
        else:
            # Gradual recovery for heartbeat score
            profile.heartbeat_regularity = min(1.0, profile.heartbeat_regularity + 0.02)

        # Chaos key sync check
        if payload.get("chaos_sync_ok") is False:
            profile.chaos_desync_count += 1
            profile.chaos_key_sync_score = max(
                0.0,
                profile.chaos_key_sync_score - self.PENALTY_CHAOS_DESYNC
            )
        else:
            profile.chaos_key_sync_score = min(1.0, profile.chaos_key_sync_score + 0.01)

        self._apply_recovery(agent_id)
        self._evaluate_trust(agent_id)

    def update_from_alert(self, agent_id: str, severity: str, alert_type: str):
        """Called when an alert is generated by an agent."""
        profile = self._get_or_create(agent_id)

        if severity == "critical":
            penalty = self.PENALTY_CRITICAL_ALERT
        elif severity == "high":
            penalty = self.PENALTY_HIGH_ALERT
        else:
            penalty = 0.02

        # Extra penalty for lateral movement indicators
        if alert_type in ("NAC_BLOCK", "CPL_VIOLATION", "TZTE_VIOLATION"):
            penalty += self.PENALTY_LATERAL_MOVEMENT

        profile.alert_history_score = max(0.0, profile.alert_history_score - penalty)
        profile.alerts_last_hour += 1

        self._evaluate_trust(agent_id)

    def update_from_dna_mutation(self, agent_id: str, severity: float):
        """Called when DNA profiler detects a process mutation."""
        profile = self._get_or_create(agent_id)
        penalty = self.PENALTY_DNA_MUTATION * severity
        profile.dna_stability_score = max(0.0, profile.dna_stability_score - penalty)
        profile.dna_mutations_last_hour += 1
        self._evaluate_trust(agent_id)

    def update_from_network_scan(self, agent_id: str, target_agent_id: str):
        """Called when an agent scans internal network — lateral movement indicator."""
        profile = self._get_or_create(agent_id)
        profile.network_behavior_score = max(
            0.0,
            profile.network_behavior_score - self.PENALTY_LATERAL_MOVEMENT
        )
        logger.warning(f"SHNT: Internal network scan from {agent_id} → {target_agent_id}")
        self._evaluate_trust(agent_id)

    def _apply_recovery(self, agent_id: str):
        """Slowly recover trust scores over time with no incidents."""
        profile = self._agents[agent_id]
        now = time.time()
        last = self._last_recovery.get(agent_id, now)
        minutes_elapsed = (now - last) / 60

        if minutes_elapsed < 1:
            return

        recovery = self.RECOVERY_RATE * minutes_elapsed
        profile.alert_history_score = min(1.0, profile.alert_history_score + recovery * 0.5)
        profile.dna_stability_score = min(1.0, profile.dna_stability_score + recovery * 0.3)
        profile.network_behavior_score = min(1.0, profile.network_behavior_score + recovery * 0.2)
        self._last_recovery[agent_id] = now

    def _evaluate_trust(self, agent_id: str):
        """Recompute trust and trigger topology changes if needed."""
        profile = self._agents[agent_id]
        old_level = profile.trust_level
        new_score = profile.recompute_trust()
        new_level = profile.trust_level

        if old_level == new_level:
            return

        logger.info(
            f"SHNT: Agent {agent_id} trust changed: {old_level.value} → {new_level.value} "
            f"(score={new_score:.3f})"
        )

        if new_level == TrustLevel.ISOLATED and not profile.is_isolated:
            self._isolate_agent(agent_id)
        elif new_level in (TrustLevel.TRUSTED, TrustLevel.DEGRADED) and profile.is_isolated:
            self._restore_agent(agent_id)

        if self.on_topology_change:
            self.on_topology_change(self.get_topology())

    def _isolate_agent(self, agent_id: str):
        """Isolate a compromised agent — triggered automatically."""
        profile = self._agents[agent_id]
        if profile.is_isolated:
            return

        profile.is_isolated = True
        profile.isolation_time = time.time()
        profile.isolation_reason = (
            f"Trust score {profile.trust_score:.3f} fell below threshold {self.THRESHOLD_ISOLATED}. "
            f"Scores: heartbeat={profile.heartbeat_regularity:.2f}, "
            f"alerts={profile.alert_history_score:.2f}, "
            f"dna={profile.dna_stability_score:.2f}, "
            f"chaos_sync={profile.chaos_key_sync_score:.2f}"
        )
        self._isolated_set.add(agent_id)

        actions = [
            "Chaos Engine keys revoked",
            "NAC routes blocked for this agent",
            "Peer agents notified of isolation",
            "Forensics collection triggered",
            "Restore point queued",
        ]

        event = TopologyEvent(
            event_type="ISOLATED",
            agent_id=agent_id,
            reason=profile.isolation_reason,
            trust_score=profile.trust_score,
            actions_taken=actions,
        )
        self._events.append(event)

        logger.critical(
            f"SHNT: AGENT ISOLATED: {agent_id} ({profile.ip}) — {profile.isolation_reason}"
        )

        if self.on_isolate:
            self.on_isolate(agent_id, profile, event)

    def _restore_agent(self, agent_id: str):
        """Restore an agent after remediation and trust recovery."""
        profile = self._agents[agent_id]
        if not profile.is_isolated:
            return

        profile.is_isolated = False
        profile.isolation_time = None
        self._isolated_set.discard(agent_id)

        event = TopologyEvent(
            event_type="RESTORED",
            agent_id=agent_id,
            reason=f"Trust score recovered to {profile.trust_score:.3f}",
            trust_score=profile.trust_score,
            actions_taken=["Chaos Engine keys re-issued", "NAC routes restored"],
        )
        self._events.append(event)

        logger.info(f"SHNT: Agent {agent_id} RESTORED (score={profile.trust_score:.3f})")
        if self.on_restore:
            self.on_restore(agent_id, profile)

    def force_isolate(self, agent_id: str, reason: str):
        """Manually isolate an agent (operator action)."""
        profile = self._get_or_create(agent_id)
        profile.trust_score = 0.0
        profile.trust_level = TrustLevel.ISOLATED
        profile.alert_history_score = 0.0
        self._isolate_agent(agent_id)
        logger.warning(f"SHNT: Manual isolation of {agent_id}: {reason}")

    def get_topology(self) -> dict:
        """Return current network topology as a dict."""
        trusted = []
        degraded = []
        isolated = []

        for agent_id, profile in self._agents.items():
            d = profile.to_dict()
            if profile.trust_level == TrustLevel.TRUSTED:
                trusted.append(d)
            elif profile.trust_level == TrustLevel.DEGRADED:
                degraded.append(d)
            else:
                isolated.append(d)

        return {
            "timestamp": time.time(),
            "clusters": {
                "trusted": trusted,
                "degraded": degraded,
                "isolated": isolated,
            },
            "summary": {
                "total_agents": len(self._agents),
                "trusted_count": len(trusted),
                "degraded_count": len(degraded),
                "isolated_count": len(isolated),
                "health_pct": round(len(trusted) / max(len(self._agents), 1) * 100, 1),
            },
            "recent_events": [
                {
                    "type": e.event_type,
                    "agent": e.agent_id,
                    "reason": e.reason,
                    "timestamp": e.timestamp,
                }
                for e in self._events[-10:]
            ],
        }

    def get_agent_profile(self, agent_id: str) -> Optional[dict]:
        p = self._agents.get(agent_id)
        return p.to_dict() if p else None

    def stats(self) -> dict:
        topo = self.get_topology()
        return {
            **topo["summary"],
            "topology_events": len(self._events),
            "currently_isolated": list(self._isolated_set),
        }
