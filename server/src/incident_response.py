"""
Gravity Incident Response Engine — Corrélation + Réponse Automatique

Quand plusieurs alertes convergent vers le même agent/processus en < TIME_WINDOW,
l'IRE ouvre automatiquement un incident, choisit un playbook et exécute les actions.

Playbooks disponibles :
  RANSOMWARE       → isolate + kill + snapshot + notify
  SUPPLY_CHAIN     → kill_process + quarantine_file + preserve_evidence
  LATERAL_MOVEMENT → block_network + escalate
  DATA_EXFIL       → block_network + preserve_evidence + notify
  DEFAULT          → investigate + notify
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Awaitable


# ── Énumérations ─────────────────────────────────────────────────────────────

class IncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


class IncidentStatus(str, Enum):
    OPEN          = "open"
    INVESTIGATING = "investigating"
    CONTAINED     = "contained"
    CLOSED        = "closed"


class ResponseAction(str, Enum):
    ISOLATE_AGENT     = "isolate_agent"
    KILL_PROCESS      = "kill_process"
    BLOCK_NETWORK     = "block_network"
    QUARANTINE_FILE   = "quarantine_file"
    PRESERVE_EVIDENCE = "preserve_evidence"
    NOTIFY_SOC        = "notify_soc"
    ESCALATE          = "escalate"
    INVESTIGATE       = "investigate"
    SNAPSHOT          = "snapshot"


# ── Modèles ───────────────────────────────────────────────────────────────────

@dataclass
class TimelineEntry:
    ts: float
    action: str
    detail: str
    auto: bool = True


@dataclass
class Incident:
    id: str
    title: str
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.OPEN
    affected_agents: List[str] = field(default_factory=list)
    alert_count: int = 0
    kill_chain_phase: Optional[str] = None
    mitre_tactics: List[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    resolved_at: Optional[float] = None
    timeline: List[TimelineEntry] = field(default_factory=list)
    response_actions: List[str] = field(default_factory=list)
    playbook: Optional[str] = None
    alerts: List[Dict] = field(default_factory=list)

    def add_timeline(self, action: str, detail: str, auto: bool = True):
        self.timeline.append(TimelineEntry(time.time(), action, detail, auto))
        self.last_updated = time.time()

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d


# ── Corrélateur d'alertes ─────────────────────────────────────────────────────

# Groupes d'alertes qui constituent un incident quand ils coïncident
INCIDENT_RULES: List[Dict] = [
    {
        "name": "RANSOMWARE",
        "triggers": {"RANSOMWARE_DETECTED", "FILE_THREAT", "QBSM_COLLAPSE"},
        "min_triggers": 2,
        "window_s": 60,
        "severity": IncidentSeverity.CRITICAL,
        "playbook": "ransomware",
        "kill_chain": "Actions on Objectives",
        "mitre": ["T1486", "T1490"],
    },
    {
        "name": "SUPPLY_CHAIN_ATTACK",
        "triggers": {"SUPPLY_CHAIN_DLL_HIJACK", "SUPPLY_CHAIN_TYPOSQUAT",
                     "SUPPLY_CHAIN_BUILD_POISON", "CBGA_GENOME_MATCH"},
        "min_triggers": 1,
        "window_s": 300,
        "severity": IncidentSeverity.CRITICAL,
        "playbook": "supply_chain",
        "kill_chain": "Delivery",
        "mitre": ["T1195", "T1574"],
    },
    {
        "name": "LATERAL_MOVEMENT",
        "triggers": {"SYSCALL_ANOMALY", "UEBA_ANOMALY", "MEMORY_THREAT"},
        "min_triggers": 3,
        "window_s": 120,
        "severity": IncidentSeverity.HIGH,
        "playbook": "lateral_movement",
        "kill_chain": "Lateral Movement",
        "mitre": ["T1021", "T1550"],
    },
    {
        "name": "DATA_EXFILTRATION",
        "triggers": {"DNA_MUTATION", "UEBA_ANOMALY", "HONEYTOKEN_TRIGGERED"},
        "min_triggers": 2,
        "window_s": 180,
        "severity": IncidentSeverity.HIGH,
        "playbook": "data_exfil",
        "kill_chain": "Exfiltration",
        "mitre": ["T1041", "T1048"],
    },
    {
        "name": "DECEPTION_HIT",
        "triggers": {"HONEYTOKEN_TRIGGERED"},
        "min_triggers": 1,
        "window_s": 10,
        "severity": IncidentSeverity.HIGH,
        "playbook": "deception",
        "kill_chain": "Reconnaissance",
        "mitre": ["T1083", "T1040"],
    },
    {
        "name": "QBSM_COLLAPSE",
        "triggers": {"QBSM_COLLAPSE", "CBGA_GENOME_MATCH"},
        "min_triggers": 1,
        "window_s": 30,
        "severity": IncidentSeverity.CRITICAL,
        "playbook": "ransomware",
        "kill_chain": "Actions on Objectives",
        "mitre": ["T1486"],
    },
]

# Playbooks → séquence d'actions Response
PLAYBOOKS: Dict[str, List[ResponseAction]] = {
    "ransomware": [
        ResponseAction.KILL_PROCESS,
        ResponseAction.ISOLATE_AGENT,
        ResponseAction.SNAPSHOT,
        ResponseAction.PRESERVE_EVIDENCE,
        ResponseAction.NOTIFY_SOC,
    ],
    "supply_chain": [
        ResponseAction.KILL_PROCESS,
        ResponseAction.QUARANTINE_FILE,
        ResponseAction.PRESERVE_EVIDENCE,
        ResponseAction.NOTIFY_SOC,
    ],
    "lateral_movement": [
        ResponseAction.BLOCK_NETWORK,
        ResponseAction.PRESERVE_EVIDENCE,
        ResponseAction.ESCALATE,
        ResponseAction.NOTIFY_SOC,
    ],
    "data_exfil": [
        ResponseAction.BLOCK_NETWORK,
        ResponseAction.PRESERVE_EVIDENCE,
        ResponseAction.NOTIFY_SOC,
    ],
    "deception": [
        ResponseAction.BLOCK_NETWORK,
        ResponseAction.PRESERVE_EVIDENCE,
        ResponseAction.INVESTIGATE,
        ResponseAction.NOTIFY_SOC,
    ],
    "default": [
        ResponseAction.INVESTIGATE,
        ResponseAction.NOTIFY_SOC,
    ],
}


# ── Incident Response Engine ──────────────────────────────────────────────────

class IncidentResponseEngine:
    """
    Corrèle les alertes, ouvre des incidents, exécute des playbooks.

    Callbacks :
      on_incident_opened(incident)
      on_action_executed(incident, action, result)
      on_incident_updated(incident)
    """

    def __init__(
        self,
        on_incident_opened: Optional[Callable] = None,
        on_action_executed: Optional[Callable] = None,
        on_incident_updated: Optional[Callable] = None,
    ):
        self._on_opened   = on_incident_opened
        self._on_action   = on_action_executed
        self._on_updated  = on_incident_updated

        # Historique récent par agent : deque de (timestamp, alert_type)
        self._agent_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        # Incidents ouverts, indexés par id
        self._incidents: Dict[str, Incident] = {}
        # Incidents récents par agent (pour éviter les doublons)
        self._agent_incidents: Dict[str, Dict[str, float]] = defaultdict(dict)

        self._stats = {
            "alerts_processed": 0,
            "incidents_opened": 0,
            "actions_executed": 0,
        }

    # ── API publique ──────────────────────────────────────────────────────────

    async def process_alert(self, alert: Dict) -> Optional[Incident]:
        """Ingère une alerte et retourne un incident si déclenché."""
        self._stats["alerts_processed"] += 1
        agent_id   = alert.get("agent_id", "unknown")
        alert_type = alert.get("type", "UNKNOWN")
        ts         = alert.get("timestamp", time.time())

        # Historique
        self._agent_history[agent_id].append((ts, alert_type))

        # Tester chaque règle
        for rule in INCIDENT_RULES:
            incident = await self._evaluate_rule(rule, agent_id, alert)
            if incident:
                return incident
        return None

    def get_incidents(
        self,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict]:
        incidents = list(self._incidents.values())
        if status:
            incidents = [i for i in incidents if i.status.value == status]
        incidents.sort(key=lambda i: i.last_updated, reverse=True)
        return [i.to_dict() for i in incidents[:limit]]

    def get_incident(self, incident_id: str) -> Optional[Dict]:
        inc = self._incidents.get(incident_id)
        return inc.to_dict() if inc else None

    async def update_incident_status(
        self, incident_id: str, status: str, note: str = ""
    ) -> bool:
        inc = self._incidents.get(incident_id)
        if not inc:
            return False
        inc.status = IncidentStatus(status)
        if status == "closed":
            inc.resolved_at = time.time()
        inc.add_timeline("status_change", f"→ {status}" + (f" — {note}" if note else ""), auto=False)
        if self._on_updated:
            await self._maybe_await(self._on_updated(inc))
        return True

    def get_stats(self) -> Dict:
        return {
            **self._stats,
            "open_incidents": sum(1 for i in self._incidents.values()
                                  if i.status == IncidentStatus.OPEN),
            "critical_incidents": sum(1 for i in self._incidents.values()
                                      if i.severity == IncidentSeverity.CRITICAL
                                      and i.status != IncidentStatus.CLOSED),
        }

    # ── Logique interne ───────────────────────────────────────────────────────

    async def _evaluate_rule(
        self, rule: Dict, agent_id: str, trigger_alert: Dict
    ) -> Optional[Incident]:
        alert_type = trigger_alert.get("type", "")
        if alert_type not in rule["triggers"]:
            return None

        window = rule["window_s"]
        now = time.time()
        cutoff = now - window

        # Compter les types distincts dans la fenêtre
        history = self._agent_history[agent_id]
        seen_types = {t for ts, t in history if ts >= cutoff and t in rule["triggers"]}

        if len(seen_types) < rule["min_triggers"]:
            return None

        # Anti-doublon : même règle + agent dans les 5min
        rule_name = rule["name"]
        last = self._agent_incidents[agent_id].get(rule_name, 0)
        if now - last < 300:
            # Enrichir l'incident existant
            existing_id = f"{agent_id}:{rule_name}"
            if existing_id in self._incidents:
                inc = self._incidents[existing_id]
                inc.alert_count += 1
                inc.alerts.append(trigger_alert)
                inc.add_timeline("new_alert", f"{alert_type} sur {agent_id}")
                if self._on_updated:
                    await self._maybe_await(self._on_updated(inc))
            return None

        # Ouvrir un nouvel incident
        self._agent_incidents[agent_id][rule_name] = now
        incident = await self._open_incident(rule, agent_id, trigger_alert, seen_types)
        return incident

    async def _open_incident(
        self,
        rule: Dict,
        agent_id: str,
        trigger_alert: Dict,
        seen_types: set,
    ) -> Incident:
        incident_id = f"{agent_id}:{rule['name']}"
        title = f"[{rule['name'].replace('_', ' ')}] — {agent_id}"

        inc = Incident(
            id=incident_id,
            title=title,
            severity=rule["severity"],
            affected_agents=[agent_id],
            alert_count=1,
            kill_chain_phase=rule.get("kill_chain"),
            mitre_tactics=rule.get("mitre", []),
            playbook=rule.get("playbook", "default"),
            alerts=[trigger_alert],
        )
        inc.add_timeline(
            "incident_opened",
            f"Corrélation: {', '.join(seen_types)} en {rule['window_s']}s"
        )

        self._incidents[incident_id] = inc
        self._stats["incidents_opened"] += 1

        # Notifier
        if self._on_opened:
            await self._maybe_await(self._on_opened(inc))

        # Exécuter le playbook
        await self._run_playbook(inc, trigger_alert)

        return inc

    async def _run_playbook(self, incident: Incident, context_alert: Dict):
        playbook_name = incident.playbook or "default"
        actions = PLAYBOOKS.get(playbook_name, PLAYBOOKS["default"])
        incident.response_actions = [a.value for a in actions]

        for action in actions:
            result = await self._execute_action(action, incident, context_alert)
            incident.add_timeline(
                action.value,
                f"Exécuté: {result.get('status', 'ok')} — {result.get('detail', '')}",
            )
            self._stats["actions_executed"] += 1
            if self._on_action:
                await self._maybe_await(self._on_action(incident, action.value, result))

        incident.status = IncidentStatus.INVESTIGATING

    async def _execute_action(
        self, action: ResponseAction, incident: Incident, alert: Dict
    ) -> Dict:
        """
        Simulation des actions de réponse.
        En production, chaque action envoie une commande au GravityAgent
        via le canal WebSocket sécurisé (RCTC-signé).
        """
        agent_id = incident.affected_agents[0] if incident.affected_agents else "?"
        process  = alert.get("process", "?")
        pid      = alert.get("pid", 0)

        handlers = {
            ResponseAction.ISOLATE_AGENT:     {"status": "sent",  "detail": f"Agent {agent_id} mis en quarantaine réseau"},
            ResponseAction.KILL_PROCESS:      {"status": "sent",  "detail": f"SIGKILL envoyé à {process} (PID {pid})"},
            ResponseAction.BLOCK_NETWORK:     {"status": "sent",  "detail": f"Règles NAC activées sur {agent_id}"},
            ResponseAction.QUARANTINE_FILE:   {"status": "sent",  "detail": f"Fichier lié à {process} déplacé en quarantaine"},
            ResponseAction.PRESERVE_EVIDENCE: {"status": "done",  "detail": f"Snapshot mémoire + logs capturés sur {agent_id}"},
            ResponseAction.SNAPSHOT:          {"status": "done",  "detail": f"Image disque initiée sur {agent_id}"},
            ResponseAction.NOTIFY_SOC:        {"status": "done",  "detail": f"Incident {incident.id} notifié au SOC"},
            ResponseAction.ESCALATE:          {"status": "done",  "detail": "Escaladé vers analyste Tier-2"},
            ResponseAction.INVESTIGATE:       {"status": "done",  "detail": "Tâche d'investigation créée"},
        }
        return handlers.get(action, {"status": "unknown", "detail": "action non reconnue"})

    @staticmethod
    async def _maybe_await(coro):
        if asyncio.iscoroutine(coro):
            await coro
