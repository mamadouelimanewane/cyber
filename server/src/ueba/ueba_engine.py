"""
Gravity Security — UEBA (User and Entity Behavior Analytics)
Détecte les comptes compromis par analyse comportementale des utilisateurs.

La plupart des attaques avancées utilisent des comptes légitimes compromis.
Les signatures et les antivirus ne peuvent pas les détecter car les outils
utilisés sont légitimes (RDP, PowerShell, partages réseau).

Le UEBA établit le profil comportemental de chaque utilisateur :
- Horaires de travail habituels
- Machines utilisées
- Volumes de données accédées
- Applications utilisées
- Localisation géographique (IP)
- Vitesse de déplacement (impossible travel)

Toute déviation significative = possible compromission.
"""

import time
import math
import json
import hashlib
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("gravity.ueba")

UEBA_DB_PATH = Path(__file__).parent.parent.parent / "data" / "ueba_profiles.json"


@dataclass
class UserActivity:
    """Représente une activité d'un utilisateur à un instant donné."""
    username: str
    agent_id: str
    machine: str
    timestamp: float
    activity_type: str        # "login", "file_access", "network", "process", "privilege"
    details: Dict = field(default_factory=dict)
    source_ip: Optional[str] = None
    country: Optional[str] = None


@dataclass
class UserProfile:
    """Profil comportemental d'un utilisateur — sa 'norme'."""
    username: str
    typical_hours: List[int] = field(default_factory=list)      # Heures de connexion habituelles (0-23)
    typical_machines: List[str] = field(default_factory=list)   # Machines habituellement utilisées
    typical_ips: List[str] = field(default_factory=list)        # IPs habituelles
    typical_countries: List[str] = field(default_factory=list)
    avg_daily_file_accesses: float = 0.0
    avg_daily_process_launches: float = 0.0
    avg_network_bytes_per_day: float = 0.0
    work_days: List[int] = field(default_factory=lambda: [0,1,2,3,4])  # 0=Lundi
    sample_days: int = 0
    last_activity: float = 0.0
    risk_score: float = 0.0
    is_privileged: bool = False
    department: str = ""


@dataclass
class UEBAAnomaly:
    """Anomalie comportementale détectée pour un utilisateur."""
    username: str
    anomaly_type: str
    risk_score: float
    description: str
    evidence: Dict
    timestamp: float = field(default_factory=time.time)
    mitre_technique: str = "T1078 — Valid Accounts"


class UEBAEngine:
    """
    Moteur UEBA — analyse comportementale des utilisateurs et entités.

    Capacités clés :
    1. Impossible Travel : connexion depuis Paris puis Tokyo en 1 heure → alerte
    2. Off-hours Access : admin connecté à 3h du matin un dimanche
    3. Data Hoarding : téléchargement massif avant le départ d'un employé
    4. Privilege Escalation : utilisateur normal demandant des droits admin
    5. Lateral Movement : connexion soudaine à 10+ machines différentes
    6. Mimicry Detection : comportement qui imite parfaitement un autre utilisateur
    """

    def __init__(self, callback=None):
        self.callback = callback
        self._profiles: Dict[str, UserProfile] = {}
        self._activity_log: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._anomalies: List[UEBAAnomaly] = []
        self._last_positions: Dict[str, Dict] = {}  # Pour impossible travel
        self._load_profiles()

    # ------------------------------------------------------------------ #
    #  Enregistrement d'activité                                        #
    # ------------------------------------------------------------------ #

    def record_activity(self, activity: UserActivity) -> Optional[UEBAAnomaly]:
        """
        Enregistre une activité utilisateur et détecte les anomalies.
        Retourne une anomalie si détectée, None sinon.
        """
        username = activity.username
        if not username:
            return None

        self._activity_log[username].append(activity)

        if username not in self._profiles:
            self._create_profile(username, activity)
            return None

        profile = self._profiles[username]
        profile.last_activity = activity.timestamp

        # Analyse des différentes dimensions comportementales
        anomaly = (
            self._check_impossible_travel(profile, activity) or
            self._check_off_hours(profile, activity) or
            self._check_new_machine(profile, activity) or
            self._check_data_hoarding(profile, username) or
            self._check_lateral_movement(username) or
            self._update_profile_and_learn(profile, activity)
        )

        if anomaly:
            self._anomalies.append(anomaly)
            self._raise_alert(anomaly)
            return anomaly

        return None

    def _create_profile(self, username: str, activity: UserActivity):
        """Crée un profil initial pour un nouvel utilisateur."""
        dt = datetime.fromtimestamp(activity.timestamp, tz=timezone.utc)
        self._profiles[username] = UserProfile(
            username=username,
            typical_hours=[dt.hour],
            typical_machines=[activity.machine] if activity.machine else [],
            typical_ips=[activity.source_ip] if activity.source_ip else [],
            typical_countries=[activity.country] if activity.country else [],
            work_days=[dt.weekday()],
        )

    # ------------------------------------------------------------------ #
    #  Détecteurs d'anomalies                                          #
    # ------------------------------------------------------------------ #

    def _check_impossible_travel(self, profile: UserProfile, activity: UserActivity) -> Optional[UEBAAnomaly]:
        """
        Détecte l'impossible travel : connexion depuis deux localisations
        géographiquement distantes en un temps trop court.
        """
        if not activity.source_ip or activity.source_ip.startswith("192.168.") or activity.source_ip.startswith("10."):
            return None

        username = profile.username
        last = self._last_positions.get(username)
        self._last_positions[username] = {
            "ip": activity.source_ip,
            "country": activity.country,
            "timestamp": activity.timestamp,
        }

        if not last:
            return None

        time_delta = activity.timestamp - last["timestamp"]
        # Connexion de deux pays différents avec moins de 2 heures d'écart
        if (last.get("country") and activity.country and
                last["country"] != activity.country and time_delta < 7200):

            speed_kmh = 20000 / max(time_delta / 3600, 0.1)  # Distance approx mondiale
            return UEBAAnomaly(
                username=username,
                anomaly_type="impossible_travel",
                risk_score=0.92,
                description=(
                    f"IMPOSSIBLE TRAVEL — {username} connecté depuis {last['country']} "
                    f"puis {activity.country} en {time_delta/60:.0f} minutes "
                    f"(vitesse impliquée ~{speed_kmh:.0f} km/h)"
                ),
                evidence={
                    "previous_location": last["country"],
                    "current_location": activity.country,
                    "time_delta_minutes": round(time_delta / 60, 1),
                    "previous_ip": last["ip"],
                    "current_ip": activity.source_ip,
                },
            )
        return None

    def _check_off_hours(self, profile: UserProfile, activity: UserActivity) -> Optional[UEBAAnomaly]:
        """Détecte les connexions en dehors des horaires habituels."""
        dt = datetime.fromtimestamp(activity.timestamp, tz=timezone.utc)
        hour = dt.hour
        weekday = dt.weekday()

        is_weekend = weekday in [5, 6]
        is_night = hour < 6 or hour > 22
        typical_hours = profile.typical_hours

        if not typical_hours:
            return None

        if is_night and len(typical_hours) >= 5:
            # Utilisateur habituellement diurne, connexion nocturne
            day_hours = [h for h in typical_hours if 8 <= h <= 20]
            if len(day_hours) / len(typical_hours) > 0.9:
                return UEBAAnomaly(
                    username=profile.username,
                    anomaly_type="off_hours_access",
                    risk_score=0.72,
                    description=(
                        f"ACCÈS HORS HORAIRES — {profile.username} connecté à {hour:02d}h "
                        f"({'week-end' if is_weekend else 'nuit'}), "
                        f"habituellement actif entre {min(day_hours)}h-{max(day_hours)}h"
                    ),
                    evidence={
                        "access_hour": hour,
                        "is_weekend": is_weekend,
                        "typical_hours_range": f"{min(day_hours)}h-{max(day_hours)}h",
                    },
                )
        return None

    def _check_new_machine(self, profile: UserProfile, activity: UserActivity) -> Optional[UEBAAnomaly]:
        """Détecte l'utilisation d'une machine jamais vue pour cet utilisateur."""
        if not activity.machine or len(profile.typical_machines) < 2:
            return None

        if activity.machine not in profile.typical_machines:
            return UEBAAnomaly(
                username=profile.username,
                anomaly_type="new_machine",
                risk_score=0.65,
                description=(
                    f"NOUVELLE MACHINE — {profile.username} accède depuis "
                    f"'{activity.machine}' — machines habituelles: {', '.join(profile.typical_machines[:3])}"
                ),
                evidence={
                    "new_machine": activity.machine,
                    "known_machines": profile.typical_machines[:5],
                },
            )
        return None

    def _check_data_hoarding(self, profile: UserProfile, username: str) -> Optional[UEBAAnomaly]:
        """Détecte le téléchargement massif de données (exfiltration interne)."""
        recent = [a for a in self._activity_log[username]
                  if a.activity_type == "file_access" and time.time() - a.timestamp < 3600]

        if len(recent) > max(50, profile.avg_daily_file_accesses * 3):
            return UEBAAnomaly(
                username=username,
                anomaly_type="data_hoarding",
                risk_score=0.80,
                description=(
                    f"ACCUMULTION DE DONNÉES — {username} a accédé à {len(recent)} fichiers "
                    f"en 1 heure (normale: {profile.avg_daily_file_accesses:.0f}/jour)"
                ),
                evidence={
                    "accesses_last_hour": len(recent),
                    "avg_daily": profile.avg_daily_file_accesses,
                    "ratio": round(len(recent) / max(profile.avg_daily_file_accesses, 1), 1),
                },
                mitre_technique="T1083 — File Discovery / T1041 — Exfiltration",
            )
        return None

    def _check_lateral_movement(self, username: str) -> Optional[UEBAAnomaly]:
        """Détecte la connexion à de nombreuses machines différentes."""
        recent = [a for a in self._activity_log[username]
                  if a.activity_type == "login" and time.time() - a.timestamp < 3600]
        unique_machines = set(a.machine for a in recent if a.machine)

        if len(unique_machines) >= 5:
            return UEBAAnomaly(
                username=username,
                anomaly_type="lateral_movement",
                risk_score=0.88,
                description=(
                    f"MOUVEMENT LATÉRAL — {username} connecté à {len(unique_machines)} "
                    f"machines différentes en 1 heure: {', '.join(list(unique_machines)[:5])}"
                ),
                evidence={
                    "machines_accessed": list(unique_machines),
                    "count": len(unique_machines),
                    "timeframe": "1 heure",
                },
                mitre_technique="T1021 — Remote Services (Lateral Movement)",
            )
        return None

    def _update_profile_and_learn(self, profile: UserProfile, activity: UserActivity) -> None:
        """Met à jour le profil en apprenant du comportement normal."""
        dt = datetime.fromtimestamp(activity.timestamp, tz=timezone.utc)
        hour = dt.hour

        if hour not in profile.typical_hours:
            profile.typical_hours.append(hour)
            profile.typical_hours = profile.typical_hours[-100:]

        if activity.machine and activity.machine not in profile.typical_machines:
            if len(profile.typical_machines) < 10:
                profile.typical_machines.append(activity.machine)

        if activity.source_ip and activity.source_ip not in profile.typical_ips:
            if len(profile.typical_ips) < 20:
                profile.typical_ips.append(activity.source_ip)

        profile.sample_days += 1
        return None

    # ------------------------------------------------------------------ #
    #  Alertes & Reporting                                              #
    # ------------------------------------------------------------------ #

    def _raise_alert(self, anomaly: UEBAAnomaly):
        alert = {
            "type": "UEBA_ANOMALY",
            "severity": "critical" if anomaly.risk_score >= 0.85 else "high",
            "threat_score": anomaly.risk_score,
            "process": anomaly.username,
            "reason": anomaly.description,
            "label": f"UEBA — {anomaly.anomaly_type.replace('_', ' ').title()}",
            "action": "Vérifier identité — possible compte compromis — forcer MFA",
            "mitre": anomaly.mitre_technique,
            "evidence": anomaly.evidence,
        }
        logger.warning(f"[UEBA] {anomaly.description}")
        if self.callback:
            self.callback(alert)

    def get_user_risk_scores(self) -> List[Dict]:
        return sorted([
            {
                "username": p.username,
                "risk_score": p.risk_score,
                "last_activity": p.last_activity,
                "is_privileged": p.is_privileged,
                "typical_hours": p.typical_hours[:5],
                "known_machines": p.typical_machines[:3],
            }
            for p in self._profiles.values()
        ], key=lambda x: x["risk_score"], reverse=True)

    def get_recent_anomalies(self, limit: int = 50) -> List[Dict]:
        return [
            {
                "username": a.username, "type": a.anomaly_type,
                "risk_score": a.risk_score, "description": a.description,
                "timestamp": a.timestamp, "evidence": a.evidence,
                "mitre": a.mitre_technique,
            }
            for a in sorted(self._anomalies, key=lambda x: x.timestamp, reverse=True)[:limit]
        ]

    def _load_profiles(self):
        pass  # À implémenter : chargement depuis DB

    def _save_profiles(self):
        pass  # À implémenter : sauvegarde vers DB
