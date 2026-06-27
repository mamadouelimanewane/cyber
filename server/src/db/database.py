"""
Gravity Security — Base de données SQLite (dev) / PostgreSQL (prod)
Stockage des agents, alertes, et statistiques.
"""

import sqlite3
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger("gravity.db")

DB_PATH = Path(__file__).parent.parent.parent / "gravity.db"


class Database:
    def __init__(self, db_path: str = str(DB_PATH)):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def initialize(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                ip TEXT,
                hostname TEXT,
                os_info TEXT,
                registered_at REAL,
                last_seen REAL,
                stats TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT,
                type TEXT,
                severity TEXT DEFAULT 'medium',
                threat_score REAL DEFAULT 0,
                process TEXT,
                file TEXT,
                reason TEXT,
                details TEXT,
                received_at TEXT,
                timestamp REAL
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_agent ON alerts(agent_id);
            CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(type);
            CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);
        """)
        conn.commit()
        logger.info(f"Base de données initialisée: {self.db_path}")

    # ------------------------------------------------------------------ #
    #  Agents                                                            #
    # ------------------------------------------------------------------ #

    def register_agent(self, agent_id: str, ip: str, hostname: str, os_info: str) -> Dict:
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO agents (agent_id, ip, hostname, os_info, registered_at, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (agent_id, ip, hostname, os_info, time.time(), time.time()))
        conn.commit()
        return {"agent_id": agent_id, "ip": ip, "hostname": hostname}

    def update_agent_heartbeat(self, agent_id: str, stats: Dict):
        conn = self._get_conn()
        conn.execute("""
            UPDATE agents SET last_seen = ?, stats = ?
            WHERE agent_id = ?
        """, (time.time(), json.dumps(stats), agent_id))
        conn.commit()

    def get_all_agents(self) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
        agents = []
        for row in rows:
            a = dict(row)
            a["stats"] = json.loads(a.get("stats") or "{}")
            a["online"] = (time.time() - (a.get("last_seen") or 0)) < 60
            agents.append(a)
        return agents

    def get_online_agents(self) -> List[Dict]:
        return [a for a in self.get_all_agents() if a["online"]]

    def count_agents(self) -> int:
        conn = self._get_conn()
        return conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]

    # ------------------------------------------------------------------ #
    #  Alertes                                                           #
    # ------------------------------------------------------------------ #

    def save_alert(self, alert: Dict):
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO alerts (agent_id, type, severity, threat_score, process, file, reason, details, received_at, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.get("agent_id", ""),
            alert.get("type", "UNKNOWN"),
            alert.get("severity", "medium"),
            float(alert.get("threat_score", 0)),
            alert.get("process", ""),
            alert.get("file", ""),
            alert.get("reason", ""),
            json.dumps(alert),
            alert.get("received_at", datetime.utcnow().isoformat()),
            time.time(),
        ))
        conn.commit()

    def get_alerts(self, limit: int = 100, severity: Optional[str] = None, agent_id: Optional[str] = None) -> List[Dict]:
        conn = self._get_conn()
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        results = []
        for row in rows:
            a = dict(row)
            try:
                details = json.loads(a.get("details") or "{}")
                a.update({k: v for k, v in details.items() if k not in a})
            except Exception:
                pass
            results.append(a)
        return results

    def count_alerts_today(self) -> int:
        conn = self._get_conn()
        since = time.time() - 86400
        return conn.execute("SELECT COUNT(*) FROM alerts WHERE timestamp > ?", (since,)).fetchone()[0]

    def count_alerts_by_type(self) -> Dict[str, int]:
        conn = self._get_conn()
        rows = conn.execute("SELECT type, COUNT(*) as count FROM alerts GROUP BY type").fetchall()
        return {row["type"]: row["count"] for row in rows}

    def count_alerts_by_severity(self) -> Dict[str, int]:
        conn = self._get_conn()
        rows = conn.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity").fetchall()
        return {row["severity"]: row["count"] for row in rows}

    def get_top_threats(self, limit: int = 5) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT process, COUNT(*) as count, MAX(threat_score) as max_score
            FROM alerts WHERE process != ''
            GROUP BY process ORDER BY count DESC LIMIT ?
        """, (limit,)).fetchall()
        return [dict(row) for row in rows]

    def get_alerts_timeline(self, hours: int = 24) -> List[Dict]:
        """Nombre d'alertes par heure sur les N dernières heures."""
        conn = self._get_conn()
        since = time.time() - hours * 3600
        rows = conn.execute("""
            SELECT CAST((timestamp - ?) / 3600 AS INTEGER) as hour_offset,
                   COUNT(*) as count
            FROM alerts WHERE timestamp > ?
            GROUP BY hour_offset ORDER BY hour_offset
        """, (since, since)).fetchall()
        return [{"hour": row["hour_offset"], "count": row["count"]} for row in rows]

    def get_network_map(self) -> Dict:
        agents = self.get_all_agents()
        nodes = [{"id": a["agent_id"], "ip": a["ip"], "online": a["online"]} for a in agents]
        return {"nodes": nodes, "edges": []}
