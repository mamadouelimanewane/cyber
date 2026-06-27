"""
Gravity Regional Collector — Niveau 2 de l'architecture 3-tier.

Rôle : Servir de concentrateur entre 500-1000 agents et le cluster central.
  - Reçoit les batches d'alertes des agents (HTTP + UDP heartbeats)
  - Décompresse, valide, re-batche pour le serveur central
  - Agrège les heartbeats (10k→1k→1 réduction de charge)
  - Pré-filtre : supprime les alertes sous seuil de sévérité configurable
  - Géo-distribution : chaque région/datacenter a son propre collector
  - Failover : si serveur central down, stocke localement (SQLite léger)

Topologie typique 10 000 machines :
  200 bureaux × 50 machines → 200 micro-collectors (1 VM 2 vCPU)
  ou
  20 régions × 500 machines → 20 collectors (1 VM 4 vCPU)
  → 1 cluster serveur central (3-5 FastAPI + PostgreSQL + Redis)
"""

import asyncio
import gzip
import hashlib
import json
import logging
import sqlite3
import socket
import threading
import time
import zlib
from collections import defaultdict
from typing import Dict, List, Optional

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
import uvicorn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [COLLECTOR] %(levelname)s — %(message)s"
)
logger = logging.getLogger("gravity.collector")

# ── Config ────────────────────────────────────────────────────────────────────
import os

COLLECTOR_ID       = os.getenv("COLLECTOR_ID", "collector-eu-west-1")
CENTRAL_URL        = os.getenv("CENTRAL_URL", "http://localhost:8000")
SHARED_SECRET      = os.getenv("SHARED_SECRET", "gravity-security-secret-change-me")
MAX_AGENTS         = int(os.getenv("MAX_AGENTS", "1000"))
FLUSH_INTERVAL     = float(os.getenv("FLUSH_INTERVAL", "3.0"))   # Flush vers central toutes les 3s
MIN_SEVERITY       = float(os.getenv("MIN_SEVERITY", "0.0"))       # Filtre alertes < seuil
UDP_PORT_OFFSET    = int(os.getenv("UDP_PORT_OFFSET", "1"))        # UDP = TCP+1
LOCAL_DB           = os.getenv("LOCAL_DB", "collector_buffer.db")

# ── Application ───────────────────────────────────────────────────────────────
app = FastAPI(title=f"Gravity Collector — {COLLECTOR_ID}", version="1.0.0")

# Buffer central
_alert_buffer: List[Dict] = []
_buffer_lock = asyncio.Lock()

# Registre des agents connectés à ce collector
_agent_registry: Dict[str, Dict] = {}   # agent_id → {last_seen, stats}
_hb_registry: Dict[str, Dict] = {}      # Heartbeats UDP

# Stats
_stats = {
    "received": 0,
    "forwarded": 0,
    "filtered": 0,
    "duplicates": 0,
    "bytes_in": 0,
    "bytes_forwarded": 0,
    "agents_seen": set(),
    "started_at": time.time(),
}

# Déduplication locale
_dedup_cache: Dict[str, float] = {}
_DEDUP_WINDOW = 15.0


def _is_duplicate(alert: Dict) -> bool:
    key = hashlib.md5(
        f"{alert.get('type')}|{alert.get('pid')}|{alert.get('process')}".encode()
    ).hexdigest()
    now = time.time()
    if key in _dedup_cache and (now - _dedup_cache[key]) < _DEDUP_WINDOW:
        return True
    _dedup_cache[key] = now
    if len(_dedup_cache) > 50_000:
        # Nettoyage : supprimer les entrées expirées
        expired = [k for k, v in _dedup_cache.items() if now - v > _DEDUP_WINDOW]
        for k in expired:
            del _dedup_cache[k]
    return False


# ── Endpoints agents ──────────────────────────────────────────────────────────

@app.post("/collect/alerts")
async def collect_alerts(request: Request, background_tasks: BackgroundTasks):
    """Reçoit un batch d'alertes compressé d'un agent."""
    # Vérifier token
    token = request.headers.get("X-Gravity-Token", "")
    agent_id = request.headers.get("X-Gravity-Agent", "unknown")

    # Décompression si nécessaire
    body = await request.body()
    _stats["bytes_in"] += len(body)

    encoding = request.headers.get("Content-Encoding", "")
    if encoding == "zlib":
        try:
            body = zlib.decompress(body)
        except Exception as e:
            raise HTTPException(400, f"Décompression zlib échouée: {e}")
    elif encoding == "gzip":
        try:
            body = gzip.decompress(body)
        except Exception as e:
            raise HTTPException(400, f"Décompression gzip échouée: {e}")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"JSON invalide: {e}")

    alerts = payload.get("alerts", [])
    if not alerts:
        return {"status": "ok", "accepted": 0}

    # Validation légère du token
    expected = hashlib.sha256(f"{agent_id}:{SHARED_SECRET}".encode()).hexdigest()[:32]
    if token and token != expected:
        logger.warning(f"Token invalide de {agent_id}")
        raise HTTPException(403, "Token invalide")

    # Mise à jour du registre agent
    _agent_registry[agent_id] = {
        "last_seen": time.time(),
        "alerts_received": _agent_registry.get(agent_id, {}).get("alerts_received", 0) + len(alerts),
    }
    _stats["agents_seen"].add(agent_id)
    _stats["received"] += len(alerts)

    # Filtrage + déduplication
    accepted = []
    for alert in alerts:
        # Filtre sévérité
        if alert.get("threat_score", 1.0) < MIN_SEVERITY:
            _stats["filtered"] += 1
            continue
        # Déduplication inter-agents
        if _is_duplicate(alert):
            _stats["duplicates"] += 1
            continue
        alert["_collector"] = COLLECTOR_ID
        accepted.append(alert)

    # Ajout au buffer
    async with _buffer_lock:
        _alert_buffer.extend(accepted)

    # Flush si buffer grand
    if len(_alert_buffer) >= 200:
        background_tasks.add_task(_flush_to_central)

    return {"status": "ok", "accepted": len(accepted), "filtered": len(alerts) - len(accepted)}


@app.get("/collect/status")
async def collector_status():
    """Statut du collector — utilisé par le serveur central pour monitoring."""
    return {
        "collector_id": COLLECTOR_ID,
        "central_url": CENTRAL_URL,
        "agents_connected": len(_agent_registry),
        "max_agents": MAX_AGENTS,
        "buffer_size": len(_alert_buffer),
        "stats": {
            **_stats,
            "agents_seen": len(_stats["agents_seen"]),
            "uptime_seconds": time.time() - _stats["started_at"],
        },
        "agents": [
            {
                "id": aid,
                "last_seen_ago": round(time.time() - info["last_seen"], 1),
                "online": (time.time() - info["last_seen"]) < 30,
                "alerts_received": info.get("alerts_received", 0),
            }
            for aid, info in sorted(
                _agent_registry.items(),
                key=lambda x: x[1]["last_seen"], reverse=True
            )[:100]
        ],
    }


@app.get("/health")
async def health():
    return {"status": "ok", "id": COLLECTOR_ID, "ts": time.time()}


# ── Flush vers le serveur central ─────────────────────────────────────────────

async def _flush_to_central():
    """Envoie le batch accumulé au serveur central."""
    import urllib.request

    async with _buffer_lock:
        if not _alert_buffer:
            return
        batch = list(_alert_buffer)
        _alert_buffer.clear()

    payload = {
        "collector_id": COLLECTOR_ID,
        "agent_id": COLLECTOR_ID,  # Compat avec l'API existante
        "alerts": batch,
        "count": len(batch),
        "ts": time.time(),
    }

    data = json.dumps(payload, default=str).encode("utf-8")
    compressed = zlib.compress(data, level=6)

    try:
        req = urllib.request.Request(
            f"{CENTRAL_URL}/api/alerts/bulk",
            data=compressed,
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "zlib",
                "X-Collector-ID": COLLECTOR_ID,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                _stats["forwarded"] += len(batch)
                _stats["bytes_forwarded"] += len(compressed)
                logger.info(
                    f"Flush → central: {len(batch)} alertes "
                    f"({len(compressed):,}B compressé)"
                )
                return
    except Exception as e:
        logger.warning(f"Erreur flush central: {e} — sauvegarde locale")
        _save_to_local_db(batch)


def _save_to_local_db(alerts: List[Dict]):
    """Sauvegarde locale si le serveur central est indisponible."""
    try:
        conn = sqlite3.connect(LOCAL_DB)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT NOT NULL,
                ts REAL NOT NULL
            )
        """)
        conn.execute(
            "INSERT INTO pending_alerts (data, ts) VALUES (?, ?)",
            (json.dumps(alerts, default=str), time.time())
        )
        conn.commit()
        conn.close()
        logger.info(f"Sauvegarde locale: {len(alerts)} alertes dans {LOCAL_DB}")
    except Exception as e:
        logger.error(f"Erreur DB locale: {e}")


async def _retry_local_db():
    """Réessaie d'envoyer les alertes sauvegardées localement."""
    import urllib.request
    try:
        conn = sqlite3.connect(LOCAL_DB)
        rows = conn.execute(
            "SELECT id, data FROM pending_alerts ORDER BY ts LIMIT 10"
        ).fetchall()
        if not rows:
            conn.close()
            return
        for row_id, data in rows:
            alerts = json.loads(data)
            async with _buffer_lock:
                _alert_buffer.extend(alerts)
            conn.execute("DELETE FROM pending_alerts WHERE id = ?", (row_id,))
        conn.commit()
        conn.close()
        logger.info(f"Récupération DB locale: {len(rows)} batches")
    except Exception:
        pass


# ── Flush périodique ──────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    asyncio.create_task(_periodic_flush())
    asyncio.create_task(_udp_listener())
    logger.info(f"Collector {COLLECTOR_ID} démarré — max {MAX_AGENTS} agents")
    logger.info(f"Central: {CENTRAL_URL} | Flush: {FLUSH_INTERVAL}s")


async def _periodic_flush():
    while True:
        await asyncio.sleep(FLUSH_INTERVAL)
        await _flush_to_central()
        await _retry_local_db()


async def _udp_listener():
    """Écoute les heartbeats UDP des agents (léger, non bloquant)."""
    loop = asyncio.get_event_loop()
    port = 8001  # UDP sur port HTTP+1 par défaut

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", port))
        sock.setblocking(False)
        logger.info(f"UDP heartbeat listener sur port {port}")

        while True:
            try:
                data = await loop.sock_recv(sock, 1024)
                hb = json.loads(data.decode())
                aid = hb.get("id", "unknown")
                _hb_registry[aid] = {
                    "last_udp": time.time(),
                    "queue": hb.get("q", 0),
                    "sent": hb.get("s", 0),
                }
                # Mise à jour rapide du registre sans lock lourd
                if aid not in _agent_registry:
                    _agent_registry[aid] = {"last_seen": time.time(), "alerts_received": 0}
                else:
                    _agent_registry[aid]["last_seen"] = time.time()
            except (BlockingIOError, json.JSONDecodeError):
                await asyncio.sleep(0.01)
            except Exception as e:
                logger.debug(f"UDP error: {e}")
                await asyncio.sleep(0.1)
    except Exception as e:
        logger.warning(f"UDP listener impossible: {e}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Gravity Regional Collector")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--id", default=COLLECTOR_ID)
    parser.add_argument("--central", default=CENTRAL_URL)
    args = parser.parse_args()

    COLLECTOR_ID = args.id
    CENTRAL_URL = args.central

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
