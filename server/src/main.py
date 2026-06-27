"""
Gravity Security — Serveur Central (FastAPI)
Orchestre les agents, stocke les alertes, expose l'API pour le dashboard.
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio
import json
import time
import logging
import uvicorn

from .db.database import Database
from .engine.threat_engine import ThreatEngine
from .api.routes import router
from .patent_orchestrator import PatentOrchestrator
from .cluster.bulk_processor import BulkProcessor
from .incident_response import IncidentResponseEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gravity.server")

app = FastAPI(
    title="Gravity Security — API Centrale",
    description="Serveur d'orchestration du système de cybersécurité Gravity",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Base de données et moteur de menaces
db = Database()
threat_engine = ThreatEngine()
patent_orchestrator = PatentOrchestrator()

# Incident Response Engine — corrélation + playbooks automatiques
async def _on_incident_opened(incident):
    await _broadcast_ws({"event": "incident_opened", "incident": incident.to_dict()})
    logger.warning(f"[INCIDENT] {incident.severity.value.upper()} — {incident.title}")

ire = IncidentResponseEngine(
    on_incident_opened=_on_incident_opened,
    on_incident_updated=lambda inc: _broadcast_ws({"event": "incident_updated", "incident": inc.to_dict()}),
)

# WebSocket connections pour le dashboard temps réel
ws_clients: List[WebSocket] = []

# BulkProcessor — traitement haute performance pour 10 000 agents
bulk_processor = BulkProcessor(
    on_critical=lambda alert: _broadcast_ws({"event": "new_alert", "alert": alert}),
    on_patent_enrich=_ire_enrich,
    on_bulk_save=lambda alerts: asyncio.get_event_loop().run_in_executor(
        None, db.save_alerts_bulk, alerts
    ),
)


# ------------------------------------------------------------------ #
#  Modèles Pydantic                                                  #
# ------------------------------------------------------------------ #

class HeartbeatPayload(BaseModel):
    agent_id: str
    type: str
    timestamp: float
    stats: Dict[str, Any] = {}


class AlertsPayload(BaseModel):
    agent_id: str
    alerts: List[Dict[str, Any]]


class AgentRegistration(BaseModel):
    agent_id: str
    ip: str
    hostname: str
    os: str = ""
    version: str = "1.0.0"


# ------------------------------------------------------------------ #
#  Endpoints principaux                                              #
# ------------------------------------------------------------------ #

@app.get("/")
async def root():
    return {
        "product": "Gravity Security",
        "version": "1.0.0",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "agents_online": len(db.get_online_agents()),
        "alerts_today": db.count_alerts_today(),
        "uptime": time.time() - app.state.start_time,
    }


@app.post("/api/agents/register")
async def register_agent(payload: AgentRegistration):
    """Enregistre un nouvel agent dans le système."""
    agent = db.register_agent(
        agent_id=payload.agent_id,
        ip=payload.ip,
        hostname=payload.hostname,
        os_info=payload.os,
    )
    logger.info(f"Agent enregistré: {payload.agent_id} ({payload.ip})")
    await _broadcast_ws({"event": "agent_registered", "agent": payload.agent_id})
    return {"status": "registered", "agent_id": payload.agent_id}


@app.post("/api/agents/heartbeat")
async def heartbeat(payload: HeartbeatPayload):
    """Reçoit le heartbeat d'un agent — met à jour son statut."""
    db.update_agent_heartbeat(payload.agent_id, payload.stats)
    # Ingestion des stats brevets dans l'orchestrateur
    if "patent" in payload.stats:
        patent_orchestrator.ingest_heartbeat(payload.agent_id, payload.stats["patent"])
    return {"status": "ok", "server_time": time.time()}


@app.post("/api/alerts")
async def receive_alerts(payload: AlertsPayload):
    """Reçoit les alertes d'un agent et les analyse."""
    processed = []
    for alert in payload.alerts:
        alert["agent_id"] = payload.agent_id
        alert["received_at"] = datetime.utcnow().isoformat()

        # Analyse par le moteur de menaces
        enriched = threat_engine.enrich(alert)
        db.save_alert(enriched)
        processed.append(enriched)

        # Diffusion temps réel au dashboard
        await _broadcast_ws({"event": "new_alert", "alert": enriched})

    logger.info(f"Reçu {len(processed)} alertes de {payload.agent_id}")
    return {"status": "ok", "processed": len(processed)}


@app.get("/api/alerts")
async def get_alerts(
    limit: int = 100,
    severity: Optional[str] = None,
    agent_id: Optional[str] = None,
):
    """Retourne les alertes récentes filtrées."""
    return db.get_alerts(limit=limit, severity=severity, agent_id=agent_id)


@app.get("/api/agents")
async def get_agents():
    """Retourne tous les agents et leur statut."""
    return db.get_all_agents()


@app.get("/api/stats")
async def get_stats():
    """Statistiques globales pour le dashboard."""
    return {
        "total_agents": db.count_agents(),
        "online_agents": len(db.get_online_agents()),
        "alerts_today": db.count_alerts_today(),
        "alerts_by_type": db.count_alerts_by_type(),
        "alerts_by_severity": db.count_alerts_by_severity(),
        "top_threats": db.get_top_threats(limit=5),
        "timeline": db.get_alerts_timeline(hours=24),
    }


@app.get("/api/network/map")
async def get_network_map():
    """Carte du réseau avec les agents et leurs connexions."""
    return db.get_network_map()


# ── Endpoints Algorithmes Brevetables ─────────────────────────────────────────

@app.get("/api/patent/status")
async def patent_status():
    """Vue globale de tous les algorithmes brevetables."""
    return patent_orchestrator.get_global_status()


@app.get("/api/patent/alerts")
async def patent_alerts(limit: int = 50, alert_type: Optional[str] = None):
    """Alertes générées exclusivement par les modules brevets."""
    return patent_orchestrator.get_patent_alerts(limit=limit, alert_type=alert_type)


@app.get("/api/patent/qbsm")
async def qbsm_landscape():
    """Paysage quantique QBSM de tous les processus surveillés."""
    return patent_orchestrator.get_qbsm_landscape()


@app.get("/api/patent/rctc")
async def rctc_trust_tree():
    """Arbre de confiance cryptographique RCTC."""
    return patent_orchestrator.get_rctc_trust_tree()


@app.post("/api/patent/network-event")
async def ingest_network_event(event: Dict[str, Any]):
    """Reçoit un événement réseau d'un agent pour analyse ASN."""
    patent_orchestrator.ingest_network_event(event)
    return {"status": "ok"}


@app.post("/api/patent/alert")
async def receive_patent_alert(alert: Dict[str, Any]):
    """Reçoit une alerte générée par un brevet (QBSM collapse, CBGA genome match…)."""
    patent_orchestrator.ingest_patent_alert(alert)
    await _broadcast_ws({"event": "patent_alert", "alert": alert})
    return {"status": "ok"}


# ── Endpoints Scale 10 000 agents ─────────────────────────────────────────────

@app.post("/api/alerts/bulk")
async def receive_bulk_alerts(request: Request):
    """
    Endpoint haute performance pour les collectors régionaux.
    Reçoit des batches compressés de centaines d'alertes à la fois.
    Cible : 10 000 agents × 2 alertes/min = 333 alertes/sec.
    """
    body = await request.body()
    encoding = request.headers.get("Content-Encoding", "")
    collector_id = request.headers.get("X-Collector-ID", "direct-agent")

    result = await bulk_processor.ingest_bulk(body, encoding, collector_id)
    return result


@app.get("/api/scale/status")
async def scale_status():
    """Vue d'ensemble de la capacité et de la charge actuelle."""
    bulk_stats = bulk_processor.get_stats()
    return {
        "architecture": "3-tier (agents → collectors → cluster)",
        "target_capacity": "10 000 agents",
        "bulk_processor": bulk_stats,
        "collectors": bulk_processor.collectors,
        "db_backend": "PostgreSQL (prod) / SQLite (dev)",
        "recommendations": _get_scale_recommendations(bulk_stats),
    }


@app.get("/api/scale/collectors")
async def get_collectors():
    """Liste tous les collectors connectés et leur statut."""
    return {
        "collectors": bulk_processor.collectors,
        "total": len(bulk_processor.collectors),
        "online": sum(1 for c in bulk_processor.collectors.values() if c.get("online")),
    }


def _get_scale_recommendations(stats: Dict) -> List[str]:
    """Génère des recommandations d'échelle basées sur la charge actuelle."""
    recs = []
    rps = stats.get("throughput_rps", 0)
    if rps > 500:
        recs.append("Ajouter un nœud FastAPI supplémentaire (load balancer Nginx)")
    if stats.get("queue", {}).get("normal_pending", 0) > 10_000:
        recs.append("Augmenter BULK_FLUSH_INTERVAL ou ajouter un worker DB")
    if len(bulk_processor.collectors) > 15:
        recs.append("Passer à Kafka pour le bus de messages inter-collectors")
    if rps < 50:
        recs.append("Capacité nominale — aucune action requise")
    return recs or ["Système nominal"]


# Import manquant pour le nouveau endpoint bulk
from fastapi import Request


# ------------------------------------------------------------------ #
#  WebSocket — Dashboard temps réel                                  #
# ------------------------------------------------------------------ #

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    ws_clients.append(websocket)
    logger.info(f"Dashboard connecté ({len(ws_clients)} clients)")
    try:
        # Envoyer l'état initial
        initial_state = {
            "event": "initial_state",
            "agents": db.get_all_agents(),
            "recent_alerts": db.get_alerts(limit=20),
            "stats": {
                "online_agents": len(db.get_online_agents()),
                "alerts_today": db.count_alerts_today(),
            },
        }
        await websocket.send_text(json.dumps(initial_state))
        while True:
            await websocket.receive_text()  # Keep-alive
    except WebSocketDisconnect:
        ws_clients.remove(websocket)
        logger.info(f"Dashboard déconnecté ({len(ws_clients)} clients)")


async def _broadcast_ws(message: Dict):
    """Diffuse un message à tous les clients WebSocket connectés."""
    if not ws_clients:
        return
    text = json.dumps(message, default=str)
    dead = []
    for ws in ws_clients:
        try:
            await ws.send_text(text)
        except Exception:
            dead.append(ws)
    for ws in dead:
        ws_clients.remove(ws)


# ------------------------------------------------------------------ #
#  Incident Response Engine — Endpoints                             #
# ------------------------------------------------------------------ #

@app.get("/api/incidents")
async def get_incidents(status: Optional[str] = None, limit: int = 100):
    return ire.get_incidents(status=status, limit=limit)


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    inc = ire.get_incident(incident_id)
    if not inc:
        return {"error": "incident not found"}
    return inc


@app.post("/api/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, request: Dict):
    ok = await ire.update_incident_status(
        incident_id,
        request.get("status", "investigating"),
        request.get("note", ""),
    )
    return {"success": ok}


@app.get("/api/incidents/stats/summary")
async def get_incident_stats():
    return ire.get_stats()


# ── Brancher IRE sur le flux d'alertes du BulkProcessor ─────────────────────

async def _ire_enrich(alerts: List[Dict]) -> List[Dict]:
    for alert in alerts:
        incident = await ire.process_alert(alert)
        if incident:
            alert["incident_id"] = incident.id
            alert["incident_severity"] = incident.severity.value
    return alerts


# ------------------------------------------------------------------ #
#  Démarrage                                                        #
# ------------------------------------------------------------------ #

@app.on_event("startup")
async def startup():
    app.state.start_time = time.time()
    db.initialize()
    await bulk_processor.start()
    logger.info("Gravity Security Server démarré — mode 10 000 agents activé")


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
