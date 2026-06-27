"""
Gravity Security — Serveur d'Inférence ML
API FastAPI légère pour scoring en temps réel depuis l'agent.
"""

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any, List
import uvicorn
import logging
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "training"))
from anomaly_detector import AnomalyDetector, extract_features

logger = logging.getLogger("gravity.ml.server")
app = FastAPI(title="Gravity ML Inference", version="1.0.0")

detector = AnomalyDetector()
_loaded = detector.load()
if not _loaded:
    logger.warning("Modèle non trouvé — scoring ML désactivé (entraîner d'abord)")


class ProcessInput(BaseModel):
    threat_score: float = 0.0
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    connections: List[Any] = []
    children: List[Any] = []
    chain_depth: int = 0
    entropy: float = 0.0
    name: str = ""
    has_network: bool = False
    parent_is_office: bool = False


@app.post("/predict")
async def predict(data: ProcessInput):
    if not detector.is_trained:
        return {"is_anomaly": False, "anomaly_score": 0.0, "model_ready": False}
    is_anomaly, score = detector.predict(data.dict())
    return {"is_anomaly": is_anomaly, "anomaly_score": score, "model_ready": True}


@app.get("/health")
async def health():
    return {"status": "ok", "model_ready": detector.is_trained}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
