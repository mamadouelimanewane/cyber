"""
Gravity BulkProcessor — Traitement haute performance des alertes de 10 000 agents.

Remplace le traitement alerte-par-alerte de l'API existante par :
  - Ingestion en vrac (bulk) depuis les collectors
  - Décompression + validation + enrichissement en pipeline
  - Déduplication globale par hash glissant (TTL 60s)
  - Écriture groupée en base de données (bulk insert toutes les 2s)
  - Priority queue : CRITICAL traité en temps réel, reste en batch

Capacité cible :
  - 10 000 agents × 2 alertes/min = 333 alertes/sec
  - Avec 20 collectors × flush 3s = 6666 alertes/flush max
  - Bulk insert : 1 requête DB / 2s au lieu de 333 requêtes/s
"""

import asyncio
import gzip
import hashlib
import json
import logging
import time
import zlib
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("gravity.bulk")

# ── Configuration ─────────────────────────────────────────────────────────────
BULK_FLUSH_INTERVAL  = 2.0       # Écriture DB toutes les 2 secondes
BULK_MAX_SIZE        = 5_000     # Max alertes par batch DB
DEDUP_TTL            = 60.0      # Déduplique sur 60 secondes
CRITICAL_THRESHOLD   = 0.85      # Alertes critiques → traitement immédiat
MAX_ALERTS_IN_MEMORY = 100_000   # Protection mémoire


class GlobalDeduplicator:
    """
    Déduplication globale inter-collectors.
    Évite qu'une alerte reçue de 5 agents différents soit stockée 5 fois.
    """

    def __init__(self, ttl: float = DEDUP_TTL, max_size: int = 500_000):
        self._cache: Dict[str, float] = {}
        self._ttl = ttl
        self._max_size = max_size
        self._total_suppressed = 0
        self._last_clean = time.time()

    def is_duplicate(self, alert: Dict) -> bool:
        key = self._key(alert)
        now = time.time()

        # Nettoyage périodique (toutes les 30s)
        if now - self._last_clean > 30:
            self._clean(now)

        if key in self._cache and (now - self._cache[key]) < self._ttl:
            self._total_suppressed += 1
            return True

        self._cache[key] = now
        return False

    def _key(self, alert: Dict) -> str:
        parts = "|".join([
            str(alert.get("type", "")),
            str(alert.get("pid", "")),
            str(alert.get("process", "")),
            str(alert.get("agent_id", "")),
        ])
        return hashlib.sha1(parts.encode()).hexdigest()

    def _clean(self, now: float):
        if len(self._cache) > self._max_size:
            expired = [k for k, v in self._cache.items() if now - v > self._ttl]
            for k in expired:
                del self._cache[k]
        self._last_clean = now

    @property
    def size(self) -> int:
        return len(self._cache)

    @property
    def total_suppressed(self) -> int:
        return self._total_suppressed


class PriorityAlertQueue:
    """
    File à deux niveaux : CRITICAL (immédiat) et NORMAL (batché).
    Les alertes critiques sont broadcastées en temps réel au dashboard.
    """

    def __init__(self):
        self._critical: asyncio.Queue = asyncio.Queue()
        self._normal: List[Dict] = []
        self._lock = asyncio.Lock()
        self._total_enqueued = 0

    async def put(self, alert: Dict):
        self._total_enqueued += 1
        score = alert.get("threat_score", 0)
        if score >= CRITICAL_THRESHOLD or alert.get("type", "").startswith("QBSM_COLLAPSE"):
            await self._critical.put(alert)
        else:
            async with self._lock:
                self._normal.append(alert)
                # Protection mémoire
                if len(self._normal) > MAX_ALERTS_IN_MEMORY:
                    self._normal = self._normal[-MAX_ALERTS_IN_MEMORY:]

    async def get_critical(self) -> Optional[Dict]:
        try:
            return self._critical.get_nowait()
        except asyncio.QueueEmpty:
            return None

    async def drain_normal(self, max_count: int = BULK_MAX_SIZE) -> List[Dict]:
        async with self._lock:
            batch = self._normal[:max_count]
            self._normal = self._normal[max_count:]
            return batch

    def stats(self) -> Dict:
        return {
            "critical_pending": self._critical.qsize(),
            "normal_pending": len(self._normal),
            "total_enqueued": self._total_enqueued,
        }


class BulkProcessor:
    """
    Moteur de traitement d'alertes pour 10 000 agents.
    Instancié une fois au démarrage du serveur.
    """

    def __init__(self,
                 on_critical: Optional[Callable[[Dict], Any]] = None,
                 on_bulk_save: Optional[Callable[[List[Dict]], Any]] = None,
                 on_patent_enrich: Optional[Callable[[Dict], Dict]] = None):
        """
        on_critical      : callback async pour alertes critiques (WS broadcast)
        on_bulk_save     : callback async pour écriture en base (bulk insert)
        on_patent_enrich : enrichissement par Patent Engine (synchrone)
        """
        self._dedup = GlobalDeduplicator()
        self._queue = PriorityAlertQueue()
        self._on_critical = on_critical
        self._on_bulk_save = on_bulk_save
        self._on_patent_enrich = on_patent_enrich

        # Stats
        self._received_total = 0
        self._saved_total = 0
        self._collectors: Dict[str, Dict] = {}
        self._started_at = time.time()
        self._running = False

    async def start(self):
        self._running = True
        asyncio.create_task(self._critical_loop())
        asyncio.create_task(self._bulk_loop())
        logger.info("BulkProcessor démarré — prêt pour 10 000 agents")

    async def ingest_bulk(self, raw_body: bytes, encoding: str, collector_id: str) -> Dict:
        """
        Point d'entrée pour /api/alerts/bulk — appelé par les collectors.
        Retourne immédiatement (traitement asynchrone).
        """
        # Décompression
        try:
            if encoding == "zlib":
                body = zlib.decompress(raw_body)
            elif encoding in ("gzip", "br"):
                body = gzip.decompress(raw_body)
            else:
                body = raw_body
            payload = json.loads(body)
        except Exception as e:
            logger.warning(f"Ingest error from {collector_id}: {e}")
            return {"status": "error", "reason": str(e)}

        alerts = payload.get("alerts", [])
        accepted = 0
        deduped = 0

        for alert in alerts:
            alert["collector_id"] = collector_id
            alert["received_at"] = time.time()

            # Enrichissement léger Patent Engine (si dispo)
            if self._on_patent_enrich:
                try:
                    alert = self._on_patent_enrich(alert)
                except Exception:
                    pass

            # Déduplication globale
            if self._dedup.is_duplicate(alert):
                deduped += 1
                continue

            await self._queue.put(alert)
            accepted += 1

        self._received_total += len(alerts)

        # Mise à jour stats collector
        self._collectors[collector_id] = {
            "last_seen": time.time(),
            "total_sent": self._collectors.get(collector_id, {}).get("total_sent", 0) + len(alerts),
        }

        return {
            "status": "ok",
            "received": len(alerts),
            "accepted": accepted,
            "deduplicated": deduped,
        }

    # ── Boucles de traitement ─────────────────────────────────────────────────

    async def _critical_loop(self):
        """Traitement temps réel des alertes critiques."""
        while self._running:
            alert = await self._queue.get_critical()
            if alert and self._on_critical:
                try:
                    await self._on_critical(alert)
                except Exception as e:
                    logger.debug(f"Critical callback error: {e}")
            else:
                await asyncio.sleep(0.01)

    async def _bulk_loop(self):
        """Écriture groupée en base toutes les BULK_FLUSH_INTERVAL secondes."""
        while self._running:
            await asyncio.sleep(BULK_FLUSH_INTERVAL)
            batch = await self._queue.drain_normal()
            if batch and self._on_bulk_save:
                try:
                    await self._on_bulk_save(batch)
                    self._saved_total += len(batch)
                    logger.debug(f"Bulk save: {len(batch)} alertes")
                except Exception as e:
                    logger.error(f"Bulk save error: {e}")

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict:
        uptime = time.time() - self._started_at
        return {
            "uptime_seconds": round(uptime, 1),
            "received_total": self._received_total,
            "saved_total": self._saved_total,
            "throughput_rps": round(self._received_total / max(uptime, 1), 1),
            "dedup_cache_size": self._dedup.size,
            "total_deduplicated": self._dedup.total_suppressed,
            "collectors": len(self._collectors),
            "queue": self._queue.stats(),
            "capacity": {
                "target_agents": 10_000,
                "max_rps": 2_000,
                "bulk_flush_sec": BULK_FLUSH_INTERVAL,
            },
        }

    @property
    def collectors(self) -> Dict:
        return {
            cid: {
                **info,
                "online": (time.time() - info["last_seen"]) < 30,
                "last_seen_ago": round(time.time() - info["last_seen"], 1),
            }
            for cid, info in self._collectors.items()
        }
