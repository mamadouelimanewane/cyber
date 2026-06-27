"""
Tests — Supply Chain Monitor + Scale Architecture (BatchReporter, BulkProcessor)
"""
import hashlib
import json
import sys
import os
import time
import threading
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server", "src"))

MASTER_KEY = hashlib.sha256(b"gravity-scale-test").digest()

# ─────────────────────────────────────────────────────────────────────────────
# SUPPLY CHAIN MONITOR
# ─────────────────────────────────────────────────────────────────────────────
from supply_chain.supply_chain_monitor import (
    SupplyChainMonitor, levenshtein, is_typosquat
)


def test_sc_levenshtein_identical():
    assert levenshtein("requests", "requests") == 0
    print("PASS: SC levenshtein identical = 0")


def test_sc_levenshtein_one_typo():
    assert levenshtein("requests", "requsets") == 2  # transposition = 2 ops
    d = levenshtein("numpy", "numpi")
    assert d == 1
    print(f"PASS: SC levenshtein typo: numpy/numpi={d}")


def test_sc_typosquat_detected():
    similar = is_typosquat("reqeusts")  # requests avec inversion
    assert similar == "requests", f"Expected 'requests', got {similar}"
    print(f"PASS: SC typosquat detected: reqeusts → {similar}")


def test_sc_legitimate_package_not_flagged():
    similar = is_typosquat("numpy")
    assert similar is None
    print("PASS: SC legitimate package not flagged: numpy → None")


def test_sc_dll_hijack_detected():
    alerts = []
    monitor = SupplyChainMonitor(MASTER_KEY, on_alert=lambda a: alerts.append(a))

    # DLL chargée depuis bureau utilisateur — suspect
    alert = monitor.check_dll_load(
        pid=1234, process="notepad.exe",
        dll_path="C:\\Users\\admin\\Desktop\\evil.dll"
    )
    assert alert is not None
    assert alert.attack_type == "DLL_HIJACK"
    assert alert.severity >= 0.8
    print(f"PASS: SC DLL hijack detected: score={alert.severity}")


def test_sc_legitimate_dll_not_flagged():
    alerts = []
    monitor = SupplyChainMonitor(MASTER_KEY, on_alert=lambda a: alerts.append(a))

    alert = monitor.check_dll_load(
        pid=500, process="explorer.exe",
        dll_path="C:\\Windows\\System32\\ntdll.dll"
    )
    assert alert is None
    print("PASS: SC legitimate DLL not flagged: System32/ntdll.dll → None")


def test_sc_update_hijack_unauthorized_host():
    alerts = []
    monitor = SupplyChainMonitor(MASTER_KEY, on_alert=lambda a: alerts.append(a))

    alert = monitor.check_update_url(
        url="http://evil-update.ru/payload.exe",
        process="updater.exe", pid=9999
    )
    assert alert is not None
    assert alert.attack_type == "UPDATE_HIJACK"
    print(f"PASS: SC update hijack detected: {alert.evidence['host']}")


def test_sc_authorized_update_host_allowed():
    monitor = SupplyChainMonitor(MASTER_KEY)
    alert = monitor.check_update_url(
        url="https://update.microsoft.com/latest.cab",
        process="wuauclt.exe", pid=800
    )
    assert alert is None
    print("PASS: SC authorized update host allowed: update.microsoft.com → None")


def test_sc_build_poison_detected(tmp_path):
    """Modifie un binaire après baseline → alerte BUILD_POISON."""
    import tempfile, pathlib
    # Créer un binaire temporaire
    binary = tmp_path / "gravity_agent.exe"
    binary.write_bytes(b"original binary content" * 100)

    alerts = []
    monitor = SupplyChainMonitor(
        MASTER_KEY, on_alert=lambda a: alerts.append(a),
        trusted_binary_paths=[str(binary)]
    )
    # Pas d'alerte juste après baseline
    assert monitor.check_binary_integrity(str(binary)) is None

    # Modifier le binaire
    binary.write_bytes(b"COMPROMISED BINARY" * 100)

    alert = monitor.check_binary_integrity(str(binary))
    assert alert is not None
    assert alert.attack_type == "BUILD_POISON"
    assert alert.severity >= 0.9
    print(f"PASS: SC build poison detected: score={alert.severity}")


# ─────────────────────────────────────────────────────────────────────────────
# BATCH REPORTER — Logique locale (sans réseau)
# ─────────────────────────────────────────────────────────────────────────────
from transport.batch_reporter import AlertDeduplicator, BatchReporter


def test_dedup_same_alert():
    dedup = AlertDeduplicator(window=5.0)
    alert = {"type": "FILE_THREAT", "pid": 1234, "process": "evil.exe"}
    assert not dedup.is_duplicate(alert)   # Première fois → accepté
    assert dedup.is_duplicate(alert)       # Même alerte → dupliqué
    assert dedup.suppressed == 1
    print("PASS: BatchReporter dedup: same alert suppressed")


def test_dedup_different_alerts():
    dedup = AlertDeduplicator(window=5.0)
    a1 = {"type": "FILE_THREAT", "pid": 1234, "process": "evil.exe"}
    a2 = {"type": "MEMORY_THREAT", "pid": 1234, "process": "evil.exe"}
    assert not dedup.is_duplicate(a1)
    assert not dedup.is_duplicate(a2)  # Type différent → pas dupliqué
    assert dedup.suppressed == 0
    print("PASS: BatchReporter dedup: different alert types accepted")


def test_dedup_window_expiry():
    dedup = AlertDeduplicator(window=0.1)  # 100ms
    alert = {"type": "FILE_THREAT", "pid": 5678, "process": "test.exe"}
    assert not dedup.is_duplicate(alert)
    time.sleep(0.15)
    assert not dedup.is_duplicate(alert)  # Fenêtre expirée → accepté de nouveau
    print("PASS: BatchReporter dedup: window expiry works")


def test_batch_reporter_ring_buffer():
    """Vérifie que le ring buffer ne dépasse pas RING_BUFFER_SIZE."""
    from transport.batch_reporter import RING_BUFFER_SIZE
    reporter = BatchReporter(
        agent_id="test-001",
        collector_url="http://localhost:19999",  # Port qui n'existe pas
        shared_secret="test"
    )
    # Injecter plus d'alertes que la taille du ring
    for i in range(RING_BUFFER_SIZE + 100):
        reporter.submit({"type": f"ALERT_{i}", "pid": i, "process": "test.exe"})

    assert len(reporter._ring) <= RING_BUFFER_SIZE
    print(f"PASS: BatchReporter ring buffer capped at {RING_BUFFER_SIZE:,}")


# ─────────────────────────────────────────────────────────────────────────────
# BULK PROCESSOR — Logique sans réseau
# ─────────────────────────────────────────────────────────────────────────────
import asyncio
from cluster.bulk_processor import (
    GlobalDeduplicator, PriorityAlertQueue, BulkProcessor, CRITICAL_THRESHOLD
)


def test_global_dedup():
    dedup = GlobalDeduplicator(ttl=60.0)
    alert = {"type": "RANSOMWARE_DETECTED", "pid": 999, "process": "ransom.exe", "agent_id": "ag1"}
    assert not dedup.is_duplicate(alert)
    assert dedup.is_duplicate(alert)
    assert dedup.total_suppressed == 1
    print("PASS: BulkProcessor GlobalDeduplicator works")


def test_global_dedup_cross_agent():
    """Même alerte de 2 agents différents → dedupliquée (inter-agents)."""
    dedup = GlobalDeduplicator(ttl=60.0)
    a1 = {"type": "FILE_THREAT", "pid": 100, "process": "evil.exe", "agent_id": "agent-1"}
    a2 = {"type": "FILE_THREAT", "pid": 100, "process": "evil.exe", "agent_id": "agent-2"}
    # Les deux ont le même type+pid+process mais agent différent
    # La dédup inclut agent_id → ce sont des événements DISTINCTS
    assert not dedup.is_duplicate(a1)
    assert not dedup.is_duplicate(a2)  # agent_id différent → pas dupliqué
    print("PASS: BulkProcessor GlobalDedup: cross-agent same event kept distinct")


async def _test_priority_queue():
    q = PriorityAlertQueue()
    critical = {"type": "QBSM_COLLAPSE", "threat_score": 0.97, "process": "evil.exe"}
    normal = {"type": "FILE_THREAT", "threat_score": 0.55, "process": "test.exe"}

    await q.put(critical)
    await q.put(normal)

    # CRITICAL doit être dans la file critique
    c = await q.get_critical()
    assert c is not None
    assert c["type"] == "QBSM_COLLAPSE"

    # NORMAL dans la file normale
    batch = await q.drain_normal()
    assert len(batch) == 1
    assert batch[0]["type"] == "FILE_THREAT"
    return True


def test_priority_queue():
    result = asyncio.run(_test_priority_queue())
    assert result
    print(f"PASS: BulkProcessor PriorityQueue: CRITICAL separated from NORMAL")


async def _test_bulk_ingest():
    saved = []
    critical_alerts = []

    processor = BulkProcessor(
        on_critical=lambda a: critical_alerts.append(a),
        on_bulk_save=lambda alerts: saved.extend(alerts),
    )
    await processor.start()

    # Préparer un payload compressé (comme un collector)
    alerts = [
        {"type": "RANSOMWARE_DETECTED", "threat_score": 0.95, "pid": 1, "process": "ransom.exe", "agent_id": "ag1"},
        {"type": "FILE_THREAT", "threat_score": 0.4, "pid": 2, "process": "file.exe", "agent_id": "ag1"},
        {"type": "FILE_THREAT", "threat_score": 0.4, "pid": 2, "process": "file.exe", "agent_id": "ag1"},  # dupliqué
    ]
    payload = json.dumps({"alerts": alerts, "count": len(alerts)}).encode()
    compressed = zlib.compress(payload, level=6)

    result = await processor.ingest_bulk(compressed, "zlib", "collector-test")
    assert result["received"] == 3
    assert result["accepted"] == 2   # 1 dupliqué
    assert result["deduplicated"] == 1

    # Laisser le loop async traiter
    await asyncio.sleep(0.05)

    stats = processor.get_stats()
    assert stats["received_total"] == 3
    assert stats["total_deduplicated"] == 1
    return True


def test_bulk_ingest_dedup():
    result = asyncio.run(_test_bulk_ingest())
    assert result
    print("PASS: BulkProcessor ingest: 3 received, 1 deduplicated, 2 accepted")


def test_bulk_compression_ratio():
    """Vérifie que la compression zlib-6 donne bien ~4x sur JSON sécurité."""
    alerts = [
        {
            "type": "FILE_THREAT", "pid": i, "process": "evil.exe",
            "threat_score": 0.75, "timestamp": time.time(),
            "cmdline": f"evil.exe --param {i} --secret {'A'*32}",
        }
        for i in range(100)
    ]
    raw = json.dumps({"alerts": alerts}).encode()
    compressed = zlib.compress(raw, level=6)
    ratio = len(raw) / len(compressed)
    assert ratio > 3.0, f"Compression ratio {ratio:.1f}x trop faible"
    print(f"PASS: Compression ratio: {ratio:.1f}x (100 alertes JSON)")


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import tempfile, pathlib

    tests = [
        # Supply Chain
        test_sc_levenshtein_identical,
        test_sc_levenshtein_one_typo,
        test_sc_typosquat_detected,
        test_sc_legitimate_package_not_flagged,
        test_sc_dll_hijack_detected,
        test_sc_legitimate_dll_not_flagged,
        test_sc_update_hijack_unauthorized_host,
        test_sc_authorized_update_host_allowed,
        # BatchReporter
        test_dedup_same_alert,
        test_dedup_different_alerts,
        test_dedup_window_expiry,
        test_batch_reporter_ring_buffer,
        # BulkProcessor
        test_global_dedup,
        test_global_dedup_cross_agent,
        test_priority_queue,
        test_bulk_ingest_dedup,
        test_bulk_compression_ratio,
    ]

    # test_sc_build_poison_detected nécessite tmp_path (pytest fixture)
    # On l'exécute manuellement avec un dossier temporaire PERSISTANT
    _tmp_dir = tempfile.mkdtemp()
    _tmp_path = pathlib.Path(_tmp_dir)

    def _run_build_poison():
        try:
            test_sc_build_poison_detected(_tmp_path)
        finally:
            import shutil
            shutil.rmtree(_tmp_dir, ignore_errors=True)

    tests.insert(8, _run_build_poison)

    passed = failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"FAIL: {getattr(test, '__name__', str(test))}: {e}")
            import traceback; traceback.print_exc()
            failed += 1

    print(f"\n{'='*65}")
    print(f"Supply Chain + Scale — {passed}/{len(tests)} tests passés")
    print("TOUS LES TESTS PASSÉS" if not failed else f"ÉCHECS: {failed}")
    print(f"{'='*65}")
    sys.exit(1 if failed else 0)
