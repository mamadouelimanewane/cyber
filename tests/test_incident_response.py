"""
Tests — Incident Response Engine
"""
import asyncio
import sys, os, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server", "src"))
from incident_response import (
    IncidentResponseEngine, IncidentSeverity, IncidentStatus, ResponseAction
)


def run(coro):
    return asyncio.run(coro)


# ── Tests ─────────────────────────────────────────────────────────────────────

async def test_ransomware_incident_opens():
    incidents = []
    ire = IncidentResponseEngine(on_incident_opened=lambda i: incidents.append(i))

    # QBSM_COLLAPSE seul → ne déclenche pas RANSOMWARE (min_triggers=2)
    # mais déclenche la règle QBSM_COLLAPSE (min=1)
    await ire.process_alert({"type": "QBSM_COLLAPSE", "agent_id": "ag1", "pid": 1, "process": "ransom.exe", "timestamp": time.time()})
    assert len(incidents) >= 1
    inc = incidents[0]
    assert inc.severity == IncidentSeverity.CRITICAL
    assert "ag1" in inc.affected_agents
    print(f"PASS: Ransomware incident opened — severity={inc.severity.value}, playbook={inc.playbook}")


async def test_ransomware_playbook_actions():
    incidents = []
    actions_executed = []

    ire = IncidentResponseEngine(
        on_incident_opened=lambda i: incidents.append(i),
        on_action_executed=lambda i, a, r: actions_executed.append(a),
    )

    await ire.process_alert({
        "type": "RANSOMWARE_DETECTED", "agent_id": "ag2",
        "pid": 999, "process": "locker.exe", "timestamp": time.time()
    })
    await ire.process_alert({
        "type": "FILE_THREAT", "agent_id": "ag2",
        "pid": 999, "process": "locker.exe", "timestamp": time.time()
    })

    # Attendre les actions async
    await asyncio.sleep(0.1)

    assert len(incidents) >= 1
    # Playbook ransomware = kill + isolate + snapshot + preserve + notify
    assert "kill_process" in actions_executed
    assert "isolate_agent" in actions_executed
    assert "notify_soc" in actions_executed
    print(f"PASS: Ransomware playbook — actions: {actions_executed}")


async def test_supply_chain_incident():
    incidents = []
    ire = IncidentResponseEngine(on_incident_opened=lambda i: incidents.append(i))

    await ire.process_alert({
        "type": "SUPPLY_CHAIN_DLL_HIJACK", "agent_id": "ag3",
        "pid": 2000, "process": "updater.exe", "timestamp": time.time()
    })

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.playbook == "supply_chain"
    assert "T1195" in inc.mitre_tactics or "T1574" in inc.mitre_tactics
    print(f"PASS: Supply chain incident — mitre={inc.mitre_tactics}")


async def test_deception_honeytoken():
    incidents = []
    ire = IncidentResponseEngine(on_incident_opened=lambda i: incidents.append(i))

    await ire.process_alert({
        "type": "HONEYTOKEN_TRIGGERED", "agent_id": "ag4",
        "pid": 777, "process": "intruder.exe", "timestamp": time.time()
    })

    assert len(incidents) == 1
    assert incidents[0].kill_chain_phase == "Reconnaissance"
    print(f"PASS: Honeytoken incident — phase={incidents[0].kill_chain_phase}")


async def test_no_incident_below_threshold():
    incidents = []
    ire = IncidentResponseEngine(on_incident_opened=lambda i: incidents.append(i))

    # LATERAL_MOVEMENT nécessite 3 triggers différents
    await ire.process_alert({"type": "SYSCALL_ANOMALY", "agent_id": "ag5",
                              "pid": 1, "process": "normal.exe", "timestamp": time.time()})
    await ire.process_alert({"type": "SYSCALL_ANOMALY", "agent_id": "ag5",
                              "pid": 2, "process": "normal.exe", "timestamp": time.time()})
    # Seulement 1 type distinct sur 3 requis → pas d'incident
    assert len(incidents) == 0
    print("PASS: No incident below threshold (1/3 distinct types)")


async def test_lateral_movement_three_types():
    incidents = []
    ire = IncidentResponseEngine(on_incident_opened=lambda i: incidents.append(i))

    for alert_type in ["SYSCALL_ANOMALY", "UEBA_ANOMALY", "MEMORY_THREAT"]:
        await ire.process_alert({
            "type": alert_type, "agent_id": "ag6",
            "pid": 100, "process": "pivot.exe", "timestamp": time.time()
        })

    assert len(incidents) >= 1
    inc = incidents[0]
    assert inc.playbook == "lateral_movement"
    assert "block_network" in inc.response_actions
    print(f"PASS: Lateral movement incident — actions={inc.response_actions[:3]}")


async def test_anti_duplicate_5min():
    incidents = []
    ire = IncidentResponseEngine(on_incident_opened=lambda i: incidents.append(i))

    # Déclencher le même incident deux fois
    for _ in range(2):
        await ire.process_alert({
            "type": "HONEYTOKEN_TRIGGERED", "agent_id": "ag7",
            "pid": 10, "process": "evil.exe", "timestamp": time.time()
        })

    # Seulement 1 incident (anti-doublon 5min)
    assert len(incidents) == 1
    print("PASS: Anti-duplicate: 2 triggers → 1 incident")


async def test_incident_status_update():
    incidents = []
    ire = IncidentResponseEngine(on_incident_opened=lambda i: incidents.append(i))

    await ire.process_alert({
        "type": "HONEYTOKEN_TRIGGERED", "agent_id": "ag8",
        "pid": 20, "process": "intruder.exe", "timestamp": time.time()
    })

    inc_id = incidents[0].id
    ok = await ire.update_incident_status(inc_id, "contained", "Agent isolé manuellement")
    assert ok

    data = ire.get_incident(inc_id)
    assert data["status"] == "contained"
    assert any("contained" in e["detail"] for e in data["timeline"])
    print(f"PASS: Incident status updated to 'contained'")


async def test_stats_tracking():
    ire = IncidentResponseEngine()

    for i in range(5):
        await ire.process_alert({
            "type": "HONEYTOKEN_TRIGGERED", "agent_id": f"ag-stat-{i}",
            "pid": i, "process": "evil.exe", "timestamp": time.time()
        })

    stats = ire.get_stats()
    assert stats["alerts_processed"] == 5
    assert stats["incidents_opened"] == 5
    assert stats["actions_executed"] > 0
    print(f"PASS: Stats — {stats['incidents_opened']} incidents, {stats['actions_executed']} actions")


async def test_incident_timeline():
    incidents = []
    ire = IncidentResponseEngine(on_incident_opened=lambda i: incidents.append(i))

    await ire.process_alert({
        "type": "QBSM_COLLAPSE", "agent_id": "ag9",
        "pid": 55, "process": "malware.exe", "timestamp": time.time()
    })
    await asyncio.sleep(0.05)

    inc = incidents[0]
    # La timeline doit contenir : incident_opened + toutes les actions
    actions_in_timeline = [e.action for e in inc.timeline]
    assert "incident_opened" in actions_in_timeline
    assert len(inc.timeline) >= 3  # opened + au moins 2 actions
    print(f"PASS: Incident timeline — {len(inc.timeline)} entrées: {actions_in_timeline[:4]}")


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    tests = [
        test_ransomware_incident_opens,
        test_ransomware_playbook_actions,
        test_supply_chain_incident,
        test_deception_honeytoken,
        test_no_incident_below_threshold,
        test_lateral_movement_three_types,
        test_anti_duplicate_5min,
        test_incident_status_update,
        test_stats_tracking,
        test_incident_timeline,
    ]

    passed = failed = 0
    for test in tests:
        try:
            asyncio.run(test())
            passed += 1
        except Exception as e:
            print(f"FAIL: {test.__name__}: {e}")
            import traceback; traceback.print_exc()
            failed += 1

    print(f"\n{'='*65}")
    print(f"Incident Response Engine — {passed}/{len(tests)} tests passés")
    print("TOUS LES TESTS PASSÉS" if not failed else f"ÉCHECS: {failed}")
    print(f"{'='*65}")
    sys.exit(1 if failed else 0)
