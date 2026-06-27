"""
Tests for Gravity Security v3 algorithms:
CPL, EGS, BCTV, SSF, TZTE, SHNT
"""
import hashlib
import sys
import time
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server", "src"))

MASTER_KEY = hashlib.sha256(b"gravity-test-v3").digest()

# ─────────────────────────────────────────────────────────────────────────────
# CPL — Cryptographic Process Lineage
# ─────────────────────────────────────────────────────────────────────────────
from cpl.process_lineage import ProcessLineageEngine


def test_cpl_ticket_issued_and_validated():
    engine = ProcessLineageEngine(MASTER_KEY)
    ticket = engine.issue_ticket(
        parent_pid=1000, child_pid=2000,
        child_exe="notepad.exe", parent_dna_hash="aabbcc"
    )
    assert ticket is not None
    assert ticket.is_valid()
    assert engine._verify_signature(ticket)
    print("PASS: CPL ticket issued and signature verified")


def test_cpl_bootstrap_processes_not_flagged():
    engine = ProcessLineageEngine(MASTER_KEY)
    engine.register_bootstrap(4, "system")
    v = engine.validate_process(4, "system", 0, "none")
    assert v is None
    print("PASS: CPL bootstrap processes exempt")


def test_cpl_high_risk_without_ticket_flagged():
    engine = ProcessLineageEngine(MASTER_KEY)
    engine._known_pids = {1000}  # parent is known
    v = engine.validate_process(9999, "powershell.exe", 1000, "explorer.exe")
    assert v is not None
    assert v.severity >= 0.85
    print(f"PASS: CPL high-risk without ticket flagged (severity={v.severity})")


def test_cpl_scan_process_list():
    engine = ProcessLineageEngine(MASTER_KEY)
    processes = [
        {"pid": 4, "name": "System", "ppid": 0, "parent_name": "none"},
        {"pid": 1000, "name": "explorer.exe", "ppid": 4, "parent_name": "System"},
        {"pid": 9000, "name": "cmd.exe", "ppid": 99999, "parent_name": "unknown_process.exe"},
    ]
    violations = engine.scan_process_list(processes)
    # cmd.exe with unknown parent should be flagged
    assert any(v.exe.lower() == "cmd.exe" for v in violations)
    print(f"PASS: CPL scan detected violations: {[v.exe for v in violations]}")


# ─────────────────────────────────────────────────────────────────────────────
# EGS — Entropy Gradient Shield
# ─────────────────────────────────────────────────────────────────────────────
from egs.entropy_gradient import EntropyGradientShield, shannon_entropy


def test_egs_shannon_entropy():
    zero_bytes = bytes([0] * 1000)
    rand_bytes = bytes(range(256)) * 4
    assert shannon_entropy(zero_bytes) == 0.0
    assert shannon_entropy(rand_bytes) > 7.9   # close to 8 bits (max for bytes)
    print(f"PASS: Shannon entropy: zeros=0.0, random={shannon_entropy(rand_bytes):.2f}")


def test_egs_ransomware_extension_triggers_alert():
    alerts = []
    shield = EntropyGradientShield(
        watch_dirs=[],
        on_alert=lambda a: alerts.append(a),
    )
    shield.record_file_change("C:\\Users\\victim\\budget.docx.encrypted")
    assert len(alerts) == 1
    assert alerts[0].severity >= 0.9
    print(f"PASS: EGS ransomware extension triggered alert (severity={alerts[0].severity})")


def test_egs_entropy_velocity_computed():
    shield = EntropyGradientShield(watch_dirs=[], window_seconds=30.0)
    import time as _time
    now = _time.time()
    # Insert entries in chronological order (oldest first)
    with shield._lock:
        for i in range(9, -1, -1):
            shield._window.append((now - i * 0.5, 1.5, f"file_{i}.docx"))
    v, rate, affected = shield._compute_entropy_velocity()
    assert v > 0, f"Expected velocity > 0, got {v}"
    assert rate > 0
    print(f"PASS: EGS velocity={v:.3f} bits/s rate={rate:.1f} files/s")


# ─────────────────────────────────────────────────────────────────────────────
# BCTV — Byzantine Consensus Threat Voting
# ─────────────────────────────────────────────────────────────────────────────
from consensus.byzantine_consensus import ByzantineConsensusEngine, Verdict


def test_bctv_single_agent_casts_vote():
    key = MASTER_KEY
    engine = ByzantineConsensusEngine("agent-1", key)
    alert = {"id": "alert-001", "threat_score": 0.95, "type": "FILE_THREAT"}
    vote = engine.cast_vote(alert)
    assert vote.verdict == Verdict.THREAT
    assert vote.confidence >= 0.9
    print(f"PASS: BCTV vote cast: {vote.verdict.value} conf={vote.confidence:.2f}")


def test_bctv_consensus_with_3_agents():
    keys = {f"agent-{i}": hashlib.sha256(f"key-{i}".encode()).digest() for i in range(3)}
    engines = {
        aid: ByzantineConsensusEngine(aid, key)
        for aid, key in keys.items()
    }
    # Register peers
    for aid, eng in engines.items():
        for other_aid, other_key in keys.items():
            if other_aid != aid:
                eng.register_agent(other_aid, other_key)

    alert = {"id": "alert-multi", "threat_score": 0.91, "type": "MEMORY_THREAT"}

    # Each agent casts and shares votes
    votes = []
    for eng in engines.values():
        v = eng.cast_vote(alert)
        votes.append(v)

    # Share votes with all engines
    for eng in engines.values():
        for v in votes:
            if v.agent_id != eng.agent_id:
                eng.receive_peer_vote(v.to_dict())

    # Check consensus
    result = engines["agent-0"].compute_consensus("alert-multi")
    assert result is not None
    assert result.consensus_reached
    assert result.final_verdict == Verdict.THREAT
    print(f"PASS: BCTV consensus: {result.final_verdict.value} "
          f"({result.threat_votes}T/{result.benign_votes}B) "
          f"conf={result.weighted_confidence:.2f}")


def test_bctv_invalid_signature_rejected():
    key = MASTER_KEY
    engine = ByzantineConsensusEngine("agent-1", key)
    engine.register_agent("malicious-agent", b"different-key" * 2)
    bad_vote = {
        "vote_id": "x",
        "alert_id": "alert-001",
        "agent_id": "malicious-agent",
        "verdict": "BENIGN",
        "confidence": 0.99,
        "evidence_hash": "fake",
        "timestamp": time.time(),
        "signature": "FORGED_SIGNATURE",
    }
    initial_count = len(engine._vote_pool.get("alert-001", []))
    engine.receive_peer_vote(bad_vote)
    assert len(engine._vote_pool.get("alert-001", [])) == initial_count
    print("PASS: BCTV forged signature rejected")


# ─────────────────────────────────────────────────────────────────────────────
# SSF — Syscall Sequence Fingerprinting
# ─────────────────────────────────────────────────────────────────────────────
from syscall_monitor.ssf import SyscallSequenceFingerprinter, MALWARE_SIGNATURES


def test_ssf_ransomware_pattern_detected():
    anomalies = []
    ssf = SyscallSequenceFingerprinter(on_anomaly=lambda a: anomalies.append(a))
    ssf.simulate_attack(pid=5000, process_name="evil.exe", attack_type="ransomware_pattern")
    assert len(anomalies) > 0
    assert anomalies[0].suspected_behavior == "Data Encrypted for Impact"
    assert anomalies[0].severity >= 0.99
    print(f"PASS: SSF ransomware pattern detected: {anomalies[0].mitre_technique}")


def test_ssf_injection_pattern_detected():
    from syscall_monitor.ssf import check_malware_signatures
    # Test the signature matcher directly
    sequence = ["MEM_ALLOC", "MEM_PROTECT", "PROC_INJECT", "PROC_INJECT"]
    match = check_malware_signatures(sequence)
    assert match is not None, f"Expected process_injection match in {sequence}"
    assert match["mitre"] == "T1055"
    print(f"PASS: SSF injection signature matched: {match['mitre']} — {match['name']}")


def test_ssf_benign_sequence_not_flagged():
    anomalies = []
    ssf = SyscallSequenceFingerprinter(on_anomaly=lambda a: anomalies.append(a))
    # Simulate normal browser behavior
    benign_calls = ["ReadFile", "WriteFile", "connect", "send", "recv"] * 5
    for call in benign_calls:
        ssf.record_syscall(1234, "chrome.exe", call)
    # Normal browser: minimal anomalies expected (may trigger low-surprisal)
    high_severity = [a for a in anomalies if a.severity >= 0.85]
    assert len(high_severity) == 0
    print(f"PASS: SSF benign sequence not flagged (anomalies={len(anomalies)} high_sev={len(high_severity)})")


# ─────────────────────────────────────────────────────────────────────────────
# TZTE — Temporal Zero-Trust Execution
# ─────────────────────────────────────────────────────────────────────────────
from tzte.tzte_daemon import TZTEDaemon, ActionType


def test_tzte_ticket_issued_and_verified():
    violations = []
    daemon = TZTEDaemon(MASTER_KEY, on_violation=lambda v: violations.append(v))
    daemon.register_trusted_process(1234, "abc123dna", "notepad.exe")
    ticket = daemon.request_ticket(1234, "notepad.exe", ActionType.FILE_WRITE_EXTERNAL,
                                   "C:\\Shared\\report.docx", dna_hash="abc123dna")
    assert ticket is not None
    ok = daemon.verify_ticket(ticket.ticket_id, 1234, ActionType.FILE_WRITE_EXTERNAL,
                              "C:\\Shared\\report.docx")
    assert ok
    assert len(violations) == 0
    print("PASS: TZTE ticket issued and verified successfully")


def test_tzte_inject_memory_without_registration_denied():
    violations = []
    daemon = TZTEDaemon(MASTER_KEY, on_violation=lambda v: violations.append(v))
    # NOT registered
    ticket = daemon.request_ticket(9999, "malware.exe", ActionType.INJECT_MEMORY,
                                   "C:\\Windows\\lsass.exe", dna_hash="")
    assert ticket is None
    assert len(violations) == 1
    assert violations[0].severity >= 0.95
    print(f"PASS: TZTE INJECT_MEMORY without registration denied (sev={violations[0].severity})")


def test_tzte_dna_mismatch_denied():
    violations = []
    daemon = TZTEDaemon(MASTER_KEY, on_violation=lambda v: violations.append(v))
    daemon.register_trusted_process(3000, "correct_dna_hash", "svchost.exe")
    ticket = daemon.request_ticket(3000, "svchost.exe", ActionType.SERVICE_CREATE,
                                   "evil_service", dna_hash="WRONG_DNA_HASH")
    assert ticket is None
    assert any("mismatch" in v.reason.lower() or "dna" in v.reason.lower() for v in violations)
    print("PASS: TZTE DNA hash mismatch denied")


def test_tzte_expired_ticket_rejected():
    violations = []
    daemon = TZTEDaemon(MASTER_KEY, on_violation=lambda v: violations.append(v))
    daemon.register_trusted_process(4000, "dna_ok", "explorer.exe")
    ticket = daemon.request_ticket(4000, "explorer.exe", ActionType.NETWORK_CONNECT,
                                   "8.8.8.8:443", dna_hash="dna_ok")
    assert ticket is not None
    # Expire the ticket
    daemon._tickets[ticket.ticket_id].expires_at = time.time() - 1
    ok = daemon.verify_ticket(ticket.ticket_id, 4000, ActionType.NETWORK_CONNECT, "8.8.8.8:443")
    assert not ok
    print("PASS: TZTE expired ticket rejected")


# ─────────────────────────────────────────────────────────────────────────────
# SHNT — Self-Healing Network Topology
# ─────────────────────────────────────────────────────────────────────────────
from topology.shnt import SelfHealingTopology, TrustLevel


def test_shnt_agent_registered():
    topo = SelfHealingTopology()
    topo.register_agent("agent-A", "192.168.1.10", "PC-A")
    assert "agent-A" in topo._agents
    assert topo._agents["agent-A"].trust_level == TrustLevel.TRUSTED
    print("PASS: SHNT agent registered at TRUSTED level")


def test_shnt_critical_alerts_lower_trust():
    topo = SelfHealingTopology()
    topo.register_agent("agent-B", "192.168.1.20", "PC-B")
    for _ in range(8):
        topo.update_from_alert("agent-B", "critical", "MEMORY_THREAT")
    profile = topo._agents["agent-B"]
    assert profile.alert_history_score < 0.5
    print(f"PASS: SHNT trust lowered by alerts: score={profile.trust_score:.3f}")


def test_shnt_agent_isolated_at_threshold():
    isolated = []
    topo = SelfHealingTopology(on_isolate=lambda aid, p, e: isolated.append(aid))
    topo.register_agent("agent-C", "192.168.1.30", "PC-C")
    # Drive all component scores to 0
    profile = topo._agents["agent-C"]
    profile.alert_history_score = 0.0
    profile.dna_stability_score = 0.0
    profile.network_behavior_score = 0.0
    profile.heartbeat_regularity = 0.0
    profile.chaos_key_sync_score = 0.0
    topo._evaluate_trust("agent-C")
    assert profile.is_isolated, f"Expected isolated, score={profile.trust_score:.3f}"
    print(f"PASS: SHNT agent isolated: score={profile.trust_score:.3f} isolated={profile.is_isolated}")


def test_shnt_topology_report():
    topo = SelfHealingTopology()
    topo.register_agent("a1", "10.0.0.1", "PC-1")
    topo.register_agent("a2", "10.0.0.2", "PC-2")
    report = topo.get_topology()
    assert "clusters" in report
    assert "summary" in report
    assert report["summary"]["total_agents"] == 2
    print(f"PASS: SHNT topology report: {report['summary']}")


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    tests = [
        # CPL
        test_cpl_ticket_issued_and_validated,
        test_cpl_bootstrap_processes_not_flagged,
        test_cpl_high_risk_without_ticket_flagged,
        test_cpl_scan_process_list,
        # EGS
        test_egs_shannon_entropy,
        test_egs_ransomware_extension_triggers_alert,
        test_egs_entropy_velocity_computed,
        # BCTV
        test_bctv_single_agent_casts_vote,
        test_bctv_consensus_with_3_agents,
        test_bctv_invalid_signature_rejected,
        # SSF
        test_ssf_ransomware_pattern_detected,
        test_ssf_injection_pattern_detected,
        test_ssf_benign_sequence_not_flagged,
        # TZTE
        test_tzte_ticket_issued_and_verified,
        test_tzte_inject_memory_without_registration_denied,
        test_tzte_dna_mismatch_denied,
        test_tzte_expired_ticket_rejected,
        # SHNT
        test_shnt_agent_registered,
        test_shnt_critical_alerts_lower_trust,
        test_shnt_agent_isolated_at_threshold,
        test_shnt_topology_report,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"FAIL: {test.__name__}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print(f"\n{'='*60}")
    print(f"Gravity Security v3 — {passed}/{len(tests)} tests passed")
    if failed:
        print(f"FAILED: {failed} tests")
    else:
        print("ALL TESTS PASSED")
    print(f"{'='*60}")
    sys.exit(1 if failed else 0)
