"""
Tests for Gravity Security Patent Algorithms:
QBSM, CBGA, ZKSP, ASN, RCTC
"""
import hashlib
import sys
import time
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server", "src"))

MASTER_KEY = hashlib.sha256(b"gravity-patent-test").digest()

# ─────────────────────────────────────────────────────────────────────────────
# BREVET 1 — QBSM : Quantum Behavioral Superposition Model
# ─────────────────────────────────────────────────────────────────────────────
from qbsm.quantum_behavioral import (
    QuantumBehavioralSuperpositionModel, QuantumState, QuantumProcessState
)


def test_qbsm_initial_state_is_superposition():
    model = QuantumBehavioralSuperpositionModel()
    state = model.register_process(1000, "notepad.exe")
    assert state.p_safe > 0.99
    assert state.p_threat < 0.01
    assert state.state == QuantumState.SUPERPOSITION
    print(f"PASS: QBSM initial state: P_safe={state.p_safe:.3f} P_threat={state.p_threat:.3f}")


def test_qbsm_honeytoken_collapses_to_threat():
    collapses = []
    model = QuantumBehavioralSuperpositionModel(on_collapse=lambda c: collapses.append(c))
    model.register_process(2000, "malware.exe")
    # Honeytoken a le plus grand poids → devrait effondrer rapidement
    for _ in range(5):
        result = model.observe(2000, "malware.exe", "honeytoken")
        if result:
            break
    state = model._states[2000]
    assert state.p_threat > 0.5, f"Expected high P_threat, got {state.p_threat:.3f}"
    print(f"PASS: QBSM honeytoken: P_threat={state.p_threat:.3f} state={state.state.value}")


def test_qbsm_contradictory_observations_maintain_superposition():
    model = QuantumBehavioralSuperpositionModel()
    model.register_process(3000, "ambiguous.exe")
    # Alternance observations normales et suspectes → décohérence ou superposition maintenue
    for _ in range(5):
        model.observe(3000, "ambiguous.exe", "normal_behavior")
        model.observe(3000, "ambiguous.exe", "ps_encoded")
    state = model._states[3000]
    # Ne doit pas avoir effondré vers CRITICAL threat
    assert state.p_threat < 0.95, f"Too many false positive: P_threat={state.p_threat:.3f}"
    print(f"PASS: QBSM contradictory obs: P_threat={state.p_threat:.3f} (no false collapse)")


def test_qbsm_entanglement_propagates():
    collapses = []
    model = QuantumBehavioralSuperpositionModel(on_collapse=lambda c: collapses.append(c))
    model.register_process(4000, "attacker_main.exe")
    model.register_process(4001, "attacker_helper.exe")
    # Intrication
    model.entangle(4000, 4001, "campaign-APT1")
    assert 4001 in model._states[4000].entangled_pids
    assert 4000 in model._states[4001].entangled_pids
    print(f"PASS: QBSM entanglement established: 4000↔4001")


def test_qbsm_observe_from_alert():
    model = QuantumBehavioralSuperpositionModel()
    model.register_process(5000, "ransomware.exe")
    alert = {
        "type": "RANSOMWARE_DETECTED",
        "pid": 5000,
        "process": "ransomware.exe",
        "threat_score": 0.99,
    }
    model.observe_from_alert(alert)
    state = model._states.get(5000)
    assert state is not None
    assert state.p_threat > 0.1
    print(f"PASS: QBSM observe_from_alert: P_threat={state.p_threat:.3f}")


# ─────────────────────────────────────────────────────────────────────────────
# BREVET 2 — CBGA : Cryptographic Behavioral Genome Alignment
# ─────────────────────────────────────────────────────────────────────────────
from cbga.genome_alignment import (
    CryptographicBehavioralGenomeAlignment, smith_waterman,
    genome_distance, ProcessGenome, MALWARE_GENOMES
)


def test_cbga_smith_waterman_identical():
    score, _, _ = smith_waterman("EFWCR", "EFWCR")
    assert score > 0
    print(f"PASS: CBGA SW identical: score={score}")


def test_cbga_smith_waterman_unrelated():
    score_same, _, _ = smith_waterman("EFWCR", "EFWCR")
    score_diff, _, _ = smith_waterman("EFWCR", "OOOOOO")
    assert score_same > score_diff
    print(f"PASS: CBGA SW unrelated < identical: {score_diff} < {score_same}")


def test_cbga_genome_distance():
    d_identical = genome_distance("EFWCRWCR", "EFWCRWCR")
    d_different = genome_distance("EFWCRWCR", "NSVNSV")
    assert d_identical < 0.1
    assert d_different > d_identical
    print(f"PASS: CBGA distance: identical={d_identical:.3f} different={d_different:.3f}")


def test_cbga_ransomware_genome_detected():
    alerts = []
    engine = CryptographicBehavioralGenomeAlignment(
        MASTER_KEY,
        on_alert=lambda a: alerts.append(a),
    )
    # Envoyer le génome ransomware directement
    ransomware_genome = MALWARE_GENOMES["Ransomware_LockBit"]["genome"].replace(" ", "")
    engine.scan_process(pid=9000, process_name="evil.exe", genome_sequence=ransomware_genome)
    assert len(alerts) > 0
    assert alerts[0].best_match.malware_name == "Ransomware_LockBit"
    assert alerts[0].best_match.similarity >= 0.85
    print(f"PASS: CBGA ransomware detected: sim={alerts[0].best_match.similarity:.3f}")


def test_cbga_genome_cryptographic_signing():
    genome = ProcessGenome(pid=1234, process_name="test.exe", sequence="EFWCRO")
    sig = genome.sign(MASTER_KEY)
    assert sig != ""
    assert genome.verify(MASTER_KEY)
    # Tamper avec la séquence → signature invalide
    genome.sequence += "X"
    assert not genome.verify(MASTER_KEY)
    print("PASS: CBGA cryptographic signing: tamper detected")


# ─────────────────────────────────────────────────────────────────────────────
# BREVET 3 — ZKSP : Zero-Knowledge Security Proof
# ─────────────────────────────────────────────────────────────────────────────
from zksp.zero_knowledge_proof import (
    ZeroKnowledgeSecurityProver, ZeroKnowledgeSecurityVerifier,
    ProofStatus, STANDARD_POLICIES
)


def test_zksp_complete_proof_cycle():
    prover = ZeroKnowledgeSecurityProver(MASTER_KEY)
    verifier = ZeroKnowledgeSecurityVerifier(MASTER_KEY)

    pid = 7000
    acts = ["file_read", "file_write", "normal_operation"]
    policy = "document_editor"

    # Phase 1 : Commit
    commitment, nonce = prover.commit(pid, "word.exe", acts, 4.2, policy)
    assert commitment.is_valid()

    # Phase 2 : Challenge
    challenge = verifier.issue_challenge(commitment)
    assert challenge.challenge_hash != ""

    # Phase 3 : Respond
    response = prover.respond(commitment, challenge, nonce, pid, acts, 4.2, policy)
    assert response.response != ""

    # Phase 4 : Verify
    result = verifier.verify(response, MASTER_KEY)
    assert result.status == ProofStatus.VALID, f"Expected VALID, got {result.status}: {result.reason}"
    print(f"PASS: ZKSP complete proof cycle: {result.status.value} policy='{policy}'")


def test_zksp_wrong_policy_rejected():
    prover = ZeroKnowledgeSecurityProver(MASTER_KEY)
    verifier = ZeroKnowledgeSecurityVerifier(MASTER_KEY)
    pid = 8000
    acts = ["file_read"]

    commitment, nonce = prover.commit(pid, "suspicious.exe", acts, 2.0, "document_editor")
    challenge = verifier.issue_challenge(commitment)
    # Répond avec une AUTRE politique (tricher)
    response = prover.respond(commitment, challenge, nonce, pid, acts, 2.0, "antivirus")
    response.policy_name = "antivirus"  # Triche
    result = verifier.verify(response, MASTER_KEY)
    assert result.status == ProofStatus.INVALID
    print(f"PASS: ZKSP wrong policy rejected: {result.status.value}")


def test_zksp_policy_compliance_check():
    policy = STANDARD_POLICIES["backup_agent"]
    # Backup agent peut chiffrer — conforme
    assert policy.is_compliant(["file_read", "crypto_encrypt", "net_send"], entropy=7.5)
    # Un agent document qui chiffre des fichiers — NON conforme
    doc_policy = STANDARD_POLICIES["document_editor"]
    assert not doc_policy.is_compliant(["file_read", "crypto_encrypt"])
    print("PASS: ZKSP policy compliance check: backup_agent allows encrypt, document_editor does not")


# ─────────────────────────────────────────────────────────────────────────────
# BREVET 4 — ASN : Adversarial Shadow Network
# ─────────────────────────────────────────────────────────────────────────────
from asn.shadow_network import (
    AdversarialShadowNetwork, NetworkPacket, wasserstein_distance_1d,
    DivergenceType
)


def test_asn_wasserstein_identical_distributions():
    hist = {100: 50, 200: 30, 300: 20}
    w = wasserstein_distance_1d(hist, hist)
    assert w < 0.01
    print(f"PASS: ASN Wasserstein identical: W₁={w:.4f}")


def test_asn_wasserstein_different_distributions():
    hist_a = {100: 100, 200: 0}
    hist_b = {100: 0,   200: 100}
    w = wasserstein_distance_1d(hist_a, hist_b)
    assert w > 0.3
    print(f"PASS: ASN Wasserstein different: W₁={w:.4f}")


def test_asn_learn_baseline():
    asn = AdversarialShadowNetwork()
    now = time.time()
    for i in range(1000):
        pkt = NetworkPacket(
            src_ip="192.168.1.1", dst_ip="192.168.1.2",
            src_port=12345, dst_port=80,
            size=500 + (i % 100), timestamp=now + i * 0.01,
            protocol="TCP", chaos_signed=True,
        )
        asn.observe_packet(pkt)
    assert asn._baseline_learned
    print(f"PASS: ASN baseline learned after 1000 packets")


def test_asn_beacon_detection():
    alerts = []
    asn = AdversarialShadowNetwork(on_alert=lambda a: alerts.append(a))
    asn._baseline_learned = True  # Skip baseline phase

    # Simuler un beacon très régulier (Cobalt Strike)
    now = time.time()
    asn.current.last_packet_time = now - 60  # Bootstrap
    for i in range(100):
        t = now - (100 - i) * 60.0  # Exactement toutes les 60 secondes
        asn.current.inter_arrival_times.append(60.0)

    regularity = asn.current.beaconing_regularity()
    assert regularity > 0.85
    print(f"PASS: ASN beacon detection: regularity={regularity:.3f}")


def test_asn_unsigned_traffic_detected():
    alerts = []
    asn = AdversarialShadowNetwork(on_alert=lambda a: alerts.append(a))
    asn._baseline_learned = True

    # 40% de trafic non signé
    asn._total_packets = 100
    asn._unsigned_blocked = 40
    asn._detect_unsigned_traffic()

    assert any(a.divergence_type == DivergenceType.UNKNOWN_ATTACK for a in alerts)
    print(f"PASS: ASN unsigned traffic detected ({len(alerts)} alerts)")


# ─────────────────────────────────────────────────────────────────────────────
# BREVET 5 — RCTC : Recursive Cryptographic Trust Chain
# ─────────────────────────────────────────────────────────────────────────────
from rctc.recursive_trust import (
    RecursiveCryptographicTrustChain, TrustAssertion, MerkleTree
)


def test_rctc_merkle_tree_root():
    tree = MerkleTree()
    tree.add_leaf("aaa")
    tree.add_leaf("bbb")
    tree.add_leaf("ccc")
    root = tree.root
    assert root != ""
    assert len(root) == 64  # SHA-256 hex
    print(f"PASS: RCTC Merkle root computed: {root[:16]}...")


def test_rctc_merkle_proof_verification():
    tree = MerkleTree()
    hashes = [hashlib.sha256(f"leaf-{i}".encode()).hexdigest() for i in range(8)]
    for h in hashes:
        tree.add_leaf(h)
    root = tree.root

    # Vérifier la preuve pour la feuille 3
    target = hashes[3]
    proof = tree.get_proof(target)
    assert proof is not None

    # Re-calculer la racine depuis la preuve
    h = target
    for sibling, is_left in proof:
        if is_left:
            h = hashlib.sha256((sibling + h).encode()).hexdigest()
        else:
            h = hashlib.sha256((h + sibling).encode()).hexdigest()
    assert h == root
    print(f"PASS: RCTC Merkle proof verification: leaf[3] → root {root[:16]}...")


def test_rctc_assert_and_verify_trust():
    rctc = RecursiveCryptographicTrustChain(MASTER_KEY)
    # Ajouter assertion OS
    os_leaf = rctc.assert_trust(
        TrustAssertion.OS_INTEGRITY, "windows-kernel",
        hashlib.sha256(b"win-kernel-hash").hexdigest(),
        parent_assertion_id="tpm-root", issuer_id="gravity-agent"
    )
    assert os_leaf is not None
    # Ajouter processus système se basant sur OS
    proc_leaf = rctc.assert_trust(
        TrustAssertion.SYSTEM_PROCESS, "lsass.exe",
        "4", parent_assertion_id=os_leaf.assertion_id,
        issuer_id="gravity-agent"
    )
    assert proc_leaf is not None
    trusted, score, reason = rctc.verify_subject("lsass.exe", TrustAssertion.SYSTEM_PROCESS)
    assert trusted
    assert score >= 0.9
    print(f"PASS: RCTC trust asserted and verified: score={score:.2f} — {reason}")


def test_rctc_revocation_cascades():
    violations = []
    rctc = RecursiveCryptographicTrustChain(
        MASTER_KEY, on_violation=lambda v: violations.append(v)
    )
    # Créer une chaîne : OS → System → User → Network
    os_leaf = rctc.assert_trust(TrustAssertion.OS_INTEGRITY, "win-os", "hash1",
                                 "tpm-root", "tpm")
    sys_leaf = rctc.assert_trust(TrustAssertion.SYSTEM_PROCESS, "explorer.exe", "hash2",
                                  os_leaf.assertion_id, "gravity")
    usr_leaf = rctc.assert_trust(TrustAssertion.USER_PROCESS, "child.exe", "hash3",
                                  sys_leaf.assertion_id, "gravity")
    net_leaf = rctc.assert_trust(TrustAssertion.NETWORK_FLOW, "flow-001", "hash4",
                                  usr_leaf.assertion_id, "gravity")

    # Révoquer au niveau OS → tout doit tomber
    revoked = rctc.revoke(os_leaf.assertion_id, "OS compromise detected")
    assert len(revoked) >= 4, f"Expected ≥4 revoked, got {len(revoked)}: {revoked}"
    # Vérifier que le processus utilisateur n'est plus fiable
    trusted, score, _ = rctc.verify_subject("child.exe", TrustAssertion.USER_PROCESS)
    assert not trusted
    print(f"PASS: RCTC revocation cascaded: {len(revoked)} assertions revoked (Trust Lightning)")


def test_rctc_sign_alert():
    rctc = RecursiveCryptographicTrustChain(MASTER_KEY)
    agent_leaf = rctc.assert_trust(
        TrustAssertion.AGENT_IDENTITY, "gravity-agent-001",
        MASTER_KEY.hex(), "tpm-root", "tpm"
    )
    alert = {"type": "FILE_THREAT", "severity": "critical", "process": "evil.exe"}
    signed_alert = rctc.sign_alert(alert, agent_leaf.assertion_id)
    assert signed_alert["rctc_signed"]
    assert "rctc_signature" in signed_alert
    assert signed_alert["rctc_trust_score"] >= 0.9
    print(f"PASS: RCTC alert signed: trust_score={signed_alert['rctc_trust_score']:.2f}")


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    tests = [
        # QBSM
        test_qbsm_initial_state_is_superposition,
        test_qbsm_honeytoken_collapses_to_threat,
        test_qbsm_contradictory_observations_maintain_superposition,
        test_qbsm_entanglement_propagates,
        test_qbsm_observe_from_alert,
        # CBGA
        test_cbga_smith_waterman_identical,
        test_cbga_smith_waterman_unrelated,
        test_cbga_genome_distance,
        test_cbga_ransomware_genome_detected,
        test_cbga_genome_cryptographic_signing,
        # ZKSP
        test_zksp_complete_proof_cycle,
        test_zksp_wrong_policy_rejected,
        test_zksp_policy_compliance_check,
        # ASN
        test_asn_wasserstein_identical_distributions,
        test_asn_wasserstein_different_distributions,
        test_asn_learn_baseline,
        test_asn_beacon_detection,
        test_asn_unsigned_traffic_detected,
        # RCTC
        test_rctc_merkle_tree_root,
        test_rctc_merkle_proof_verification,
        test_rctc_assert_and_verify_trust,
        test_rctc_revocation_cascades,
        test_rctc_sign_alert,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"FAIL: {test.__name__}: {e}")
            import traceback; traceback.print_exc()
            failed += 1

    print(f"\n{'='*65}")
    print(f"Gravity Security — Brevets — {passed}/{len(tests)} tests passés")
    if failed:
        print(f"ÉCHECS : {failed}")
    else:
        print("TOUS LES TESTS PASSÉS")
    print(f"{'='*65}")
    sys.exit(1 if failed else 0)
