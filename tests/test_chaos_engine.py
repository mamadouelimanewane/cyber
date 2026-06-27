"""Tests unitaires — Mathematical Chaos Engine"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent", "src"))

from chaos_engine.key_manager import ChaosKeyManager
from chaos_engine.chaos_engine import ChaosEngine


def test_key_rotation():
    """Deux secondes consécutives → clés différentes."""
    mgr = ChaosKeyManager("secret-test")
    k1 = mgr.derive_key(1000)
    k2 = mgr.derive_key(1001)
    assert k1 != k2, "Les clés doivent être différentes à chaque seconde"
    assert len(k1) == 32, "Clé 256 bits attendue"
    print("✓ Rotation des clés OK")


def test_same_second_same_key():
    """Même seconde → même clé (pour synchronisation inter-agents)."""
    mgr = ChaosKeyManager("secret-test")
    k1 = mgr.derive_key(9999)
    k2 = mgr.derive_key(9999)
    assert k1 == k2
    print("✓ Cohérence de clé intra-seconde OK")


def test_different_secrets_different_keys():
    """Secrets différents → clés totalement différentes."""
    mgr1 = ChaosKeyManager("secret-A")
    mgr2 = ChaosKeyManager("secret-B")
    k1 = mgr1.derive_key(5000)
    k2 = mgr2.derive_key(5000)
    assert k1 != k2
    print("✓ Isolation des secrets OK")


def test_encrypt_decrypt_roundtrip():
    """Chiffrement puis déchiffrement → données intactes."""
    engine = ChaosEngine("agent-test", "shared-secret")
    plaintext = b"Hello Gravity Security!"
    ciphertext = engine.encrypt(plaintext)
    assert ciphertext != plaintext
    decrypted, valid = engine.decrypt(ciphertext)
    assert valid, "Déchiffrement doit être valide"
    assert decrypted == plaintext, f"Attendu: {plaintext}, Obtenu: {decrypted}"
    print("✓ Encrypt/Decrypt roundtrip OK")


def test_tampered_packet_rejected():
    """Paquet modifié → rejeté."""
    engine = ChaosEngine("agent-test", "shared-secret")
    ciphertext = engine.encrypt(b"Data confidentielle")
    # Modifier un octet au milieu
    tampered = bytearray(ciphertext)
    tampered[20] ^= 0xFF
    _, valid = engine.decrypt(bytes(tampered))
    assert not valid, "Paquet altéré doit être rejeté"
    print("✓ Détection de paquet altéré OK")


def test_nac_sign_verify():
    """Signature NAC valide → acceptée, invalide → rejetée."""
    engine = ChaosEngine("agent-001", "shared-secret")
    packet = b"paquet reseau test"
    signed = engine.sign_packet(packet)
    assert engine.verify_packet(signed)
    # Modifier la signature
    bad = bytearray(signed)
    bad[-1] ^= 0x01
    assert not engine.verify_packet(bytes(bad))
    print("✓ Signature NAC OK")


def test_lorenz_sequence_chaos():
    """Conditions initiales différentes → séquences différentes (sensibilité au chaos)."""
    s1 = ChaosEngine.lorenz_sequence(1.0, 1.0, 1.0, steps=50)
    # Perturbation plus grande pour observer la divergence sur 50 pas
    s2 = ChaosEngine.lorenz_sequence(1.1, 1.0, 1.0, steps=50)
    differ = sum(1 for a, b in zip(s1, s2) if a != b)
    assert differ > 10, f"Séquences chaotiques doivent diverger, seulement {differ} octets différents"
    # Vérifier que les deux séquences sont distinctes dans leur ensemble
    assert s1 != s2
    print(f"✓ Chaos de Lorenz OK — {differ}/50 octets divergents entre conditions initiales différentes")


if __name__ == "__main__":
    print("\n=== Tests Gravity Security — Chaos Engine ===\n")
    test_key_rotation()
    test_same_second_same_key()
    test_different_secrets_different_keys()
    test_encrypt_decrypt_roundtrip()
    test_tampered_packet_rejected()
    test_nac_sign_verify()
    test_lorenz_sequence_chaos()
    print("\n✅ Tous les tests passent !\n")
