"""Tests unitaires — Scanner Comportemental"""

import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent", "src"))

from scanner.behavioral_scanner import BehavioralScanner

scanner = BehavioralScanner()


def test_shannon_entropy_random():
    """Données aléatoires → entropie proche de 8."""
    import os as _os
    data = _os.urandom(10000)
    entropy = BehavioralScanner._shannon_entropy(data)
    assert entropy > 7.5, f"Entropie trop basse: {entropy}"
    print(f"✓ Entropie données aléatoires: {entropy:.3f}/8.0")


def test_shannon_entropy_repeated():
    """Données répétitives → entropie proche de 0."""
    data = b"\x00" * 10000
    entropy = BehavioralScanner._shannon_entropy(data)
    assert entropy == 0.0
    print(f"✓ Entropie données uniformes: {entropy:.3f}/8.0")


def test_high_entropy_file_flagged():
    """Fichier .exe avec haute entropie doit être suspect."""
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        # Simule un exécutable packé (haute entropie)
        import os as _os
        f.write(b"MZ" + _os.urandom(5000))
        path = f.name
    try:
        result = scanner.scan_file(path)
        assert result.entropy > 7.0
        assert result.threat_score > 0.0
        print(f"✓ Fichier haute entropie signalé (score={result.threat_score:.2f}, entropy={result.entropy:.2f})")
    finally:
        os.unlink(path)


def test_normal_text_file_not_flagged():
    """Fichier texte normal → pas de menace."""
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
        f.write("Hello world " * 1000)
        path = f.name
    try:
        result = scanner.scan_file(path)
        # Fichier .txt ne passe pas les filtres d'extension du scan_directory
        # mais scan_file direct doit donner un score bas
        assert result.threat_score < 0.5
        print(f"✓ Fichier texte normal (score={result.threat_score:.2f})")
    finally:
        os.unlink(path)


def test_suspicious_strings_detected():
    """Fichier avec strings suspectes → score élevé."""
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        content = (
            b"MZ" + b"\x00" * 100 +
            b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00" +
            b"powershell\x00cmd.exe\x00http://malware.example.com\x00" +
            b"SetWindowsHookEx\x00GetAsyncKeyState\x00" +
            b"\x00" * 200
        )
        f.write(content)
        path = f.name
    try:
        result = scanner.scan_file(path)
        assert result.threat_score >= 0.30, f"Score trop bas: {result.threat_score}"
        assert len(result.reasons) > 0
        print(f"✓ Strings suspectes détectées (score={result.threat_score:.2f}): {result.reasons[:2]}")
    finally:
        os.unlink(path)


def test_scan_nonexistent_file():
    """Fichier inexistant → résultat vide sans crash."""
    result = scanner.scan_file("/nonexistent/path/malware.exe")
    assert not result.is_threat
    assert result.threat_score == 0.0
    print("✓ Fichier inexistant géré proprement")


if __name__ == "__main__":
    print("\n=== Tests Gravity Security — Behavioral Scanner ===\n")
    test_shannon_entropy_random()
    test_shannon_entropy_repeated()
    test_high_entropy_file_flagged()
    test_normal_text_file_not_flagged()
    test_suspicious_strings_detected()
    test_scan_nonexistent_file()
    print("\n✅ Tous les tests passent !\n")
