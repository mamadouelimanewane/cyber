"""
Gravity Security — Kill Chain AI Engine
Mappe chaque alerte sur le framework MITRE ATT&CK et détermine
automatiquement la phase de l'attaque et la réponse optimale.

Le Kill Chain est le concept Lockheed Martin / MITRE qui décrit
les 7-14 phases d'une cyberattaque. En identifiant la phase actuelle,
on peut couper l'attaque au meilleur moment sans perturber la production.

MITRE ATT&CK Tactics (TA0001 à TA0040) :
TA0001 Initial Access → TA0002 Execution → TA0003 Persistence →
TA0004 Privilege Escalation → TA0005 Defense Evasion →
TA0006 Credential Access → TA0007 Discovery → TA0008 Lateral Movement →
TA0009 Collection → TA0010 Exfiltration → TA0011 Command and Control →
TA0040 Impact
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import time
import logging

logger = logging.getLogger("gravity.kill_chain")


@dataclass
class MITRETechnique:
    technique_id: str          # Ex: T1059.001
    name: str
    tactic: str                # Ex: TA0002 — Execution
    tactic_name: str
    description: str
    severity: str              # critical / high / medium
    detection_signals: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)


@dataclass
class KillChainPhase:
    phase_id: int             # 1-8 (simplifié depuis les 14 de MITRE)
    name: str
    description: str
    attacker_goal: str
    defender_action: str
    urgency: str              # immediate / high / medium


@dataclass
class AttackCampaign:
    """Regroupe des alertes liées en une campagne d'attaque cohérente."""
    campaign_id: str
    agent_id: str
    start_time: float
    last_seen: float
    alerts: List[Dict] = field(default_factory=list)
    techniques_seen: List[str] = field(default_factory=list)
    current_phase: int = 1
    attacker_goal: str = "Inconnu"
    risk_score: float = 0.0
    recommended_action: str = ""
    auto_contained: bool = False


# ------------------------------------------------------------------ #
#  Base de données MITRE ATT&CK (sous-ensemble clé)                #
# ------------------------------------------------------------------ #

MITRE_TECHNIQUES: Dict[str, MITRETechnique] = {
    "T1566": MITRETechnique(
        "T1566", "Phishing", "TA0001", "Initial Access",
        "Email/spear-phishing pour obtenir accès initial",
        "high",
        ["Pièce jointe suspecte", "Lien externe dans email"],
        ["Formation utilisateurs", "Filtrage email", "MFA"],
    ),
    "T1059": MITRETechnique(
        "T1059", "Command and Scripting Interpreter", "TA0002", "Execution",
        "Exécution via PowerShell, cmd, bash, Python...",
        "high",
        ["powershell.exe lancé par Office", "cmd.exe avec arguments suspects"],
        ["Politique d'exécution PowerShell", "Blocage LOLBins", "AppLocker"],
    ),
    "T1059.001": MITRETechnique(
        "T1059.001", "PowerShell", "TA0002", "Execution",
        "Abus de PowerShell pour l'exécution de commandes",
        "high",
        ["Commandes encodées base64", "IEX/Invoke-Expression", "DownloadString"],
        ["Constrained Language Mode", "AMSI", "Script Block Logging"],
    ),
    "T1055": MITRETechnique(
        "T1055", "Process Injection", "TA0004", "Privilege Escalation",
        "Injection de code dans d'autres processus",
        "critical",
        ["VirtualAllocEx + WriteProcessMemory + CreateRemoteThread", "Régions mémoire RWX"],
        ["Contrôle d'intégrité mémoire", "EDR comportemental"],
    ),
    "T1003": MITRETechnique(
        "T1003", "OS Credential Dumping", "TA0006", "Credential Access",
        "Extraction de credentials depuis la mémoire (LSASS, SAM, NTDS)",
        "critical",
        ["Accès à LSASS", "Mimikatz strings", "reg save SAM"],
        ["Credential Guard", "Protected Users group", "MFA"],
    ),
    "T1021": MITRETechnique(
        "T1021", "Remote Services", "TA0008", "Lateral Movement",
        "Déplacement latéral via SMB, WMI, RDP, PSExec...",
        "critical",
        ["Connexions SMB vers autres machines", "WMI remote execution", "PsExec"],
        ["Segmentation réseau", "Least privilege", "NAC"],
    ),
    "T1083": MITRETechnique(
        "T1083", "File and Directory Discovery", "TA0007", "Discovery",
        "Découverte des fichiers et dossiers intéressants",
        "medium",
        ["dir/ls dans Temp/Documents", "Recherche de fichiers .xlsx .pdf .docx"],
        ["Honeytokens", "Audit d'accès fichiers"],
    ),
    "T1041": MITRETechnique(
        "T1041", "Exfiltration Over C2 Channel", "TA0010", "Exfiltration",
        "Exfiltration de données via le canal C2 existant",
        "critical",
        ["Upload de données volumineuses vers IP externe", "DNS exfiltration"],
        ["DLP", "Inspection SSL/TLS", "Limitation débit sortant"],
    ),
    "T1071": MITRETechnique(
        "T1071", "Application Layer Protocol", "TA0011", "Command and Control",
        "Communication C2 via HTTP/S, DNS, SMTP...",
        "high",
        ["Connexions HTTP périodiques vers IP inconnues", "Beacon pattern"],
        ["Proxy d'inspection", "Blocage DNS non autorisé", "Threat intel"],
    ),
    "T1486": MITRETechnique(
        "T1486", "Data Encrypted for Impact", "TA0040", "Impact",
        "Chiffrement des données pour rançon (ransomware)",
        "critical",
        ["Suppression VSS", "Renommage massif de fichiers", "bcdedit modifié"],
        ["Backup hors ligne", "EDR avec blocage ransomware", "Snapshots fréquents"],
    ),
    "T1078": MITRETechnique(
        "T1078", "Valid Accounts", "TA0001", "Initial Access",
        "Utilisation de comptes légitimes compromis",
        "high",
        ["Connexion depuis IP inhabituelle", "Horaire anormal", "Comportement UEBA suspect"],
        ["MFA", "UEBA", "Privileged Access Management"],
    ),
    "T1190": MITRETechnique(
        "T1190", "Exploit Public-Facing Application", "TA0001", "Initial Access",
        "Exploitation de vulnérabilités d'applications exposées (web, VPN, etc.)",
        "critical",
        ["Requêtes HTTP anormales", "Codes d'erreur inhabituels", "Payload dans params"],
        ["WAF", "Patch management", "Segmentation DMZ"],
    ),
    "T1547": MITRETechnique(
        "T1547", "Boot or Logon Autostart Execution", "TA0003", "Persistence",
        "Persistance via clés de démarrage registre, tâches planifiées...",
        "high",
        ["Nouvelles clés HKLM Run", "Tâches planifiées suspectes", "Services créés"],
        ["Moniteur d'intégrité registre", "AppLocker", "Audit GPO"],
    ),
    "T1562": MITRETechnique(
        "T1562", "Impair Defenses", "TA0005", "Defense Evasion",
        "Désactivation des outils de sécurité (AV, firewall, logging)",
        "critical",
        ["net stop", "sc delete", "Set-MpPreference -DisableRealtimeMonitoring"],
        ["Protection anti-tamper", "Alertes sur arrêt d'agents", "SIEM"],
    ),
}

# ------------------------------------------------------------------ #
#  Phases du Kill Chain (simplifié)                                 #
# ------------------------------------------------------------------ #

KILL_CHAIN_PHASES = {
    1: KillChainPhase(1, "Reconnaissance", "Collecte d'informations sur la cible",
                      "Identifier les systèmes et vulnérabilités", "Monitorer les scans réseau", "medium"),
    2: KillChainPhase(2, "Initial Access", "Premier point d'entrée sur le réseau",
                      "Établir un foothold", "ISOLER la machine compromise immédiatement", "immediate"),
    3: KillChainPhase(3, "Execution", "Exécution du code malveillant",
                      "Faire tourner le payload", "Bloquer l'exécution — suspendre les processus suspects", "immediate"),
    4: KillChainPhase(4, "Persistence", "Mécanisme de persistance installé",
                      "Survivre aux redémarrages", "Nettoyer les mécanismes de persistance", "high"),
    5: KillChainPhase(5, "Privilege Escalation", "Élévation des droits",
                      "Obtenir des droits admin/SYSTEM", "Révoquer les tokens — forcer reauth", "immediate"),
    6: KillChainPhase(6, "Lateral Movement", "Déplacement vers d'autres machines",
                      "Étendre la compromission", "ISOLER le segment réseau — bloquer SMB interne", "immediate"),
    7: KillChainPhase(7, "Collection & Exfiltration", "Vol de données",
                      "Collecter et exfiltrer des données sensibles", "Bloquer trafic sortant — DLP", "immediate"),
    8: KillChainPhase(8, "Impact", "Action finale destructrice",
                      "Ransomware, sabotage, destruction", "ISOLER TOUT — activer DR immédiatement", "immediate"),
}

# Mapping type d'alerte → phase kill chain
ALERT_TO_PHASE = {
    "SUSPICIOUS_PROCESS": 3,
    "FILE_THREAT": 3,
    "NAC_BLOCK": 6,
    "SIGNATURE_MATCH": 3,
    "MEMORY_THREAT": 3,
    "DNA_MUTATION": 3,
    "HONEYTOKEN_TRIGGERED": 6,
}

TECHNIQUE_TO_PHASE = {
    "TA0001": 2, "TA0002": 3, "TA0003": 4,
    "TA0004": 5, "TA0005": 4, "TA0006": 5,
    "TA0007": 6, "TA0008": 6, "TA0009": 7,
    "TA0010": 7, "TA0011": 3, "TA0040": 8,
}


class MITREEngine:
    """
    Moteur d'analyse MITRE ATT&CK — mappe les alertes sur les techniques,
    regroupe en campagnes, détermine la phase et recommande les actions.
    """

    def __init__(self):
        self._campaigns: Dict[str, AttackCampaign] = {}
        self._alert_history: List[Dict] = []

    def analyze_alert(self, alert: Dict) -> Dict:
        """
        Analyse une alerte et retourne l'enrichissement MITRE ATT&CK.
        Identifie ou crée une campagne d'attaque associée.
        """
        # Identifier la technique MITRE
        technique_id = self._extract_technique(alert)
        technique = MITRE_TECHNIQUES.get(technique_id)

        # Déterminer la phase kill chain
        phase_num = self._determine_phase(alert, technique)
        phase = KILL_CHAIN_PHASES.get(phase_num, KILL_CHAIN_PHASES[3])

        # Grouper dans une campagne
        campaign = self._get_or_create_campaign(alert)
        campaign.alerts.append(alert)
        if technique_id and technique_id not in campaign.techniques_seen:
            campaign.techniques_seen.append(technique_id)
        campaign.current_phase = max(campaign.current_phase, phase_num)
        campaign.last_seen = time.time()
        campaign.risk_score = min(1.0, len(campaign.techniques_seen) * 0.15 + alert.get("threat_score", 0) * 0.5)
        campaign.attacker_goal = self._infer_goal(campaign)
        campaign.recommended_action = phase.defender_action

        enriched = {
            **alert,
            "mitre_technique_id": technique_id,
            "mitre_technique_name": technique.name if technique else "Inconnu",
            "mitre_tactic": technique.tactic_name if technique else "Inconnu",
            "kill_chain_phase": phase_num,
            "kill_chain_phase_name": phase.name,
            "kill_chain_urgency": phase.urgency,
            "campaign_id": campaign.campaign_id,
            "campaign_risk": campaign.risk_score,
            "attacker_goal": campaign.attacker_goal,
            "defender_action": campaign.recommended_action,
            "mitigations": technique.mitigations if technique else [],
        }

        if phase_num >= 6 or campaign.risk_score >= 0.75:
            logger.critical(
                f"[KILL CHAIN] Phase {phase_num} ({phase.name}) détectée — "
                f"Campagne {campaign.campaign_id} — Action: {phase.defender_action}"
            )

        return enriched

    def _extract_technique(self, alert: Dict) -> str:
        """Extrait ou déduit l'identifiant de technique MITRE."""
        # Technique déjà fournie par l'agent
        if "mitre" in alert:
            mitre_str = alert["mitre"]
            for tech_id in MITRE_TECHNIQUES:
                if tech_id in mitre_str:
                    return tech_id

        # Déduction depuis le type d'alerte et le contenu
        alert_type = alert.get("type", "")
        reason = (alert.get("reason") or "").lower()
        process = (alert.get("process") or "").lower()

        if "ransomware" in reason or "vssadmin" in reason or "encrypt" in reason:
            return "T1486"
        if "lsass" in reason or "mimikatz" in reason or "credential" in reason:
            return "T1003"
        if "powershell" in process and ("base64" in reason or "enc" in reason):
            return "T1059.001"
        if "powershell" in process or "cmd" in process or "wscript" in process:
            return "T1059"
        if "injection" in reason or "memory" in reason.lower() or alert_type == "MEMORY_THREAT":
            return "T1055"
        if "honeytoken" in alert_type.lower():
            return "T1083"
        if "dna" in alert_type.lower():
            return "T1036"
        if "nac" in alert_type.lower():
            return "T1021"
        if "run" in reason or "schtask" in reason or "persist" in reason:
            return "T1547"
        if "disable" in reason or "stop" in reason or "tamper" in reason:
            return "T1562"

        return "T1059"

    def _determine_phase(self, alert: Dict, technique: Optional[MITRETechnique]) -> int:
        if technique:
            return TECHNIQUE_TO_PHASE.get(technique.tactic, 3)
        return ALERT_TO_PHASE.get(alert.get("type", ""), 3)

    def _get_or_create_campaign(self, alert: Dict) -> AttackCampaign:
        """Regroupe les alertes d'un même agent en campagne."""
        agent_id = alert.get("agent_id", "unknown")
        # Même campagne si alerte du même agent dans les 2 dernières heures
        for cid, campaign in self._campaigns.items():
            if campaign.agent_id == agent_id and (time.time() - campaign.last_seen) < 7200:
                return campaign

        # Nouvelle campagne
        import hashlib
        campaign_id = "ATK-" + hashlib.sha256(f"{agent_id}{time.time()}".encode()).hexdigest()[:8].upper()
        campaign = AttackCampaign(
            campaign_id=campaign_id,
            agent_id=agent_id,
            start_time=time.time(),
            last_seen=time.time(),
        )
        self._campaigns[campaign_id] = campaign
        logger.info(f"Nouvelle campagne d'attaque détectée: {campaign_id} sur {agent_id}")
        return campaign

    def _infer_goal(self, campaign: AttackCampaign) -> str:
        """Infère l'objectif de l'attaquant depuis les techniques observées."""
        techs = set(campaign.techniques_seen)
        if "T1486" in techs:
            return "Ransomware — Extorsion financière"
        if "T1003" in techs and "T1021" in techs:
            return "APT — Espionnage / Mouvement latéral"
        if "T1041" in techs or "T1083" in techs:
            return "Exfiltration de données"
        if "T1055" in techs:
            return "Élévation de privilèges / Persistance furtive"
        if "T1071" in techs:
            return "Command & Control — Accès persistant"
        return "Accès initial / Reconnaissance"

    def get_campaigns(self) -> List[Dict]:
        return [
            {
                "campaign_id": c.campaign_id,
                "agent_id": c.agent_id,
                "start_time": c.start_time,
                "last_seen": c.last_seen,
                "phase": c.current_phase,
                "phase_name": KILL_CHAIN_PHASES.get(c.current_phase, KILL_CHAIN_PHASES[1]).name,
                "techniques": c.techniques_seen,
                "risk_score": c.risk_score,
                "attacker_goal": c.attacker_goal,
                "recommended_action": c.recommended_action,
                "alert_count": len(c.alerts),
            }
            for c in self._campaigns.values()
        ]

    def get_technique_info(self, technique_id: str) -> Optional[Dict]:
        t = MITRE_TECHNIQUES.get(technique_id)
        if not t:
            return None
        return {
            "id": t.technique_id, "name": t.name,
            "tactic": t.tactic_name, "severity": t.severity,
            "description": t.description,
            "mitigations": t.mitigations,
            "detection_signals": t.detection_signals,
        }
