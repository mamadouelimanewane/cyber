"""
Analyseur de chaînes de processus — détecte les séquences parent→enfant malveillantes.

Modèle de menace principal :
  Office App → cmd.exe/powershell.exe → téléchargement réseau → exécution

C'est le vecteur utilisé dans 80%+ des attaques ciblées (macros, phishing).
"""

import re
from typing import Dict, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .process_monitor import ProcessNode


# Règles de chaînes suspectes : (parent_pattern, enfant_pattern, score, raison)
CHAIN_RULES = [
    # Office → shell (macro malveillante classique)
    (r"(winword|excel|powerpnt|outlook)\.exe", r"(cmd|powershell|wscript|cscript)\.exe",
     0.90, "Document Office lance un interpréteur shell — macro suspecte"),

    # Navigateur → shell (drive-by download)
    (r"(chrome|firefox|msedge|iexplore)\.exe", r"(cmd|powershell|wscript)\.exe",
     0.85, "Navigateur lance un shell — possible drive-by download"),

    # PDF → shell
    (r"(acrord32|acrobat|foxitreader)\.exe", r"(cmd|powershell|wscript)\.exe",
     0.92, "Lecteur PDF lance un shell — exploit PDF probable"),

    # LOLBin → réseau (certutil, bitsadmin téléchargent des payloads)
    (r".*", r"(certutil|bitsadmin)\.exe",
     0.75, "Outil système utilisé pour téléchargement — LOLBin suspect"),

    # Double hop shell (cmd → powershell ou powershell → cmd)
    (r"cmd\.exe", r"powershell\.exe", 0.70, "Double hop shell cmd→powershell"),
    (r"powershell\.exe", r"cmd\.exe", 0.70, "Double hop shell powershell→cmd"),

    # Shell → exécutable dans temp/appdata (payload téléchargé)
    (r"(cmd|powershell|wscript)\.exe", r".*\.(exe|dll|bat|vbs|js|hta)$",
     0.80, "Shell lance un exécutable depuis répertoire temporaire"),

    # MSHTA (HTML Application — vecteur fréquent)
    (r".*", r"mshta\.exe", 0.88, "Lancement de mshta.exe — vecteur HTA détecté"),

    # Regsvr32 / Rundll32 avec URL (Squiblydoo attack)
    (r".*", r"(regsvr32|rundll32)\.exe", 0.72, "Lancement de regsvr32/rundll32 suspect"),
]

# Patterns dans la ligne de commande qui augmentent le score
CMDLINE_PATTERNS = [
    (r"-[Ee][Nn][Cc]", 0.30, "PowerShell encodé en base64"),
    (r"-[Ww]indow[Ss]tyle\s+[Hh]idden", 0.25, "Fenêtre cachée"),
    (r"-[Nn]o[Pp]rofile", 0.15, "Bypass profil PowerShell"),
    (r"[Ii][Ee][Xx]|[Ii]nvoke-[Ee]xpression", 0.35, "IEX / Invoke-Expression détecté"),
    (r"[Dd]ownload[Ss]tring|[Ww]eb[Cc]lient", 0.40, "Téléchargement via PowerShell"),
    (r"[Bb]y[Pp]ass|[Uu]nrestricted", 0.30, "Bypass politique d'exécution"),
    (r"http[s]?://", 0.35, "URL dans les arguments"),
    (r"\\[Tt]emp\\|\\[Aa]ppdata\\", 0.20, "Exécution depuis dossier temporaire"),
    (r"[Ss]ch[Tt]asks|schtasks\.exe", 0.25, "Création de tâche planifiée"),
    (r"net\s+(user|localgroup|share)", 0.35, "Énumération/modification comptes réseau"),
    (r"[Ww][Mm][Ii][Cc]|wmi", 0.20, "Utilisation de WMI"),
    (r"[Rr]eg(add|delete|export|import)", 0.25, "Modification du registre"),
]


class ProcessChainAnalyzer:
    """
    Analyse un ProcessNode dans le contexte de l'arbre de processus complet
    et retourne un score de menace [0.0, 1.0] avec une explication.
    """

    def analyze(self, node, all_processes: Dict) -> Tuple[float, str]:
        score = 0.0
        reasons = []

        parent_name = node.parent_name or self._get_parent_name(node.parent_pid, all_processes)
        child_name = node.name

        # 1. Vérification des règles de chaînes parent→enfant
        for parent_pat, child_pat, rule_score, reason in CHAIN_RULES:
            if re.search(parent_pat, parent_name, re.I) and re.search(child_pat, child_name, re.I):
                score = max(score, rule_score)
                reasons.append(reason)

        # 2. Analyse de la ligne de commande
        cmdline = " ".join(node.cmdline)
        for pattern, extra_score, reason in CMDLINE_PATTERNS:
            if re.search(pattern, cmdline, re.I):
                score = min(1.0, score + extra_score)
                reasons.append(reason)

        # 3. Connexions réseau depuis un LOLBin
        if node.name in self._lolbins() and node.connections:
            score = min(1.0, score + 0.30)
            reasons.append(f"{node.name} établit des connexions réseau")

        # 4. Profondeur de chaîne suspecte (shell → shell → shell)
        depth = self._chain_depth(node, all_processes)
        if depth >= 3:
            score = min(1.0, score + 0.15 * (depth - 2))
            reasons.append(f"Chaîne d'exécution profonde (depth={depth})")

        final_reason = " | ".join(reasons) if reasons else ""
        return round(score, 3), final_reason

    def _get_parent_name(self, parent_pid: int, all_processes: Dict) -> str:
        parent = all_processes.get(parent_pid)
        return parent.name if parent else ""

    def _chain_depth(self, node, all_processes: Dict, max_depth: int = 10) -> int:
        depth = 0
        current = node
        visited = set()
        while current and current.parent_pid and depth < max_depth:
            if current.parent_pid in visited:
                break
            visited.add(current.pid)
            parent = all_processes.get(current.parent_pid)
            if parent is None:
                break
            current = parent
            depth += 1
        return depth

    @staticmethod
    def _lolbins():
        return {
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
            "bitsadmin.exe", "wmic.exe", "msiexec.exe",
        }
