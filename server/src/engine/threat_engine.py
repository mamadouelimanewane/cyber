"""
Gravity Security — Moteur de Décision de Menaces
Enrichit et classe les alertes reçues des agents.
"""

from typing import Dict, Any


SEVERITY_MAP = [
    (0.9, "critical"),
    (0.7, "high"),
    (0.5, "medium"),
    (0.2, "low"),
    (0.0, "info"),
]

TYPE_LABELS = {
    "SUSPICIOUS_PROCESS": "Processus suspect",
    "FILE_THREAT": "Fichier malveillant",
    "NAC_BLOCK": "Accès réseau bloqué",
    "SIGNATURE_MATCH": "Signature connue détectée",
}


class ThreatEngine:
    """
    Enrichit les alertes brutes avec :
    - Classification de sévérité
    - Label lisible
    - Recommandations d'action
    - Corrélation avec d'autres alertes (futur)
    """

    def enrich(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        score = float(alert.get("threat_score", 0.0))

        # Sévérité
        severity = "info"
        for threshold, label in SEVERITY_MAP:
            if score >= threshold:
                severity = label
                break

        alert["severity"] = severity
        alert["label"] = TYPE_LABELS.get(alert.get("type", ""), alert.get("type", "Alerte"))
        alert["action"] = self._recommend_action(alert)
        alert["enriched"] = True

        return alert

    def _recommend_action(self, alert: Dict) -> str:
        alert_type = alert.get("type", "")
        score = float(alert.get("threat_score", 0))

        if alert_type == "SUSPICIOUS_PROCESS":
            if score >= 0.9:
                return "ISOLER la machine et terminer le processus immédiatement"
            elif score >= 0.7:
                return "Surveiller et collecter les logs — préparer isolation"
            else:
                return "Journaliser et surveiller le comportement"

        elif alert_type == "FILE_THREAT":
            if score >= 0.8:
                return "QUARANTAINE du fichier — analyse forensique recommandée"
            else:
                return "Soumettre à analyse approfondie"

        elif alert_type == "NAC_BLOCK":
            return "Connexion bloquée automatiquement — vérifier la source"

        return "Surveiller"
