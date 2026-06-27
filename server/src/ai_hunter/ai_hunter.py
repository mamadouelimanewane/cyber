"""
Gravity Security — AI Threat Hunter
Interface langage naturel pour investiguer les menaces.

Permet aux analystes (même non-experts) de poser des questions en français :
- "Montre-moi tous les processus PowerShell lancés hier soir"
- "Est-ce que quelqu'un a accédé à des données depuis une IP étrangère ?"
- "Quel est l'agent le plus à risque en ce moment ?"
- "Y a-t-il eu des tentatives de mouvement latéral cette semaine ?"

Le moteur traduit ces questions en requêtes structurées sur la base
d'alertes, puis génère une réponse en langage naturel avec les preuves.
"""

import re
import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta

logger = logging.getLogger("gravity.ai_hunter")


# ------------------------------------------------------------------ #
#  Parseur de questions en langage naturel                          #
# ------------------------------------------------------------------ #

class NLQueryParser:
    """
    Parseur de requêtes en langage naturel → filtres structurés.
    Gère le français et l'anglais.
    """

    TIME_PATTERNS = [
        (r"hier soir|last night", lambda: (
            datetime.now().replace(hour=18, minute=0, second=0) - timedelta(days=1),
            datetime.now().replace(hour=23, minute=59, second=59) - timedelta(days=1)
        )),
        (r"hier|yesterday", lambda: (
            datetime.now().replace(hour=0,minute=0,second=0) - timedelta(days=1),
            datetime.now().replace(hour=23,minute=59,second=59) - timedelta(days=1)
        )),
        (r"cette semaine|this week", lambda: (
            datetime.now() - timedelta(days=7), datetime.now()
        )),
        (r"les? (\d+) derni[eè]re?s? heures?|last (\d+) hours?", None),
        (r"aujourd'hui|today", lambda: (
            datetime.now().replace(hour=0,minute=0,second=0), datetime.now()
        )),
        (r"24 heures|24h", lambda: (datetime.now() - timedelta(hours=24), datetime.now())),
    ]

    ENTITY_PATTERNS = {
        "process": [
            r"processus?\s+([a-zA-Z0-9_.-]+\.exe)",
            r"([a-zA-Z0-9_.-]+\.exe)",
            r"powershell|cmd|wscript|mshta|rundll32",
        ],
        "agent": [
            r"agent\s+([a-zA-Z0-9_-]+)",
            r"machine\s+([a-zA-Z0-9_-]+)",
            r"sur\s+([A-Z][A-Z0-9_-]+)",
        ],
        "user": [
            r"utilisateur\s+([a-zA-Z0-9_.-]+)",
            r"user\s+([a-zA-Z0-9_.-]+)",
            r"compte\s+([a-zA-Z0-9_.-]+)",
        ],
        "ip": [
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
        ],
    }

    INTENT_PATTERNS = {
        "list_threats": [
            r"montre|affiche|liste|donne|quels?|quelles?|show|list|get",
        ],
        "count": [
            r"combien|nombre|count|how many",
        ],
        "explain": [
            r"explique|qu'est-ce|pourquoi|explain|why|what is",
        ],
        "status": [
            r"statut|état|status|est-ce que|y a-t-il|is there",
        ],
        "top_risk": [
            r"le plus.*risque|most.*risk|highest.*threat|plus dangereux",
        ],
    }

    def parse(self, question: str) -> Dict:
        """Parse une question en langage naturel et retourne les filtres."""
        q = question.lower()
        filters = {
            "time_range": None,
            "processes": [],
            "agents": [],
            "users": [],
            "ips": [],
            "severity": None,
            "alert_type": None,
            "intent": "list_threats",
            "limit": 10,
        }

        # Temps
        for pattern, time_fn in self.TIME_PATTERNS:
            m = re.search(pattern, q, re.I)
            if m:
                if time_fn:
                    start, end = time_fn()
                    filters["time_range"] = (start.timestamp(), end.timestamp())
                elif "heures" in pattern or "hours" in pattern:
                    hours = int(m.group(1) or m.group(2))
                    filters["time_range"] = (
                        (datetime.now() - timedelta(hours=hours)).timestamp(),
                        datetime.now().timestamp()
                    )
                break

        if not filters["time_range"]:
            # Par défaut : dernières 24h
            filters["time_range"] = (
                (datetime.now() - timedelta(hours=24)).timestamp(),
                datetime.now().timestamp()
            )

        # Entités
        for entity_type, patterns in self.ENTITY_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, q, re.I)
                if matches:
                    key = entity_type + "s"
                    filters[key] = list(set(matches))[:5]

        # Sévérité
        if any(w in q for w in ["critique", "critical", "urgent", "grave"]):
            filters["severity"] = "critical"
        elif any(w in q for w in ["élevé", "high", "important"]):
            filters["severity"] = "high"

        # Types d'alertes
        if any(w in q for w in ["mémoire", "memory", "ram", "shellcode"]):
            filters["alert_type"] = "MEMORY_THREAT"
        elif any(w in q for w in ["dna", "mutation", "comportement"]):
            filters["alert_type"] = "DNA_MUTATION"
        elif any(w in q for w in ["honeytoken", "piège", "leurre"]):
            filters["alert_type"] = "HONEYTOKEN_TRIGGERED"
        elif any(w in q for w in ["réseau", "network", "lateral", "latéral", "mouvement"]):
            filters["alert_type"] = "NAC_BLOCK"
        elif any(w in q for w in ["utilisateur", "user", "compte", "account", "ueba"]):
            filters["alert_type"] = "UEBA_ANOMALY"
        elif any(w in q for w in ["ransomware", "chiffrement", "rançon"]):
            filters["alert_type"] = "FILE_THREAT"

        # Intention
        for intent, patterns in self.INTENT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, q, re.I):
                    filters["intent"] = intent
                    break

        # Limite
        m = re.search(r"(\d+)\s*(premiers?|derniers?|top|first|last)", q)
        if m:
            filters["limit"] = min(50, int(m.group(1)))

        return filters


class AIThreatHunter:
    """
    AI Threat Hunter — interface langage naturel pour investigations.

    Utilise le parseur NL pour comprendre les questions,
    interroge la base d'alertes, et génère des réponses claires.
    """

    def __init__(self, database=None):
        self.db = database
        self.parser = NLQueryParser()
        self._conversation_history: List[Dict] = []

    def ask(self, question: str, db=None) -> Dict:
        """
        Répond à une question en langage naturel sur les données de sécurité.
        Retourne la réponse + les preuves + les visualisations suggérées.
        """
        if db:
            self.db = db

        self._conversation_history.append({"role": "user", "content": question, "timestamp": time.time()})

        # 1. Parser la question
        filters = self.parser.parse(question)

        # 2. Exécuter la requête
        results = self._execute_query(filters)

        # 3. Générer la réponse
        response = self._generate_response(question, filters, results)

        self._conversation_history.append({
            "role": "assistant", "content": response["text"],
            "timestamp": time.time(), "data": results
        })

        return response

    def _execute_query(self, filters: Dict) -> Dict:
        """Exécute les filtres sur la base de données."""
        if not self.db:
            return {"alerts": [], "count": 0, "agents": [], "stats": {}}

        try:
            alerts = self.db.get_alerts(limit=200)

            # Filtrer par temps
            if filters["time_range"]:
                start_ts, end_ts = filters["time_range"]
                alerts = [a for a in alerts
                         if start_ts <= (a.get("timestamp") or 0) <= end_ts]

            # Filtrer par sévérité
            if filters["severity"]:
                alerts = [a for a in alerts if a.get("severity") == filters["severity"]]

            # Filtrer par type
            if filters["alert_type"]:
                alerts = [a for a in alerts if a.get("type") == filters["alert_type"]]

            # Filtrer par processus
            if filters["processes"]:
                procs = [p.lower() for p in filters["processes"]]
                alerts = [a for a in alerts
                         if any(p in (a.get("process") or "").lower() for p in procs)]

            # Filtrer par agent
            if filters["agents"]:
                agent_ids = [ag.lower() for ag in filters["agents"]]
                alerts = [a for a in alerts
                         if any(ag in (a.get("agent_id") or "").lower() for ag in agent_ids)]

            # Statistiques
            agents = self.db.get_all_agents()
            stats = {
                "total_filtered": len(alerts),
                "by_severity": {},
                "by_type": {},
                "top_agents": {},
                "top_processes": {},
            }
            for alert in alerts:
                sev = alert.get("severity", "unknown")
                stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
                t = alert.get("type", "unknown")
                stats["by_type"][t] = stats["by_type"].get(t, 0) + 1
                ag = alert.get("agent_id", "unknown")
                stats["top_agents"][ag] = stats["top_agents"].get(ag, 0) + 1
                proc = alert.get("process", "")
                if proc:
                    stats["top_processes"][proc] = stats["top_processes"].get(proc, 0) + 1

            return {
                "alerts": alerts[:filters["limit"]],
                "count": len(alerts),
                "agents": agents,
                "stats": stats,
            }
        except Exception as e:
            logger.error(f"Erreur requête AI Hunter: {e}")
            return {"alerts": [], "count": 0, "agents": [], "stats": {}}

    def _generate_response(self, question: str, filters: Dict, results: Dict) -> Dict:
        """Génère une réponse en langage naturel depuis les résultats."""
        count = results["count"]
        alerts = results["alerts"]
        stats = results["stats"]
        intent = filters["intent"]

        # Formater la période
        if filters["time_range"]:
            start = datetime.fromtimestamp(filters["time_range"][0]).strftime("%d/%m %H:%M")
            end = datetime.fromtimestamp(filters["time_range"][1]).strftime("%d/%m %H:%M")
            period = f"du {start} au {end}"
        else:
            period = "sur les dernières 24h"

        # Réponse selon l'intention
        if intent == "count":
            text = f"J'ai trouvé **{count} alertes** {period}"
            if filters["severity"]:
                text += f" de sévérité '{filters['severity']}'"
            if filters["alert_type"]:
                text += f" de type '{filters['alert_type']}'"
            text += "."
            if stats.get("by_severity"):
                text += "\n\nRépartition par sévérité :\n"
                for sev, cnt in sorted(stats["by_severity"].items(), key=lambda x: x[1], reverse=True):
                    text += f"- **{sev}** : {cnt}\n"

        elif intent == "top_risk":
            if not results["agents"]:
                text = "Aucun agent enregistré."
            else:
                online = [a for a in results["agents"] if a.get("online")]
                most_alerts = sorted(stats.get("top_agents", {}).items(), key=lambda x: x[1], reverse=True)
                if most_alerts:
                    top_agent, top_count = most_alerts[0]
                    text = f"L'agent le plus à risque est **{top_agent}** avec {top_count} alertes {period}."
                else:
                    text = f"Aucune alerte détectée {period}. Tous les systèmes semblent protégés."

        elif intent == "status":
            if count == 0:
                text = f"✅ **Aucune alerte détectée** {period}. Le système est en bonne santé."
                if filters["alert_type"]:
                    text = f"✅ Aucune alerte de type '{filters['alert_type']}' {period}."
            else:
                critical = stats.get("by_severity", {}).get("critical", 0)
                if critical > 0:
                    text = f"⚠️ **{critical} alertes critiques** détectées {period} ({count} au total). Intervention recommandée."
                else:
                    text = f"ℹ️ **{count} alertes** détectées {period}, aucune critique."

        else:  # list_threats
            if count == 0:
                text = f"Aucune alerte trouvée {period}"
                if filters["processes"]:
                    text += f" pour le(s) processus {', '.join(filters['processes'])}"
                text += "."
            else:
                text = f"**{count} alertes trouvées** {period}"
                if filters["severity"]:
                    text += f" (sévérité: {filters['severity']})"
                text += ".\n\n"

                if stats.get("top_processes"):
                    top_proc = sorted(stats["top_processes"].items(), key=lambda x: x[1], reverse=True)[:3]
                    text += "**Processus les plus impliqués :**\n"
                    for proc, cnt in top_proc:
                        text += f"- `{proc}` : {cnt} alertes\n"
                    text += "\n"

                text += "**Alertes les plus récentes :**\n"
                for alert in alerts[:5]:
                    score = int(alert.get("threat_score", 0) * 100)
                    text += (
                        f"- [{alert.get('severity', '?').upper()}] "
                        f"`{alert.get('process') or alert.get('file', 'N/A')}` "
                        f"— {score}% risque — {alert.get('reason', '')[:60]}...\n"
                    )

        # Recommandations contextuelles
        recommendations = self._get_recommendations(filters, stats, count)

        return {
            "text": text,
            "count": count,
            "alerts": alerts[:10],
            "stats": stats,
            "recommendations": recommendations,
            "filters_applied": filters,
            "suggested_queries": self._suggest_followup(question, count, filters),
        }

    def _get_recommendations(self, filters: Dict, stats: Dict, count: int) -> List[str]:
        """Génère des recommandations contextuelles."""
        recs = []
        critical = stats.get("by_severity", {}).get("critical", 0)
        if critical > 0:
            recs.append(f"🚨 {critical} alertes critiques nécessitent une action immédiate")
        if stats.get("by_type", {}).get("HONEYTOKEN_TRIGGERED", 0) > 0:
            recs.append("🎯 Un honeytoken a été déclenché — incident confirmé, activer le plan de réponse")
        if stats.get("by_type", {}).get("MEMORY_THREAT", 0) > 0:
            recs.append("💾 Menace en mémoire détectée — possible malware fileless, forensics RAM recommandée")
        if stats.get("by_type", {}).get("UEBA_ANOMALY", 0) > 0:
            recs.append("👤 Comportement utilisateur anormal — vérifier si compte compromis, forcer MFA")
        return recs

    def _suggest_followup(self, original: str, count: int, filters: Dict) -> List[str]:
        """Suggère des questions de suivi pertinentes."""
        suggestions = []
        if count > 0:
            suggestions.append("Quels sont les agents les plus touchés ?")
            suggestions.append("Y a-t-il eu du mouvement latéral associé ?")
            if not filters.get("alert_type"):
                suggestions.append("Montre-moi uniquement les alertes critiques")
        else:
            suggestions.append("Élargir la période de recherche à 7 jours")
            suggestions.append("Quel est le statut général de la sécurité ?")
        suggestions.append("Quelle est la technique MITRE la plus utilisée cette semaine ?")
        return suggestions[:4]

    def get_history(self) -> List[Dict]:
        return list(self._conversation_history)
