import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import React, { useMemo } from "react";
import { Target, AlertTriangle, ChevronRight, Shield, Zap } from "lucide-react";
const PHASES = [
    { id: 1, name: "Initial Access", short: "Accès", color: "yellow", tactic: "TA0001" },
    { id: 2, name: "Execution", short: "Exécution", color: "orange", tactic: "TA0002" },
    { id: 3, name: "Persistence", short: "Persistance", color: "orange", tactic: "TA0003" },
    { id: 4, name: "Privilege Escalation", short: "Escalade", color: "red", tactic: "TA0004" },
    { id: 5, name: "Defense Evasion", short: "Évasion", color: "red", tactic: "TA0005" },
    { id: 6, name: "Lateral Movement", short: "Latéral", color: "red", tactic: "TA0008" },
    { id: 7, name: "Exfiltration", short: "Exfil.", color: "purple", tactic: "TA0010" },
    { id: 8, name: "Impact", short: "Impact", color: "purple", tactic: "TA0040" },
];
const TECHNIQUE_MAP = {
    "SUSPICIOUS_PROCESS": { phase: 2, name: "Command Execution", id: "T1059" },
    "FILE_THREAT": { phase: 2, name: "Malicious File", id: "T1204" },
    "NAC_BLOCK": { phase: 6, name: "Remote Services", id: "T1021" },
    "MEMORY_THREAT": { phase: 4, name: "Process Injection", id: "T1055" },
    "DNA_MUTATION": { phase: 5, name: "Masquerading", id: "T1036" },
    "HONEYTOKEN_TRIGGERED": { phase: 6, name: "Discovery", id: "T1083" },
    "UEBA_ANOMALY": { phase: 1, name: "Valid Accounts", id: "T1078" },
    "SIGNATURE_MATCH": { phase: 2, name: "Known Malware", id: "T1204" },
};
const COLOR_CLASSES = {
    yellow: "border-yellow-500 bg-yellow-500/10 text-yellow-300",
    orange: "border-orange-500 bg-orange-500/10 text-orange-300",
    red: "border-red-500 bg-red-500/10 text-red-300",
    purple: "border-purple-500 bg-purple-500/10 text-purple-300",
    gray: "border-gray-700 bg-gray-800/50 text-gray-500",
};
const URGENCY_ACTIONS = {
    1: "Monitorer les scans — bloquer les IPs suspectes",
    2: "Bloquer l'exécution — suspendre les processus suspects",
    3: "Supprimer les mécanismes de persistance",
    4: "Révoquer les tokens — forcer reauth",
    5: "Renforcer les logs — isoler les outils suspects",
    6: "ISOLER le segment réseau — bloquer SMB/RDP interne",
    7: "Bloquer trafic sortant — activer DLP",
    8: "ISOLER TOUT — activer le plan de reprise d'activité",
};
export default function KillChainView({ alerts }) {
    const phaseData = useMemo(() => {
        const counts = {};
        PHASES.forEach((p) => { counts[p.id] = { count: 0, alerts: [], max_score: 0 }; });
        alerts.forEach((alert) => {
            const phase = alert.kill_chain_phase || TECHNIQUE_MAP[alert.type]?.phase || 2;
            if (counts[phase]) {
                counts[phase].count++;
                counts[phase].alerts.push(alert);
                counts[phase].max_score = Math.max(counts[phase].max_score, alert.threat_score || 0);
            }
        });
        return counts;
    }, [alerts]);
    const maxPhaseReached = Math.max(...Object.entries(phaseData).filter(([, v]) => v.count > 0).map(([k]) => Number(k)), 0);
    const campaigns = useMemo(() => {
        const map = {};
        alerts.forEach((a) => {
            if (a.campaign_id) {
                if (!map[a.campaign_id]) {
                    map[a.campaign_id] = { id: a.campaign_id, count: 0, maxPhase: 0, agent: a.agent_id || "" };
                }
                map[a.campaign_id].count++;
                const phase = a.kill_chain_phase || TECHNIQUE_MAP[a.type]?.phase || 2;
                map[a.campaign_id].maxPhase = Math.max(map[a.campaign_id].maxPhase, phase);
            }
        });
        return Object.values(map);
    }, [alerts]);
    return (_jsxs("div", { className: "space-y-6", children: [_jsxs("div", { className: "bg-gray-900 rounded-xl border border-gray-800 p-6", children: [_jsxs("div", { className: "flex items-center gap-2 mb-6", children: [_jsx(Target, { className: "w-5 h-5 text-red-400" }), _jsx("h2", { className: "text-sm font-semibold uppercase tracking-wider text-gray-400", children: "MITRE ATT&CK Kill Chain \u2014 \u00C9tat en temps r\u00E9el" }), maxPhaseReached >= 6 && (_jsx("span", { className: "ml-auto text-xs bg-red-500/20 border border-red-500 text-red-300 px-2 py-0.5 rounded-full animate-pulse", children: "\u26A0 Phase critique atteinte" }))] }), _jsx("div", { className: "flex items-stretch gap-1 overflow-x-auto pb-2", children: PHASES.map((phase, idx) => {
                            const data = phaseData[phase.id];
                            const isActive = data.count > 0;
                            const isCurrent = phase.id === maxPhaseReached;
                            const colorKey = isActive ? phase.color : "gray";
                            const colorClass = COLOR_CLASSES[colorKey];
                            return (_jsxs(React.Fragment, { children: [_jsxs("div", { className: `flex-1 min-w-[90px] rounded-lg border p-3 transition-all ${colorClass} ${isCurrent ? "ring-2 ring-white/20 scale-105" : ""}`, children: [_jsxs("div", { className: "text-xs font-bold mb-1 opacity-60", children: ["Phase ", phase.id] }), _jsx("div", { className: "text-xs font-semibold mb-2 leading-tight", children: phase.short }), isActive ? (_jsxs(_Fragment, { children: [_jsx("div", { className: "text-2xl font-bold", children: data.count }), _jsx("div", { className: "text-xs opacity-60 mt-1", children: "alertes" }), _jsx("div", { className: "mt-2 h-1 bg-white/20 rounded-full", children: _jsx("div", { className: "h-full bg-white/60 rounded-full", style: { width: `${data.max_score * 100}%` } }) })] })) : (_jsx("div", { className: "text-2xl font-bold opacity-20", children: "\u2014" })), isCurrent && _jsx("div", { className: "text-xs mt-1 font-bold opacity-80", children: "\u2190 ICI" })] }), idx < PHASES.length - 1 && (_jsx(ChevronRight, { className: "w-4 h-4 text-gray-700 self-center shrink-0" }))] }, phase.id));
                        }) }), maxPhaseReached > 0 && (_jsxs("div", { className: "mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg", children: [_jsxs("div", { className: "flex items-center gap-2 text-red-300", children: [_jsx(Zap, { className: "w-4 h-4 shrink-0" }), _jsxs("span", { className: "text-sm font-semibold", children: ["Action recommand\u00E9e (Phase ", maxPhaseReached, ") :"] })] }), _jsx("p", { className: "text-sm text-red-200 mt-1 ml-6", children: URGENCY_ACTIONS[maxPhaseReached] })] }))] }), campaigns.length > 0 && (_jsxs("div", { className: "bg-gray-900 rounded-xl border border-gray-800 p-4", children: [_jsxs("h3", { className: "text-sm font-semibold uppercase tracking-wider text-gray-400 mb-4 flex items-center gap-2", children: [_jsx(AlertTriangle, { className: "w-4 h-4 text-orange-400" }), "Campagnes d'attaque actives"] }), _jsx("div", { className: "grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3", children: campaigns.map((c) => (_jsxs("div", { className: "border border-orange-500/30 bg-orange-500/5 rounded-lg p-3", children: [_jsx("div", { className: "text-xs font-mono text-orange-400 font-bold", children: c.id }), _jsxs("div", { className: "text-xs text-gray-400 mt-1", children: ["Agent: ", c.agent] }), _jsxs("div", { className: "flex items-center justify-between mt-2", children: [_jsxs("span", { className: "text-xs text-gray-500", children: [c.count, " alertes"] }), _jsxs("span", { className: "text-xs text-orange-300", children: ["Phase ", c.maxPhase, "/", PHASES.length] })] }), _jsx("div", { className: "mt-1 h-1 bg-gray-700 rounded-full", children: _jsx("div", { className: "h-full bg-orange-500 rounded-full", style: { width: `${(c.maxPhase / PHASES.length) * 100}%` } }) })] }, c.id))) })] })), _jsxs("div", { className: "bg-gray-900 rounded-xl border border-gray-800 p-4", children: [_jsxs("h3", { className: "text-sm font-semibold uppercase tracking-wider text-gray-400 mb-4 flex items-center gap-2", children: [_jsx(Shield, { className: "w-4 h-4 text-blue-400" }), "Techniques MITRE ATT&CK d\u00E9tect\u00E9es"] }), alerts.length === 0 ? (_jsxs("div", { className: "text-center text-gray-600 py-6", children: [_jsx(Shield, { className: "w-8 h-8 mx-auto mb-2 opacity-20" }), _jsx("p", { className: "text-xs", children: "Aucune technique d\u00E9tect\u00E9e" })] })) : (_jsx("div", { className: "grid grid-cols-2 lg:grid-cols-4 gap-2", children: Object.entries(alerts.reduce((acc, a) => {
                            const t = TECHNIQUE_MAP[a.type];
                            if (t)
                                acc[t.id] = { name: t.name, id: t.id, count: (acc[t.id]?.count || 0) + 1 };
                            return acc;
                        }, {})).map(([id, tech]) => (_jsxs("div", { className: "border border-blue-500/20 bg-blue-500/5 rounded-lg p-2", children: [_jsx("div", { className: "text-xs font-mono text-blue-400", children: id }), _jsx("div", { className: "text-xs text-gray-300 mt-0.5 leading-tight", children: tech.name }), _jsx("div", { className: "text-lg font-bold text-white mt-1", children: tech.count })] }, id))) }))] })] }));
}
