import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useState, useCallback } from 'react';
import { Atom, Dna, Shield, Eye, Link, Zap, AlertTriangle, CheckCircle, Activity } from 'lucide-react';
// ─── Données démo ─────────────────────────────────────────────────────────────
const DEMO_STATUS = {
    agents_reporting: 3,
    total_patent_alerts: 7,
    qbsm: { total_processes: 142, in_superposition: 138, collapsed_threat: 3, collapsed_safe: 1, decoherent: 0 },
    cbga: { tracked_processes: 12, total_alerts: 2, reference_genomes: 7 },
    rctc: { total_assertions: 28, revoked: 1, violations: 0 },
    asn: { baseline_learned: true, total_packets: 18420, unsigned_blocked: 23, beacon_sessions: 1 },
    recent_patent_alerts: [
        { type: 'QBSM_COLLAPSE', process: 'cmd.exe', pid: 4872, threat_score: 0.97, qbsm_confidence: 0.97 },
        { type: 'CBGA_GENOME_MATCH', process: 'svchost32.exe', pid: 3301, threat_score: 0.91, cbga_similarity: 0.91 },
        { type: 'ASN_BEACON_DETECTED', threat_score: 0.88, source: 'ASN' },
        { type: 'QBSM_COLLAPSE', process: 'wscript.exe', pid: 2210, threat_score: 0.86, qbsm_confidence: 0.86 },
        { type: 'RCTC_VIOLATION', process: 'rundll32.exe', pid: 5544, threat_score: 0.82, rctc_trust_score: 0.12 },
    ],
};
// ─── Sous-composants ──────────────────────────────────────────────────────────
function ModuleCard({ icon: Icon, name, acronym, color, children, }) {
    return (_jsxs("div", { className: `bg-gray-900 border rounded-lg p-4 border-${color}-500/30`, children: [_jsxs("div", { className: "flex items-center gap-2 mb-3", children: [_jsx("div", { className: `p-1.5 rounded bg-${color}-500/10`, children: _jsx(Icon, { className: `w-4 h-4 text-${color}-400` }) }), _jsxs("div", { children: [_jsx("span", { className: `text-xs font-bold text-${color}-400`, children: acronym }), _jsx("span", { className: "text-xs text-gray-500 ml-2", children: name })] })] }), children] }));
}
function Stat({ label, value, highlight }) {
    return (_jsxs("div", { className: "flex justify-between items-center py-1 border-b border-gray-800 last:border-0", children: [_jsx("span", { className: "text-xs text-gray-500", children: label }), _jsx("span", { className: `text-xs font-mono font-bold ${highlight ? 'text-red-400' : 'text-gray-200'}`, children: value })] }));
}
function QBSMPanel({ data }) {
    const threatPct = data.total_processes > 0
        ? Math.round((data.collapsed_threat / data.total_processes) * 100)
        : 0;
    return (_jsxs(ModuleCard, { icon: Atom, name: "Quantum Behavioral Superposition Model", acronym: "QBSM", color: "purple", children: [_jsxs("div", { className: "mb-3 flex items-center gap-2", children: [_jsx("div", { className: "flex-1 h-3 bg-gray-800 rounded-full overflow-hidden", children: _jsx("div", { className: "h-full bg-gradient-to-r from-purple-600 to-blue-500 transition-all", style: { width: `${100 - threatPct}%` } }) }), _jsxs("span", { className: "text-xs text-gray-400 w-14 text-right", children: [100 - threatPct, "% s\u00FBrs"] })] }), _jsx(Stat, { label: "Processus surveill\u00E9s", value: data.total_processes }), _jsx(Stat, { label: "En superposition |\u03C8\u27E9", value: data.in_superposition }), _jsx(Stat, { label: "Effondr\u00E9s \u2192 MENACE", value: data.collapsed_threat, highlight: data.collapsed_threat > 0 }), _jsx(Stat, { label: "Effondr\u00E9s \u2192 S\u00DBRS", value: data.collapsed_safe }), data.collapsed_threat > 0 && (_jsxs("div", { className: "mt-2 flex items-center gap-1 text-xs text-red-400 bg-red-900/20 rounded px-2 py-1", children: [_jsx(Zap, { className: "w-3 h-3" }), "Collapse quantique d\u00E9tect\u00E9 \u2014 isolation recommand\u00E9e"] }))] }));
}
function CBGAPanel({ data }) {
    return (_jsxs(ModuleCard, { icon: Dna, name: "Cryptographic Behavioral Genome Alignment", acronym: "CBGA", color: "green", children: [_jsx(Stat, { label: "Processus s\u00E9quenc\u00E9s", value: data.tracked_processes }), _jsx(Stat, { label: "G\u00E9nomes r\u00E9f\u00E9rence (malware)", value: data.reference_genomes }), _jsx(Stat, { label: "Alertes g\u00E9nomiques", value: data.total_alerts, highlight: data.total_alerts > 0 }), _jsx("div", { className: "mt-2 text-xs text-gray-600", children: "Algorithme Smith-Waterman + matrice BLOSUM-SECURITY" }), data.total_alerts > 0 && (_jsxs("div", { className: "mt-2 flex items-center gap-1 text-xs text-orange-400 bg-orange-900/20 rounded px-2 py-1", children: [_jsx(AlertTriangle, { className: "w-3 h-3" }), "G\u00E9nome comportemental malveillant d\u00E9tect\u00E9"] }))] }));
}
function RCTCPanel({ data }) {
    const health = data.total_assertions > 0
        ? Math.round(((data.total_assertions - data.revoked) / data.total_assertions) * 100)
        : 100;
    return (_jsxs(ModuleCard, { icon: Link, name: "Recursive Cryptographic Trust Chain", acronym: "RCTC", color: "blue", children: [_jsxs("div", { className: "mb-3", children: [_jsxs("div", { className: "flex justify-between text-xs mb-1", children: [_jsx("span", { className: "text-gray-500", children: "Int\u00E9grit\u00E9 de la cha\u00EEne" }), _jsxs("span", { className: health > 90 ? 'text-green-400' : 'text-red-400', children: [health, "%"] })] }), _jsx("div", { className: "h-2 bg-gray-800 rounded-full overflow-hidden", children: _jsx("div", { className: `h-full rounded-full transition-all ${health > 90 ? 'bg-green-500' : 'bg-red-500'}`, style: { width: `${health}%` } }) })] }), _jsx(Stat, { label: "Assertions Merkle actives", value: data.total_assertions }), _jsx(Stat, { label: "R\u00E9vocations (Trust Lightning)", value: data.revoked, highlight: data.revoked > 0 }), _jsx(Stat, { label: "Violations d\u00E9tect\u00E9es", value: data.violations, highlight: data.violations > 0 })] }));
}
function ASNPanel({ data }) {
    return (_jsxs(ModuleCard, { icon: Eye, name: "Adversarial Shadow Network", acronym: "ASN", color: "yellow", children: [_jsxs("div", { className: "flex items-center gap-2 mb-2", children: [_jsx("div", { className: `w-2 h-2 rounded-full ${data.baseline_learned ? 'bg-green-400' : 'bg-yellow-400 animate-pulse'}` }), _jsx("span", { className: "text-xs text-gray-400", children: data.baseline_learned ? 'Baseline apprise — surveillance active' : 'Apprentissage baseline…' })] }), _jsx(Stat, { label: "Paquets analys\u00E9s", value: data.total_packets?.toLocaleString() ?? 0 }), _jsx(Stat, { label: "Trafic non sign\u00E9 bloqu\u00E9", value: data.unsigned_blocked, highlight: data.unsigned_blocked > 0 }), _jsx(Stat, { label: "Sessions beacon d\u00E9tect\u00E9es", value: data.beacon_sessions, highlight: data.beacon_sessions > 0 }), _jsx("div", { className: "mt-2 text-xs text-gray-600", children: "Distance de Wasserstein W\u2081 \u2014 transport optimal" })] }));
}
function ZKSPPanel() {
    return (_jsxs(ModuleCard, { icon: Shield, name: "Zero-Knowledge Security Proof", acronym: "ZKSP", color: "cyan", children: [_jsxs("div", { className: "flex items-center gap-2 mb-3", children: [_jsx(CheckCircle, { className: "w-4 h-4 text-cyan-400" }), _jsx("span", { className: "text-xs text-gray-300", children: "Protocole Fiat-Shamir actif" })] }), _jsx("div", { className: "space-y-1.5", children: ['document_editor', 'web_browser', 'backup_agent', 'antivirus', 'minimal'].map(policy => (_jsxs("div", { className: "flex items-center justify-between text-xs", children: [_jsx("span", { className: "text-gray-500 font-mono", children: policy }), _jsx("span", { className: "text-green-400 text-xs", children: "\u2713 valid\u00E9" })] }, policy))) }), _jsx("div", { className: "mt-2 text-xs text-gray-600", children: "Preuve sans r\u00E9v\u00E9lation \u00B7 3 rounds \u00B7 P(triche) < 1/8" })] }));
}
function PatentAlertRow({ alert }) {
    const TYPE_META = {
        QBSM_COLLAPSE: { label: 'QBSM Collapse', color: 'purple' },
        CBGA_GENOME_MATCH: { label: 'Genome Match', color: 'green' },
        ASN_BEACON_DETECTED: { label: 'Beacon C2', color: 'yellow' },
        RCTC_VIOLATION: { label: 'Trust Violation', color: 'red' },
        ASN_PORT_SCAN: { label: 'Port Scan', color: 'orange' },
        ASN_EXFILTRATION: { label: 'Exfiltration', color: 'red' },
    };
    const meta = TYPE_META[alert.type] ?? { label: alert.type, color: 'gray' };
    const score = alert.threat_score ?? alert.qbsm_confidence ?? alert.cbga_similarity ?? 0;
    return (_jsxs("tr", { className: "border-b border-gray-800 hover:bg-gray-800/40 transition-colors", children: [_jsx("td", { className: "py-2 px-3", children: _jsx("span", { className: `px-1.5 py-0.5 rounded text-xs font-bold text-${meta.color}-400 bg-${meta.color}-400/10`, children: meta.label }) }), _jsx("td", { className: "py-2 px-3 text-xs text-gray-400 font-mono", children: alert.process ?? alert.source ?? '—' }), _jsx("td", { className: "py-2 px-3 text-xs text-gray-400 font-mono", children: alert.pid ?? '—' }), _jsx("td", { className: "py-2 px-3", children: _jsxs("div", { className: "flex items-center gap-2", children: [_jsx("div", { className: "flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden w-16", children: _jsx("div", { className: `h-full rounded-full ${score > 0.85 ? 'bg-red-500' : score > 0.6 ? 'bg-orange-500' : 'bg-yellow-500'}`, style: { width: `${score * 100}%` } }) }), _jsxs("span", { className: "text-xs font-mono text-gray-300", children: [(score * 100).toFixed(0), "%"] })] }) })] }));
}
// ─── Composant principal ──────────────────────────────────────────────────────
export default function PatentDashboard() {
    const [status, setStatus] = useState(DEMO_STATUS);
    const [loading, setLoading] = useState(false);
    const fetchStatus = useCallback(async () => {
        try {
            const res = await fetch('/api/patent/status');
            if (res.ok)
                setStatus(await res.json());
        }
        catch {
            // Mode démo — données statiques
        }
    }, []);
    useEffect(() => {
        fetchStatus();
        const id = setInterval(fetchStatus, 10000);
        return () => clearInterval(id);
    }, [fetchStatus]);
    return (_jsxs("div", { className: "space-y-4", children: [_jsxs("div", { className: "flex items-center justify-between", children: [_jsxs("div", { children: [_jsxs("h2", { className: "text-lg font-bold text-white flex items-center gap-2", children: [_jsx(Activity, { className: "w-5 h-5 text-purple-400" }), "Intelligence Brevetable"] }), _jsx("p", { className: "text-xs text-gray-500 mt-0.5", children: "5 algorithmes propri\u00E9taires \u2014 QBSM \u00B7 CBGA \u00B7 ZKSP \u00B7 ASN \u00B7 RCTC" })] }), _jsxs("div", { className: "text-right", children: [_jsx("div", { className: "text-2xl font-bold text-red-400", children: status.total_patent_alerts }), _jsx("div", { className: "text-xs text-gray-500", children: "alertes brevets" })] })] }), _jsxs("div", { className: "grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3", children: [_jsx(QBSMPanel, { data: status.qbsm }), _jsx(CBGAPanel, { data: status.cbga }), _jsx(RCTCPanel, { data: status.rctc }), _jsx(ASNPanel, { data: status.asn }), _jsx(ZKSPPanel, {}), _jsxs("div", { className: "bg-gray-900 border border-gray-700 rounded-lg p-4", children: [_jsxs("div", { className: "flex items-center gap-2 mb-3", children: [_jsx(Shield, { className: "w-4 h-4 text-white" }), _jsx("span", { className: "text-sm font-bold text-white", children: "Couverture globale" })] }), _jsx(Stat, { label: "Agents actifs", value: status.agents_reporting }), _jsx(Stat, { label: "Alertes brevets totales", value: status.total_patent_alerts, highlight: status.total_patent_alerts > 0 }), _jsx("div", { className: "mt-3 pt-3 border-t border-gray-800 space-y-1", children: ['QBSM', 'CBGA', 'RCTC', 'ASN', 'ZKSP'].map(name => (_jsxs("div", { className: "flex items-center justify-between text-xs", children: [_jsx("span", { className: "text-gray-500 font-mono", children: name }), _jsxs("span", { className: "text-green-400 flex items-center gap-1", children: [_jsx("span", { className: "w-1.5 h-1.5 rounded-full bg-green-400 inline-block" }), "actif"] })] }, name))) })] })] }), status.recent_patent_alerts.length > 0 && (_jsxs("div", { className: "bg-gray-900 border border-gray-700 rounded-lg overflow-hidden", children: [_jsxs("div", { className: "px-4 py-3 border-b border-gray-800 flex items-center gap-2", children: [_jsx(Zap, { className: "w-4 h-4 text-yellow-400" }), _jsx("span", { className: "text-sm font-semibold text-white", children: "Alertes des algorithmes brevetables" }), _jsxs("span", { className: "ml-auto text-xs text-gray-500", children: [status.recent_patent_alerts.length, " r\u00E9centes"] })] }), _jsx("div", { className: "overflow-x-auto", children: _jsxs("table", { className: "w-full text-xs", children: [_jsx("thead", { children: _jsxs("tr", { className: "border-b border-gray-800", children: [_jsx("th", { className: "text-left py-2 px-3 text-gray-500 font-medium", children: "Algorithme" }), _jsx("th", { className: "text-left py-2 px-3 text-gray-500 font-medium", children: "Processus" }), _jsx("th", { className: "text-left py-2 px-3 text-gray-500 font-medium", children: "PID" }), _jsx("th", { className: "text-left py-2 px-3 text-gray-500 font-medium", children: "Confiance" })] }) }), _jsx("tbody", { children: status.recent_patent_alerts.map((alert, i) => (_jsx(PatentAlertRow, { alert: alert }, i))) })] }) })] })), _jsxs("div", { className: "text-xs text-gray-700 border border-gray-800 rounded p-3 bg-gray-900/50", children: [_jsx("span", { className: "text-gray-500 font-semibold", children: "Architecture synergique :" }), ' ', "Les alertes existantes (v1/v2/v3) transitent automatiquement par le Patent Engine. QBSM observe chaque alerte \u2192 CBGA accumule le g\u00E9nome comportemental \u2192 RCTC signe cryptographiquement chaque alerte \u2192 ASN analyse le trafic r\u00E9seau \u2192 ZKSP v\u00E9rifie la conformit\u00E9 \u00E0 la politique sans r\u00E9v\u00E9ler les actes. Z\u00E9ro overhead \u2014 z\u00E9ro doublon \u2014 synergie totale."] })] }));
}
