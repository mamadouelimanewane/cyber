import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { AlertTriangle, Shield, Network, FileWarning } from "lucide-react";
const SEVERITY_STYLE = {
    critical: "border-red-500 bg-red-500/10 text-red-300",
    high: "border-orange-500 bg-orange-500/10 text-orange-300",
    medium: "border-yellow-500 bg-yellow-500/10 text-yellow-300",
    low: "border-blue-500 bg-blue-500/10 text-blue-300",
    info: "border-gray-500 bg-gray-500/10 text-gray-300",
};
const TYPE_ICON = {
    SUSPICIOUS_PROCESS: _jsx(AlertTriangle, { className: "w-4 h-4" }),
    FILE_THREAT: _jsx(FileWarning, { className: "w-4 h-4" }),
    NAC_BLOCK: _jsx(Network, { className: "w-4 h-4" }),
    SIGNATURE_MATCH: _jsx(Shield, { className: "w-4 h-4" }),
};
export default function AlertFeed({ alerts }) {
    const sorted = [...alerts].sort((a, b) => (b.threat_score || 0) - (a.threat_score || 0));
    return (_jsxs("div", { className: "bg-gray-900 rounded-xl border border-gray-800 p-4", children: [_jsxs("h2", { className: "text-sm font-semibold uppercase tracking-wider text-gray-400 mb-4 flex items-center gap-2", children: [_jsx(AlertTriangle, { className: "w-4 h-4 text-orange-400" }), "Flux d'alertes", _jsx("span", { className: "ml-auto bg-gray-800 text-gray-300 text-xs px-2 py-0.5 rounded-full", children: alerts.length })] }), _jsx("div", { className: "space-y-2 max-h-96 overflow-y-auto pr-1", children: sorted.length === 0 ? (_jsxs("div", { className: "text-center text-gray-600 py-8", children: [_jsx(Shield, { className: "w-10 h-10 mx-auto mb-2 opacity-30" }), _jsx("p", { children: "Aucune alerte \u2014 Syst\u00E8me prot\u00E9g\u00E9" })] })) : (sorted.map((alert, idx) => {
                    const style = SEVERITY_STYLE[alert.severity] || SEVERITY_STYLE.info;
                    const icon = TYPE_ICON[alert.type] || _jsx(AlertTriangle, { className: "w-4 h-4" });
                    return (_jsx("div", { className: `rounded-lg border p-3 ${style}`, children: _jsxs("div", { className: "flex items-start gap-2", children: [_jsx("span", { className: "mt-0.5 shrink-0", children: icon }), _jsxs("div", { className: "min-w-0 flex-1", children: [_jsxs("div", { className: "flex items-center gap-2 mb-1", children: [_jsx("span", { className: "text-xs font-bold uppercase", children: alert.severity }), _jsx("span", { className: "text-xs opacity-60", children: alert.label || alert.type }), _jsxs("span", { className: "ml-auto text-xs font-mono opacity-50", children: [(alert.threat_score * 100).toFixed(0), "%"] })] }), _jsx("p", { className: "text-xs opacity-80 truncate", children: alert.process || alert.file || "—" }), alert.reason && (_jsx("p", { className: "text-xs opacity-50 mt-1 line-clamp-2", children: alert.reason })), alert.action && (_jsxs("p", { className: "text-xs font-medium mt-1 opacity-70", children: ["\u2192 ", alert.action] })), _jsxs("p", { className: "text-xs opacity-30 mt-1", children: ["Agent: ", alert.agent_id, " \u2022 ", alert.received_at?.slice(0, 19) || ""] })] })] }) }, alert.id || idx));
                })) })] }));
}
