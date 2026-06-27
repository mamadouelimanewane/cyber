import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useMemo } from "react";
import { Activity } from "lucide-react";
export default function ThreatChart({ alerts }) {
    // Regrouper par heure sur les 12 dernières heures
    const timeline = useMemo(() => {
        const now = Date.now();
        const buckets = {};
        for (let h = 11; h >= 0; h--) {
            buckets[h] = { critical: 0, high: 0, medium: 0, total: 0 };
        }
        alerts.forEach((a) => {
            if (!a.received_at)
                return;
            const ts = new Date(a.received_at).getTime();
            const hoursAgo = Math.floor((now - ts) / 3600000);
            if (hoursAgo >= 0 && hoursAgo < 12) {
                const bucket = buckets[hoursAgo];
                if (bucket) {
                    bucket.total++;
                    if (a.severity === "critical")
                        bucket.critical++;
                    else if (a.severity === "high")
                        bucket.high++;
                    else
                        bucket.medium++;
                }
            }
        });
        return Object.entries(buckets)
            .sort(([a], [b]) => Number(b) - Number(a))
            .reverse()
            .map(([hoursAgo, counts]) => ({
            label: hoursAgo === "0" ? "Maintenant" : `-${hoursAgo}h`,
            ...counts,
        }));
    }, [alerts]);
    const maxVal = Math.max(...timeline.map((t) => t.total), 1);
    return (_jsxs("div", { className: "bg-gray-900 rounded-xl border border-gray-800 p-4", children: [_jsxs("h2", { className: "text-sm font-semibold uppercase tracking-wider text-gray-400 mb-4 flex items-center gap-2", children: [_jsx(Activity, { className: "w-4 h-4 text-blue-400" }), "Activit\u00E9 des menaces \u2014 12 derni\u00E8res heures"] }), _jsx("div", { className: "flex items-end gap-1 h-24", children: timeline.map((bucket, idx) => (_jsxs("div", { className: "flex-1 flex flex-col items-center gap-0.5", children: [_jsxs("div", { className: "w-full flex flex-col justify-end", style: { height: "80px" }, children: [_jsx("div", { className: "w-full bg-red-500 rounded-sm transition-all", style: { height: `${(bucket.critical / maxVal) * 80}px` } }), _jsx("div", { className: "w-full bg-orange-500 rounded-sm transition-all", style: { height: `${(bucket.high / maxVal) * 80}px` } }), _jsx("div", { className: "w-full bg-yellow-500 rounded-sm transition-all", style: { height: `${(bucket.medium / maxVal) * 80}px` } })] }), _jsx("span", { className: "text-xs text-gray-600 whitespace-nowrap", style: { fontSize: "9px" }, children: bucket.label })] }, idx))) }), _jsxs("div", { className: "flex gap-4 mt-3 text-xs text-gray-500", children: [_jsxs("span", { className: "flex items-center gap-1", children: [_jsx("span", { className: "w-2 h-2 rounded-sm bg-red-500 inline-block" }), " Critique"] }), _jsxs("span", { className: "flex items-center gap-1", children: [_jsx("span", { className: "w-2 h-2 rounded-sm bg-orange-500 inline-block" }), " \u00C9lev\u00E9"] }), _jsxs("span", { className: "flex items-center gap-1", children: [_jsx("span", { className: "w-2 h-2 rounded-sm bg-yellow-500 inline-block" }), " Moyen"] })] })] }));
}
