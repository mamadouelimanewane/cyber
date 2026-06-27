import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
const COLOR_MAP = {
    emerald: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
    red: "text-red-400 bg-red-400/10 border-red-400/20",
    orange: "text-orange-400 bg-orange-400/10 border-orange-400/20",
    blue: "text-blue-400 bg-blue-400/10 border-blue-400/20",
    yellow: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
    purple: "text-purple-400 bg-purple-400/10 border-purple-400/20",
};
export default function StatsCard({ title, value, total, icon, color, blink }) {
    const colors = COLOR_MAP[color];
    return (_jsxs("div", { className: `rounded-xl border p-4 ${colors} ${blink && value > 0 ? "animate-pulse" : ""}`, children: [_jsxs("div", { className: "flex items-center justify-between mb-2", children: [_jsx("span", { className: "text-xs font-medium uppercase tracking-wider opacity-70", children: title }), _jsx("span", { className: "opacity-60", children: icon })] }), _jsxs("div", { className: "text-3xl font-bold", children: [value, total !== undefined && (_jsxs("span", { className: "text-base font-normal opacity-50 ml-1", children: ["/ ", total] }))] })] }));
}
