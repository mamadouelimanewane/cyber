import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useState, useCallback } from "react";
import { Shield, Server, AlertTriangle, Activity, Wifi, WifiOff, Brain, Target, Eye, Users, Globe, Lock, TrendingUp, } from "lucide-react";
import StatsCard from "../components/StatsCard";
import AlertFeed from "../components/AlertFeed";
import AgentMap from "../components/AgentMap";
import ThreatChart from "../components/ThreatChart";
import KillChainView from "../components/killchain/KillChainView";
import ThreatHunterChat from "../components/ThreatHunterChat";
import DeceptionStatus from "../components/deception/DeceptionStatus";
import ThreatIntelFeed from "../components/ThreatIntelFeed";
import PatentDashboard from "../components/patent/PatentDashboard";
import ScaleView from "../components/ScaleView";
import { useSecurityStore } from "../store/securityStore";
import { connectWebSocket } from "../api/websocket";
const TABS = [
    { id: "overview", label: "Vue Générale", icon: _jsx(Activity, { className: "w-4 h-4" }), color: "emerald" },
    { id: "killchain", label: "Kill Chain AI", icon: _jsx(Target, { className: "w-4 h-4" }), color: "red" },
    { id: "hunter", label: "AI Threat Hunter", icon: _jsx(Brain, { className: "w-4 h-4" }), color: "purple" },
    { id: "deception", label: "Deception Engine", icon: _jsx(Eye, { className: "w-4 h-4" }), color: "orange" },
    { id: "intel", label: "Threat Intel", icon: _jsx(Globe, { className: "w-4 h-4" }), color: "blue" },
    { id: "patent", label: "IA Brevets", icon: _jsx(Lock, { className: "w-4 h-4" }), color: "violet" },
    { id: "scale", label: "Scale 10k", icon: _jsx(Globe, { className: "w-4 h-4" }), color: "blue" },
];
export default function Dashboard() {
    const { agents, alerts, stats, addAlert, setStats, setAgents } = useSecurityStore();
    const [wsStatus, setWsStatus] = useState("connecting");
    const [activeTab, setActiveTab] = useState("overview");
    const initWS = useCallback(() => {
        const ws = connectWebSocket({
            onMessage: (msg) => {
                if (msg.event === "new_alert")
                    addAlert(msg.alert);
                if (msg.event === "initial_state") {
                    setAgents(msg.agents || []);
                    setStats(msg.stats || {});
                }
            },
            onOpen: () => setWsStatus("connected"),
            onClose: () => { setWsStatus("disconnected"); setTimeout(initWS, 3000); },
        });
        return ws;
    }, [addAlert, setStats, setAgents]);
    useEffect(() => { const ws = initWS(); return () => ws?.close(); }, [initWS]);
    const criticalCount = alerts.filter((a) => a.severity === "critical").length;
    const highCount = alerts.filter((a) => a.severity === "high").length;
    const onlineAgents = agents.filter((a) => a.online).length;
    const honeytokenAlerts = alerts.filter((a) => a.type === "HONEYTOKEN_TRIGGERED").length;
    const memoryThreats = alerts.filter((a) => a.type === "MEMORY_THREAT").length;
    const uebaAlerts = alerts.filter((a) => a.type === "UEBA_ANOMALY").length;
    const dnaMutations = alerts.filter((a) => a.type === "DNA_MUTATION").length;
    return (_jsxs("div", { className: "min-h-screen bg-gray-950 text-gray-100", children: [_jsxs("header", { className: "border-b border-gray-800 bg-gray-900/50 backdrop-blur sticky top-0 z-50", children: [_jsxs("div", { className: "px-6 py-3 flex items-center justify-between", children: [_jsxs("div", { className: "flex items-center gap-3", children: [_jsxs("div", { className: "relative", children: [_jsx(Shield, { className: "w-8 h-8 text-emerald-400" }), _jsx("span", { className: "absolute -top-1 -right-1 w-3 h-3 bg-emerald-400 rounded-full animate-pulse" })] }), _jsxs("div", { children: [_jsx("h1", { className: "text-lg font-bold text-white tracking-tight", children: "GRAVITY SECURITY" }), _jsx("p", { className: "text-xs text-gray-500", children: "Next-Generation Cybersecurity Platform" })] })] }), _jsxs("div", { className: "flex items-center gap-4", children: [honeytokenAlerts > 0 && (_jsxs("span", { className: "flex items-center gap-1 bg-red-500/20 border border-red-500/50 text-red-300 text-xs px-2 py-1 rounded-full animate-pulse", children: [_jsx(Eye, { className: "w-3 h-3" }), " ", honeytokenAlerts, " Honeytoken"] })), memoryThreats > 0 && (_jsxs("span", { className: "flex items-center gap-1 bg-orange-500/20 border border-orange-500/50 text-orange-300 text-xs px-2 py-1 rounded-full", children: [_jsx(Lock, { className: "w-3 h-3" }), " ", memoryThreats, " RAM"] })), _jsxs("span", { className: `flex items-center gap-1.5 text-xs ${wsStatus === "connected" ? "text-emerald-400" : "text-red-400"}`, children: [wsStatus === "connected" ? _jsx(Wifi, { className: "w-3 h-3" }) : _jsx(WifiOff, { className: "w-3 h-3" }), wsStatus === "connected" ? "Live" : wsStatus === "connecting" ? "Connexion..." : "Déconnecté"] })] })] }), _jsx("nav", { className: "px-6 flex gap-1 pb-0", children: TABS.map((tab) => (_jsxs("button", { onClick: () => setActiveTab(tab.id), className: `flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === tab.id
                                ? "border-emerald-400 text-emerald-400"
                                : "border-transparent text-gray-500 hover:text-gray-300"}`, children: [tab.icon, tab.label] }, tab.id))) })] }), _jsxs("main", { className: "p-6", children: [_jsxs("div", { className: "grid grid-cols-2 lg:grid-cols-6 gap-3 mb-6", children: [_jsx(StatsCard, { title: "Agents", value: onlineAgents, total: agents.length, icon: _jsx(Server, { className: "w-4 h-4" }), color: "emerald" }), _jsx(StatsCard, { title: "Critiques", value: criticalCount, icon: _jsx(AlertTriangle, { className: "w-4 h-4" }), color: "red", blink: criticalCount > 0 }), _jsx(StatsCard, { title: "\u00C9lev\u00E9es", value: highCount, icon: _jsx(Activity, { className: "w-4 h-4" }), color: "orange" }), _jsx(StatsCard, { title: "Honeytokens", value: honeytokenAlerts, icon: _jsx(Eye, { className: "w-4 h-4" }), color: "yellow", blink: honeytokenAlerts > 0 }), _jsx(StatsCard, { title: "UEBA", value: uebaAlerts, icon: _jsx(Users, { className: "w-4 h-4" }), color: "purple" }), _jsx(StatsCard, { title: "DNA Mutations", value: dnaMutations, icon: _jsx(TrendingUp, { className: "w-4 h-4" }), color: "blue" })] }), activeTab === "overview" && (_jsxs("div", { className: "space-y-6", children: [_jsxs("div", { className: "grid grid-cols-1 lg:grid-cols-3 gap-6", children: [_jsx("div", { className: "lg:col-span-2", children: _jsx(AlertFeed, { alerts: alerts }) }), _jsx(AgentMap, { agents: agents })] }), _jsx(ThreatChart, { alerts: alerts })] })), activeTab === "killchain" && (_jsx(KillChainView, { alerts: alerts })), activeTab === "hunter" && (_jsx(ThreatHunterChat, {})), activeTab === "deception" && (_jsx(DeceptionStatus, { alerts: alerts })), activeTab === "intel" && (_jsx(ThreatIntelFeed, { alerts: alerts })), activeTab === "patent" && (_jsx(PatentDashboard, {})), activeTab === "scale" && (_jsx(ScaleView, {}))] })] }));
}
