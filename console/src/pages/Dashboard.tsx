import React, { useEffect, useState, useCallback } from "react";
import {
  Shield, Server, AlertTriangle, Activity, Wifi, WifiOff,
  Brain, Target, Eye, Users, Globe, Lock, TrendingUp,
} from "lucide-react";
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

type TabId = "overview" | "killchain" | "hunter" | "deception" | "intel" | "patent" | "scale";

const TABS: { id: TabId; label: string; icon: React.ReactNode; color: string }[] = [
  { id: "overview", label: "Vue Générale", icon: <Activity className="w-4 h-4" />, color: "emerald" },
  { id: "killchain", label: "Kill Chain AI", icon: <Target className="w-4 h-4" />, color: "red" },
  { id: "hunter", label: "AI Threat Hunter", icon: <Brain className="w-4 h-4" />, color: "purple" },
  { id: "deception", label: "Deception Engine", icon: <Eye className="w-4 h-4" />, color: "orange" },
  { id: "intel", label: "Threat Intel", icon: <Globe className="w-4 h-4" />, color: "blue" },
  { id: "patent", label: "IA Brevets", icon: <Lock className="w-4 h-4" />, color: "violet" },
  { id: "scale", label: "Scale 10k", icon: <Globe className="w-4 h-4" />, color: "blue" },
];

export default function Dashboard() {
  const { agents, alerts, stats, addAlert, setStats, setAgents } = useSecurityStore();
  const [wsStatus, setWsStatus] = useState<"connecting" | "connected" | "disconnected">("connecting");
  const [activeTab, setActiveTab] = useState<TabId>("overview");

  const initWS = useCallback(() => {
    const ws = connectWebSocket({
      onMessage: (msg) => {
        if (msg.event === "new_alert") addAlert(msg.alert);
        if (msg.event === "initial_state") { setAgents(msg.agents || []); setStats(msg.stats || {}); }
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

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/50 backdrop-blur sticky top-0 z-50">
        <div className="px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Shield className="w-8 h-8 text-emerald-400" />
              <span className="absolute -top-1 -right-1 w-3 h-3 bg-emerald-400 rounded-full animate-pulse" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-white tracking-tight">GRAVITY SECURITY</h1>
              <p className="text-xs text-gray-500">Next-Generation Cybersecurity Platform</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            {/* Indicateurs critiques rapides */}
            {honeytokenAlerts > 0 && (
              <span className="flex items-center gap-1 bg-red-500/20 border border-red-500/50 text-red-300 text-xs px-2 py-1 rounded-full animate-pulse">
                <Eye className="w-3 h-3" /> {honeytokenAlerts} Honeytoken
              </span>
            )}
            {memoryThreats > 0 && (
              <span className="flex items-center gap-1 bg-orange-500/20 border border-orange-500/50 text-orange-300 text-xs px-2 py-1 rounded-full">
                <Lock className="w-3 h-3" /> {memoryThreats} RAM
              </span>
            )}
            <span className={`flex items-center gap-1.5 text-xs ${wsStatus === "connected" ? "text-emerald-400" : "text-red-400"}`}>
              {wsStatus === "connected" ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
              {wsStatus === "connected" ? "Live" : wsStatus === "connecting" ? "Connexion..." : "Déconnecté"}
            </span>
          </div>
        </div>

        {/* Navigation tabs */}
        <nav className="px-6 flex gap-1 pb-0">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? "border-emerald-400 text-emerald-400"
                  : "border-transparent text-gray-500 hover:text-gray-300"
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </nav>
      </header>

      <main className="p-6">
        {/* Stats globales — toujours visibles */}
        <div className="grid grid-cols-2 lg:grid-cols-6 gap-3 mb-6">
          <StatsCard title="Agents" value={onlineAgents} total={agents.length} icon={<Server className="w-4 h-4" />} color="emerald" />
          <StatsCard title="Critiques" value={criticalCount} icon={<AlertTriangle className="w-4 h-4" />} color="red" blink={criticalCount > 0} />
          <StatsCard title="Élevées" value={highCount} icon={<Activity className="w-4 h-4" />} color="orange" />
          <StatsCard title="Honeytokens" value={honeytokenAlerts} icon={<Eye className="w-4 h-4" />} color="yellow" blink={honeytokenAlerts > 0} />
          <StatsCard title="UEBA" value={uebaAlerts} icon={<Users className="w-4 h-4" />} color="purple" />
          <StatsCard title="DNA Mutations" value={dnaMutations} icon={<TrendingUp className="w-4 h-4" />} color="blue" />
        </div>

        {/* Contenu par onglet */}
        {activeTab === "overview" && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2"><AlertFeed alerts={alerts} /></div>
              <AgentMap agents={agents} />
            </div>
            <ThreatChart alerts={alerts} />
          </div>
        )}

        {activeTab === "killchain" && (
          <KillChainView alerts={alerts} />
        )}

        {activeTab === "hunter" && (
          <ThreatHunterChat />
        )}

        {activeTab === "deception" && (
          <DeceptionStatus alerts={alerts} />
        )}

        {activeTab === "intel" && (
          <ThreatIntelFeed alerts={alerts} />
        )}

        {activeTab === "patent" && (
          <PatentDashboard />
        )}

        {activeTab === "scale" && (
          <ScaleView />
        )}
      </main>
    </div>
  );
}
