import React from "react";
import { Server, Wifi, WifiOff, Shield } from "lucide-react";

interface Agent {
  agent_id: string;
  ip: string;
  hostname?: string;
  online: boolean;
  os_info?: string;
  stats?: Record<string, any>;
}

export default function AgentMap({ agents }: { agents: Agent[] }) {
  return (
    <div className="bg-gray-900 rounded-xl border border-gray-800 p-4 h-full">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-4 flex items-center gap-2">
        <Server className="w-4 h-4 text-emerald-400" />
        Agents
        <span className="ml-auto text-xs">
          <span className="text-emerald-400 font-bold">{agents.filter((a) => a.online).length}</span>
          <span className="text-gray-600">/{agents.length} en ligne</span>
        </span>
      </h2>

      <div className="space-y-2 max-h-96 overflow-y-auto">
        {agents.length === 0 ? (
          <div className="text-center text-gray-600 py-8">
            <Server className="w-8 h-8 mx-auto mb-2 opacity-30" />
            <p className="text-xs">Aucun agent enregistré</p>
          </div>
        ) : (
          agents.map((agent) => (
            <div
              key={agent.agent_id}
              className={`rounded-lg border p-3 ${
                agent.online
                  ? "border-emerald-500/30 bg-emerald-500/5"
                  : "border-gray-700 bg-gray-800/50"
              }`}
            >
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full shrink-0 ${agent.online ? "bg-emerald-400 animate-pulse" : "bg-gray-600"}`} />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-white truncate">
                    {agent.hostname || agent.agent_id}
                  </p>
                  <p className="text-xs text-gray-500">{agent.ip}</p>
                </div>
                {agent.online ? (
                  <Shield className="w-3 h-3 text-emerald-400 shrink-0" />
                ) : (
                  <WifiOff className="w-3 h-3 text-gray-600 shrink-0" />
                )}
              </div>
              {(agent.stats?.alerts_pending ?? 0) > 0 && (
                <div className="mt-1 text-xs text-orange-400">
                  {agent.stats?.alerts_pending} alertes en attente
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
