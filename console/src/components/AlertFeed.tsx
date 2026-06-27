import React from "react";
import { AlertTriangle, Shield, Network, FileWarning } from "lucide-react";

const SEVERITY_STYLE = {
  critical: "border-red-500 bg-red-500/10 text-red-300",
  high: "border-orange-500 bg-orange-500/10 text-orange-300",
  medium: "border-yellow-500 bg-yellow-500/10 text-yellow-300",
  low: "border-blue-500 bg-blue-500/10 text-blue-300",
  info: "border-gray-500 bg-gray-500/10 text-gray-300",
};

const TYPE_ICON: Record<string, React.ReactNode> = {
  SUSPICIOUS_PROCESS: <AlertTriangle className="w-4 h-4" />,
  FILE_THREAT: <FileWarning className="w-4 h-4" />,
  NAC_BLOCK: <Network className="w-4 h-4" />,
  SIGNATURE_MATCH: <Shield className="w-4 h-4" />,
};

interface Alert {
  id?: number;
  type: string;
  severity: string;
  threat_score: number;
  process?: string;
  file?: string;
  reason?: string;
  agent_id?: string;
  received_at?: string;
  label?: string;
  action?: string;
}

export default function AlertFeed({ alerts }: { alerts: Alert[] }) {
  const sorted = [...alerts].sort((a, b) => (b.threat_score || 0) - (a.threat_score || 0));

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-4 flex items-center gap-2">
        <AlertTriangle className="w-4 h-4 text-orange-400" />
        Flux d'alertes
        <span className="ml-auto bg-gray-800 text-gray-300 text-xs px-2 py-0.5 rounded-full">
          {alerts.length}
        </span>
      </h2>

      <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
        {sorted.length === 0 ? (
          <div className="text-center text-gray-600 py-8">
            <Shield className="w-10 h-10 mx-auto mb-2 opacity-30" />
            <p>Aucune alerte — Système protégé</p>
          </div>
        ) : (
          sorted.map((alert, idx) => {
            const style = SEVERITY_STYLE[alert.severity as keyof typeof SEVERITY_STYLE] || SEVERITY_STYLE.info;
            const icon = TYPE_ICON[alert.type] || <AlertTriangle className="w-4 h-4" />;
            return (
              <div key={alert.id || idx} className={`rounded-lg border p-3 ${style}`}>
                <div className="flex items-start gap-2">
                  <span className="mt-0.5 shrink-0">{icon}</span>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-bold uppercase">{alert.severity}</span>
                      <span className="text-xs opacity-60">{alert.label || alert.type}</span>
                      <span className="ml-auto text-xs font-mono opacity-50">
                        {(alert.threat_score * 100).toFixed(0)}%
                      </span>
                    </div>
                    <p className="text-xs opacity-80 truncate">
                      {alert.process || alert.file || "—"}
                    </p>
                    {alert.reason && (
                      <p className="text-xs opacity-50 mt-1 line-clamp-2">{alert.reason}</p>
                    )}
                    {alert.action && (
                      <p className="text-xs font-medium mt-1 opacity-70">→ {alert.action}</p>
                    )}
                    <p className="text-xs opacity-30 mt-1">
                      Agent: {alert.agent_id} • {alert.received_at?.slice(0, 19) || ""}
                    </p>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
