import React, { useMemo } from "react";
import { Eye, AlertTriangle, CheckCircle, Clock, Globe, FileText, Server } from "lucide-react";

const DEMO_TOKENS = [
  { id: "tok_001", type: "file", description: "passwords_backup.txt", triggered: true, trigger_count: 2, path: "C:\\Users\\HP\\Desktop\\" },
  { id: "tok_002", type: "file", description: "vpn_credentials.json", triggered: false, trigger_count: 0, path: "C:\\Users\\HP\\Documents\\" },
  { id: "tok_003", type: "file", description: "database_config.env", triggered: false, trigger_count: 0, path: "C:\\Users\\HP\\Desktop\\" },
  { id: "tok_004", type: "file", description: "aws_credentials", triggered: false, trigger_count: 0, path: "C:\\Users\\HP\\.aws\\" },
  { id: "tok_005", type: "port", description: "Port 4444/tcp (Meterpreter leurre)", triggered: true, trigger_count: 1, path: "0.0.0.0:4444" },
  { id: "tok_006", type: "port", description: "Port 1337/tcp (Hacker classic)", triggered: false, trigger_count: 0, path: "0.0.0.0:1337" },
  { id: "tok_007", type: "port", description: "Port 31337/tcp (Elite port)", triggered: false, trigger_count: 0, path: "0.0.0.0:31337" },
];

const TYPE_ICON: Record<string, React.ReactNode> = {
  file: <FileText className="w-3 h-3" />,
  port: <Globe className="w-3 h-3" />,
  process: <Server className="w-3 h-3" />,
};

interface Alert { type: string; severity?: string; threat_score?: number; reason?: string; received_at?: string; }

export default function DeceptionStatus({ alerts }: { alerts: Alert[] }) {
  const honeyAlerts = useMemo(
    () => alerts.filter((a) => a.type === "HONEYTOKEN_TRIGGERED"),
    [alerts]
  );

  const triggered = DEMO_TOKENS.filter((t) => t.triggered);
  const safe = DEMO_TOKENS.filter((t) => !t.triggered);

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <div className="flex items-center gap-2 text-gray-400 text-xs mb-2"><Eye className="w-4 h-4 text-orange-400" /> Honeytokens déployés</div>
          <div className="text-3xl font-bold text-white">{DEMO_TOKENS.length}</div>
        </div>
        <div className={`bg-gray-900 rounded-xl border p-4 ${triggered.length > 0 ? "border-red-500/50" : "border-gray-800"}`}>
          <div className="flex items-center gap-2 text-gray-400 text-xs mb-2"><AlertTriangle className="w-4 h-4 text-red-400" /> Déclenchés</div>
          <div className={`text-3xl font-bold ${triggered.length > 0 ? "text-red-400" : "text-white"}`}>{triggered.length}</div>
          {triggered.length > 0 && <div className="text-xs text-red-400 mt-1 animate-pulse">Attaquant détecté !</div>}
        </div>
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <div className="flex items-center gap-2 text-gray-400 text-xs mb-2"><CheckCircle className="w-4 h-4 text-emerald-400" /> Intacts</div>
          <div className="text-3xl font-bold text-emerald-400">{safe.length}</div>
        </div>
      </div>

      {/* Alertes honeytoken */}
      {honeyAlerts.length > 0 && (
        <div className="bg-red-500/10 border border-red-500/40 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-red-300 mb-3 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" /> Incidents de déception confirmés
          </h3>
          {honeyAlerts.map((alert, i) => (
            <div key={i} className="text-xs text-red-200 bg-red-500/10 rounded-lg p-2 mb-2">
              <p className="font-semibold">{alert.reason}</p>
              <p className="text-red-400 mt-1">{alert.received_at?.slice(0, 19)}</p>
            </div>
          ))}
        </div>
      )}

      {/* Carte des honeytokens */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-4 flex items-center gap-2">
          <Eye className="w-4 h-4 text-orange-400" /> Carte des Honeytokens
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {DEMO_TOKENS.map((token) => (
            <div
              key={token.id}
              className={`rounded-lg border p-3 ${
                token.triggered
                  ? "border-red-500/50 bg-red-500/10"
                  : "border-gray-700 bg-gray-800/50"
              }`}
            >
              <div className="flex items-center gap-2 mb-2">
                <span className={token.triggered ? "text-red-400" : "text-gray-500"}>
                  {TYPE_ICON[token.type] || <Eye className="w-3 h-3" />}
                </span>
                <span className="text-xs font-mono text-gray-400 uppercase">{token.type}</span>
                {token.triggered ? (
                  <span className="ml-auto text-xs bg-red-500/20 text-red-300 px-1.5 rounded animate-pulse">
                    ⚠ DÉCLENCHÉ
                  </span>
                ) : (
                  <span className="ml-auto text-xs bg-emerald-500/20 text-emerald-400 px-1.5 rounded">
                    ✓ Actif
                  </span>
                )}
              </div>
              <div className="text-sm font-medium text-white">{token.description}</div>
              <div className="text-xs text-gray-600 mt-1 font-mono truncate">{token.path}</div>
              {token.triggered && (
                <div className="text-xs text-red-400 mt-2">
                  {token.trigger_count} déclenchement{token.trigger_count > 1 ? "s" : ""}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Explications */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
        <h3 className="text-sm font-semibold text-gray-400 mb-3 flex items-center gap-2">
          <Eye className="w-4 h-4 text-purple-400" /> Comment fonctionne la Deception Engine
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs text-gray-500">
          <div className="space-y-1">
            <div className="text-gray-300 font-semibold">1. Déploiement</div>
            <p>Des fichiers, ports et ressources leurres sont déployés sur toutes les machines protégées.</p>
          </div>
          <div className="space-y-1">
            <div className="text-gray-300 font-semibold">2. Attente passive</div>
            <p>Aucun utilisateur légitime n'a de raison d'accéder à ces ressources. Toute interaction = attaquant.</p>
          </div>
          <div className="space-y-1">
            <div className="text-gray-300 font-semibold">3. Alerte certaine</div>
            <p>Un honeytoken déclenché = 100% de certitude d'un incident. Collecte forensics automatique.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
