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

const TECHNIQUE_MAP: Record<string, { phase: number; name: string; id: string }> = {
  "SUSPICIOUS_PROCESS": { phase: 2, name: "Command Execution", id: "T1059" },
  "FILE_THREAT": { phase: 2, name: "Malicious File", id: "T1204" },
  "NAC_BLOCK": { phase: 6, name: "Remote Services", id: "T1021" },
  "MEMORY_THREAT": { phase: 4, name: "Process Injection", id: "T1055" },
  "DNA_MUTATION": { phase: 5, name: "Masquerading", id: "T1036" },
  "HONEYTOKEN_TRIGGERED": { phase: 6, name: "Discovery", id: "T1083" },
  "UEBA_ANOMALY": { phase: 1, name: "Valid Accounts", id: "T1078" },
  "SIGNATURE_MATCH": { phase: 2, name: "Known Malware", id: "T1204" },
};

const COLOR_CLASSES: Record<string, string> = {
  yellow: "border-yellow-500 bg-yellow-500/10 text-yellow-300",
  orange: "border-orange-500 bg-orange-500/10 text-orange-300",
  red: "border-red-500 bg-red-500/10 text-red-300",
  purple: "border-purple-500 bg-purple-500/10 text-purple-300",
  gray: "border-gray-700 bg-gray-800/50 text-gray-500",
};

const URGENCY_ACTIONS: Record<number, string> = {
  1: "Monitorer les scans — bloquer les IPs suspectes",
  2: "Bloquer l'exécution — suspendre les processus suspects",
  3: "Supprimer les mécanismes de persistance",
  4: "Révoquer les tokens — forcer reauth",
  5: "Renforcer les logs — isoler les outils suspects",
  6: "ISOLER le segment réseau — bloquer SMB/RDP interne",
  7: "Bloquer trafic sortant — activer DLP",
  8: "ISOLER TOUT — activer le plan de reprise d'activité",
};

interface Alert {
  type: string;
  severity?: string;
  threat_score?: number;
  process?: string;
  reason?: string;
  agent_id?: string;
  received_at?: string;
  kill_chain_phase?: number;
  mitre_technique_id?: string;
  mitre_technique_name?: string;
  campaign_id?: string;
}

export default function KillChainView({ alerts }: { alerts: Alert[] }) {
  const phaseData = useMemo(() => {
    const counts: Record<number, { count: number; alerts: Alert[]; max_score: number }> = {};
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

  const maxPhaseReached = Math.max(
    ...Object.entries(phaseData).filter(([, v]) => v.count > 0).map(([k]) => Number(k)),
    0
  );

  const campaigns = useMemo(() => {
    const map: Record<string, { id: string; count: number; maxPhase: number; agent: string }> = {};
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

  return (
    <div className="space-y-6">
      {/* Kill Chain visuelle */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <div className="flex items-center gap-2 mb-6">
          <Target className="w-5 h-5 text-red-400" />
          <h2 className="text-sm font-semibold uppercase tracking-wider text-gray-400">
            MITRE ATT&CK Kill Chain — État en temps réel
          </h2>
          {maxPhaseReached >= 6 && (
            <span className="ml-auto text-xs bg-red-500/20 border border-red-500 text-red-300 px-2 py-0.5 rounded-full animate-pulse">
              ⚠ Phase critique atteinte
            </span>
          )}
        </div>

        {/* Phases */}
        <div className="flex items-stretch gap-1 overflow-x-auto pb-2">
          {PHASES.map((phase, idx) => {
            const data = phaseData[phase.id];
            const isActive = data.count > 0;
            const isCurrent = phase.id === maxPhaseReached;
            const colorKey = isActive ? phase.color : "gray";
            const colorClass = COLOR_CLASSES[colorKey];

            return (
              <React.Fragment key={phase.id}>
                <div className={`flex-1 min-w-[90px] rounded-lg border p-3 transition-all ${colorClass} ${isCurrent ? "ring-2 ring-white/20 scale-105" : ""}`}>
                  <div className="text-xs font-bold mb-1 opacity-60">Phase {phase.id}</div>
                  <div className="text-xs font-semibold mb-2 leading-tight">{phase.short}</div>
                  {isActive ? (
                    <>
                      <div className="text-2xl font-bold">{data.count}</div>
                      <div className="text-xs opacity-60 mt-1">alertes</div>
                      <div className="mt-2 h-1 bg-white/20 rounded-full">
                        <div
                          className="h-full bg-white/60 rounded-full"
                          style={{ width: `${data.max_score * 100}%` }}
                        />
                      </div>
                    </>
                  ) : (
                    <div className="text-2xl font-bold opacity-20">—</div>
                  )}
                  {isCurrent && <div className="text-xs mt-1 font-bold opacity-80">← ICI</div>}
                </div>
                {idx < PHASES.length - 1 && (
                  <ChevronRight className="w-4 h-4 text-gray-700 self-center shrink-0" />
                )}
              </React.Fragment>
            );
          })}
        </div>

        {/* Action recommandée */}
        {maxPhaseReached > 0 && (
          <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
            <div className="flex items-center gap-2 text-red-300">
              <Zap className="w-4 h-4 shrink-0" />
              <span className="text-sm font-semibold">Action recommandée (Phase {maxPhaseReached}) :</span>
            </div>
            <p className="text-sm text-red-200 mt-1 ml-6">{URGENCY_ACTIONS[maxPhaseReached]}</p>
          </div>
        )}
      </div>

      {/* Campagnes actives */}
      {campaigns.length > 0 && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-4 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-orange-400" />
            Campagnes d'attaque actives
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {campaigns.map((c) => (
              <div key={c.id} className="border border-orange-500/30 bg-orange-500/5 rounded-lg p-3">
                <div className="text-xs font-mono text-orange-400 font-bold">{c.id}</div>
                <div className="text-xs text-gray-400 mt-1">Agent: {c.agent}</div>
                <div className="flex items-center justify-between mt-2">
                  <span className="text-xs text-gray-500">{c.count} alertes</span>
                  <span className="text-xs text-orange-300">Phase {c.maxPhase}/{PHASES.length}</span>
                </div>
                <div className="mt-1 h-1 bg-gray-700 rounded-full">
                  <div
                    className="h-full bg-orange-500 rounded-full"
                    style={{ width: `${(c.maxPhase / PHASES.length) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Techniques MITRE détectées */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-4 flex items-center gap-2">
          <Shield className="w-4 h-4 text-blue-400" />
          Techniques MITRE ATT&CK détectées
        </h3>
        {alerts.length === 0 ? (
          <div className="text-center text-gray-600 py-6">
            <Shield className="w-8 h-8 mx-auto mb-2 opacity-20" />
            <p className="text-xs">Aucune technique détectée</p>
          </div>
        ) : (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
            {Object.entries(
              alerts.reduce((acc, a) => {
                const t = TECHNIQUE_MAP[a.type];
                if (t) acc[t.id] = { name: t.name, id: t.id, count: (acc[t.id]?.count || 0) + 1 };
                return acc;
              }, {} as Record<string, { name: string; id: string; count: number }>)
            ).map(([id, tech]) => (
              <div key={id} className="border border-blue-500/20 bg-blue-500/5 rounded-lg p-2">
                <div className="text-xs font-mono text-blue-400">{id}</div>
                <div className="text-xs text-gray-300 mt-0.5 leading-tight">{tech.name}</div>
                <div className="text-lg font-bold text-white mt-1">{tech.count}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
