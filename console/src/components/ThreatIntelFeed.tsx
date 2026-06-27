import React, { useMemo } from "react";
import { Globe, Shield, Hash, Network, Terminal, TrendingUp } from "lucide-react";

const DEMO_IOCS = [
  { id: "ioc_001", type: "file_hash", threat: "Meterpreter Stager", severity: "critical", confidence: 0.98, seen_count: 47, value: "a3f4b2c1d5e6f789..." },
  { id: "ioc_002", type: "ip", threat: "C2 Server (Cobalt Strike)", severity: "critical", confidence: 0.95, seen_count: 128, value: "185.220.101.47" },
  { id: "ioc_003", type: "domain", threat: "Phishing Domain", severity: "high", confidence: 0.87, seen_count: 23, value: "update-microsoft-secure.com" },
  { id: "ioc_004", type: "cmdline_pattern", threat: "PowerShell Encoded Downloader", severity: "high", confidence: 0.82, seen_count: 89, value: "powershell.*-Enc.*[A-Z0-9+/]{50,}" },
  { id: "ioc_005", type: "file_hash", threat: "Mimikatz Variant", severity: "critical", confidence: 0.99, seen_count: 312, value: "deadbeefdeadbeef..." },
  { id: "ioc_006", type: "ip", threat: "Tor Exit Node", severity: "medium", confidence: 0.70, seen_count: 7, value: "198.96.155.3" },
  { id: "ioc_007", type: "cmdline_pattern", threat: "LOLBin certutil downloader", severity: "high", confidence: 0.88, seen_count: 54, value: "certutil.*-urlcache.*-f.*http" },
  { id: "ioc_008", type: "domain", threat: "Ransomware C2", severity: "critical", confidence: 0.96, seen_count: 201, value: "pay-now-xmr.onion.ws" },
];

const TYPE_ICON: Record<string, React.ReactNode> = {
  file_hash: <Hash className="w-3 h-3" />,
  ip: <Network className="w-3 h-3" />,
  domain: <Globe className="w-3 h-3" />,
  cmdline_pattern: <Terminal className="w-3 h-3" />,
};

const SEV_COLOR: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
};

interface Alert { type: string; hash?: string; }

export default function ThreatIntelFeed({ alerts }: { alerts: Alert[] }) {
  const confirmedCount = useMemo(
    () => alerts.filter((a) => (a as any).threat_intel_confirmed).length,
    [alerts]
  );

  const typeStats = DEMO_IOCS.reduce((acc, ioc) => {
    acc[ioc.type] = (acc[ioc.type] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <div className="text-xs text-gray-500 mb-1 flex items-center gap-1"><Shield className="w-3 h-3" /> IOC totaux</div>
          <div className="text-2xl font-bold text-white">{DEMO_IOCS.length}</div>
          <div className="text-xs text-emerald-400 mt-1">Base locale</div>
        </div>
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <div className="text-xs text-gray-500 mb-1 flex items-center gap-1"><Hash className="w-3 h-3" /> Hashes</div>
          <div className="text-2xl font-bold text-white">{typeStats.file_hash || 0}</div>
        </div>
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <div className="text-xs text-gray-500 mb-1 flex items-center gap-1"><Network className="w-3 h-3" /> IPs / Domaines</div>
          <div className="text-2xl font-bold text-white">{(typeStats.ip || 0) + (typeStats.domain || 0)}</div>
        </div>
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <div className="text-xs text-gray-500 mb-1 flex items-center gap-1"><TrendingUp className="w-3 h-3" /> Confirmés alertes</div>
          <div className="text-2xl font-bold text-emerald-400">{confirmedCount}</div>
        </div>
      </div>

      {/* Statut réseau fédéré */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
        <h3 className="text-sm font-semibold text-gray-400 mb-4 flex items-center gap-2">
          <Globe className="w-4 h-4 text-blue-400" /> Réseau Federated Threat Intelligence
        </h3>
        <div className="grid grid-cols-3 gap-4 text-center">
          <div>
            <div className="text-2xl font-bold text-blue-400">1</div>
            <div className="text-xs text-gray-500 mt-1">Votre organisation</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-gray-600">—</div>
            <div className="text-xs text-gray-600 mt-1">Hub central (hors ligne)</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-gray-600">0</div>
            <div className="text-xs text-gray-500 mt-1">Pairs connectés</div>
          </div>
        </div>
        <div className="mt-3 p-2 bg-blue-500/10 border border-blue-500/20 rounded text-xs text-blue-300">
          Mode local actif — connectez le hub Gravity pour activer l'immunité collective
        </div>
      </div>

      {/* Table IOC */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-4">
          Base d'IOC locale — {DEMO_IOCS.length} indicateurs
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-gray-600 border-b border-gray-800">
                <th className="text-left pb-2 font-medium">Type</th>
                <th className="text-left pb-2 font-medium">Valeur</th>
                <th className="text-left pb-2 font-medium">Menace</th>
                <th className="text-left pb-2 font-medium">Sévérité</th>
                <th className="text-right pb-2 font-medium">Confiance</th>
                <th className="text-right pb-2 font-medium">Vus</th>
              </tr>
            </thead>
            <tbody>
              {DEMO_IOCS.map((ioc) => (
                <tr key={ioc.id} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors">
                  <td className="py-2">
                    <span className="flex items-center gap-1 text-gray-400">
                      {TYPE_ICON[ioc.type]}
                      {ioc.type.replace("_", " ")}
                    </span>
                  </td>
                  <td className="py-2 font-mono text-gray-300">{ioc.value}</td>
                  <td className="py-2 text-gray-300">{ioc.threat}</td>
                  <td className="py-2">
                    <span className={`px-1.5 py-0.5 rounded border text-xs ${SEV_COLOR[ioc.severity] || ""}`}>
                      {ioc.severity}
                    </span>
                  </td>
                  <td className="py-2 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <div className="w-12 h-1 bg-gray-700 rounded-full">
                        <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${ioc.confidence * 100}%` }} />
                      </div>
                      <span className="text-gray-400">{Math.round(ioc.confidence * 100)}%</span>
                    </div>
                  </td>
                  <td className="py-2 text-right text-gray-400">{ioc.seen_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
