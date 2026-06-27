import React, { useMemo } from "react";
import { Activity } from "lucide-react";

interface Alert {
  received_at?: string;
  severity?: string;
  threat_score?: number;
}

export default function ThreatChart({ alerts }: { alerts: Alert[] }) {
  // Regrouper par heure sur les 12 dernières heures
  const timeline = useMemo(() => {
    const now = Date.now();
    const buckets: Record<number, { critical: number; high: number; medium: number; total: number }> = {};

    for (let h = 11; h >= 0; h--) {
      buckets[h] = { critical: 0, high: 0, medium: 0, total: 0 };
    }

    alerts.forEach((a) => {
      if (!a.received_at) return;
      const ts = new Date(a.received_at).getTime();
      const hoursAgo = Math.floor((now - ts) / 3_600_000);
      if (hoursAgo >= 0 && hoursAgo < 12) {
        const bucket = buckets[hoursAgo];
        if (bucket) {
          bucket.total++;
          if (a.severity === "critical") bucket.critical++;
          else if (a.severity === "high") bucket.high++;
          else bucket.medium++;
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

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-4 flex items-center gap-2">
        <Activity className="w-4 h-4 text-blue-400" />
        Activité des menaces — 12 dernières heures
      </h2>

      <div className="flex items-end gap-1 h-24">
        {timeline.map((bucket, idx) => (
          <div key={idx} className="flex-1 flex flex-col items-center gap-0.5">
            <div className="w-full flex flex-col justify-end" style={{ height: "80px" }}>
              {/* Stack des barres */}
              <div
                className="w-full bg-red-500 rounded-sm transition-all"
                style={{ height: `${(bucket.critical / maxVal) * 80}px` }}
              />
              <div
                className="w-full bg-orange-500 rounded-sm transition-all"
                style={{ height: `${(bucket.high / maxVal) * 80}px` }}
              />
              <div
                className="w-full bg-yellow-500 rounded-sm transition-all"
                style={{ height: `${(bucket.medium / maxVal) * 80}px` }}
              />
            </div>
            <span className="text-xs text-gray-600 whitespace-nowrap" style={{ fontSize: "9px" }}>
              {bucket.label}
            </span>
          </div>
        ))}
      </div>

      <div className="flex gap-4 mt-3 text-xs text-gray-500">
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-red-500 inline-block" /> Critique</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-orange-500 inline-block" /> Élevé</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-yellow-500 inline-block" /> Moyen</span>
      </div>
    </div>
  );
}
