import React, { useEffect, useState } from 'react'
import { Server, Cpu, Wifi, AlertTriangle, CheckCircle, TrendingUp, Database, Globe } from 'lucide-react'

interface Collector {
  online: boolean
  total_sent: number
  last_seen_ago: number
}

interface QueueStats {
  critical_pending: number
  normal_pending: number
  total_enqueued: number
}

interface ScaleStatus {
  architecture: string
  target_capacity: string
  bulk_processor: {
    uptime_seconds: number
    received_total: number
    saved_total: number
    throughput_rps: number
    dedup_cache_size: number
    total_deduplicated: number
    collectors: number
    queue: QueueStats
    capacity: { target_agents: number; max_rps: number; bulk_flush_sec: number }
  }
  collectors: Record<string, Collector>
  recommendations: string[]
}

const DEMO_STATUS: ScaleStatus = {
  architecture: "3-tier (agents → collectors → cluster)",
  target_capacity: "10 000 agents",
  bulk_processor: {
    uptime_seconds: 3612,
    received_total: 487_320,
    saved_total: 481_002,
    throughput_rps: 134.9,
    dedup_cache_size: 28_441,
    total_deduplicated: 61_887,
    collectors: 8,
    queue: { critical_pending: 2, normal_pending: 47, total_enqueued: 487_320 },
    capacity: { target_agents: 10_000, max_rps: 2_000, bulk_flush_sec: 2 },
  },
  collectors: {
    "collector-eu-west-1": { online: true, total_sent: 82_400, last_seen_ago: 0.8 },
    "collector-eu-west-2": { online: true, total_sent: 76_120, last_seen_ago: 1.2 },
    "collector-us-east-1": { online: true, total_sent: 91_300, last_seen_ago: 0.6 },
    "collector-us-west-1": { online: true, total_sent: 68_900, last_seen_ago: 2.1 },
    "collector-ap-south-1": { online: true, total_sent: 54_200, last_seen_ago: 1.8 },
    "collector-ap-north-1": { online: false, total_sent: 42_100, last_seen_ago: 45.3 },
    "collector-af-1": { online: true, total_sent: 38_800, last_seen_ago: 1.5 },
    "collector-latam-1": { online: true, total_sent: 33_500, last_seen_ago: 2.8 },
  },
  recommendations: ["Système nominal"],
}

function MetricCard({ label, value, sub, icon: Icon, warn }: {
  label: string; value: string | number; sub?: string; icon: React.ElementType; warn?: boolean
}) {
  return (
    <div className={`bg-gray-900 border rounded-lg p-4 ${warn ? 'border-orange-500/40' : 'border-gray-700'}`}>
      <div className="flex items-center gap-2 mb-2">
        <Icon className={`w-4 h-4 ${warn ? 'text-orange-400' : 'text-blue-400'}`} />
        <span className="text-xs text-gray-500">{label}</span>
      </div>
      <div className={`text-2xl font-bold font-mono ${warn ? 'text-orange-300' : 'text-white'}`}>{value}</div>
      {sub && <div className="text-xs text-gray-600 mt-1">{sub}</div>}
    </div>
  )
}

export default function ScaleView() {
  const [status, setStatus] = useState<ScaleStatus>(DEMO_STATUS)

  useEffect(() => {
    const fetch_status = async () => {
      try {
        const res = await fetch('/api/scale/status')
        if (res.ok) setStatus(await res.json())
      } catch { /* démo */ }
    }
    fetch_status()
    const id = setInterval(fetch_status, 5000)
    return () => clearInterval(id)
  }, [])

  const bp = status.bulk_processor
  const collectors = Object.entries(status.collectors)
  const online = collectors.filter(([, c]) => c.online).length
  const loadPct = Math.min(Math.round((bp.throughput_rps / bp.capacity.max_rps) * 100), 100)

  return (
    <div className="space-y-4">
      {/* En-tête */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Globe className="w-5 h-5 text-blue-400" />
            Architecture Scale — 10 000 Machines
          </h2>
          <p className="text-xs text-gray-500 mt-0.5">{status.architecture}</p>
        </div>
        <div className="text-right">
          <div className="text-2xl font-bold text-blue-400">{bp.throughput_rps}</div>
          <div className="text-xs text-gray-500">alertes/sec actuelles</div>
        </div>
      </div>

      {/* Métriques globales */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <MetricCard
          icon={TrendingUp} label="Alertes reçues"
          value={bp.received_total.toLocaleString()}
          sub={`${bp.saved_total.toLocaleString()} persistées`}
        />
        <MetricCard
          icon={Database} label="Dédupliquées"
          value={bp.total_deduplicated.toLocaleString()}
          sub={`Cache ${bp.dedup_cache_size.toLocaleString()} entrées TTL 60s`}
        />
        <MetricCard
          icon={Server} label="Collectors actifs"
          value={`${online}/${collectors.length}`}
          sub="Niveau 2 — régionaux"
          warn={online < collectors.length}
        />
        <MetricCard
          icon={Cpu} label="Queue normale"
          value={bp.queue.normal_pending}
          sub={`${bp.queue.critical_pending} critiques en temps réel`}
          warn={bp.queue.normal_pending > 5000}
        />
      </div>

      {/* Charge système */}
      <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm font-semibold text-white">Charge du cluster central</span>
          <span className={`text-sm font-mono ${loadPct > 70 ? 'text-orange-400' : 'text-green-400'}`}>
            {loadPct}% ({bp.throughput_rps} / {bp.capacity.max_rps} rps max)
          </span>
        </div>
        <div className="h-4 bg-gray-800 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-1000 ${
              loadPct > 80 ? 'bg-red-500' : loadPct > 60 ? 'bg-orange-500' : 'bg-green-500'
            }`}
            style={{ width: `${loadPct}%` }}
          />
        </div>
        <div className="flex justify-between text-xs text-gray-600 mt-1">
          <span>0</span>
          <span>500 rps — 1 instance FastAPI</span>
          <span>2 000 rps max</span>
        </div>
      </div>

      {/* Architecture 3 niveaux */}
      <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-white mb-4">Architecture 3 niveaux</h3>
        <div className="flex items-stretch gap-4 overflow-x-auto">
          {/* Niveau 1 : Agents */}
          <div className="flex-1 min-w-32 bg-gray-800/50 rounded-lg p-3 border border-gray-700">
            <div className="text-xs font-bold text-emerald-400 mb-2">NIVEAU 1</div>
            <div className="text-lg font-bold text-white">10 000</div>
            <div className="text-xs text-gray-400">agents légers</div>
            <div className="mt-2 space-y-1 text-xs text-gray-600">
              <div>• Batch 50 alertes / 5s</div>
              <div>• Heartbeat UDP 10s</div>
              <div>• Ring buffer 10k local</div>
              <div>• Compression zlib-6 (4x)</div>
            </div>
          </div>

          {/* Flèche */}
          <div className="flex items-center text-gray-600 text-2xl">→</div>

          {/* Niveau 2 : Collectors */}
          <div className="flex-1 min-w-32 bg-gray-800/50 rounded-lg p-3 border border-blue-500/30">
            <div className="text-xs font-bold text-blue-400 mb-2">NIVEAU 2</div>
            <div className="text-lg font-bold text-white">{collectors.length}</div>
            <div className="text-xs text-gray-400">collectors régionaux</div>
            <div className="mt-2 space-y-1 text-xs text-gray-600">
              <div>• 500-1000 agents chacun</div>
              <div>• Dédup locale 15s</div>
              <div>• Flush central 3s</div>
              <div>• Failover SQLite local</div>
            </div>
          </div>

          {/* Flèche */}
          <div className="flex items-center text-gray-600 text-2xl">→</div>

          {/* Niveau 3 : Cluster */}
          <div className="flex-1 min-w-32 bg-gray-800/50 rounded-lg p-3 border border-purple-500/30">
            <div className="text-xs font-bold text-purple-400 mb-2">NIVEAU 3</div>
            <div className="text-lg font-bold text-white">Cluster</div>
            <div className="text-xs text-gray-400">serveur central</div>
            <div className="mt-2 space-y-1 text-xs text-gray-600">
              <div>• BulkProcessor async</div>
              <div>• Dédup globale 60s TTL</div>
              <div>• Bulk insert DB / 2s</div>
              <div>• PostgreSQL + Redis</div>
            </div>
          </div>
        </div>
      </div>

      {/* Collectors régionaux */}
      <div className="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-800 flex items-center gap-2">
          <Wifi className="w-4 h-4 text-blue-400" />
          <span className="text-sm font-semibold text-white">Collectors régionaux</span>
          <span className="ml-auto text-xs text-gray-500">
            <span className="text-green-400">{online}</span>/{collectors.length} en ligne
          </span>
        </div>
        <div className="divide-y divide-gray-800">
          {collectors.map(([id, info]) => (
            <div key={id} className="px-4 py-2.5 flex items-center gap-3">
              <div className={`w-2 h-2 rounded-full flex-shrink-0 ${info.online ? 'bg-green-400' : 'bg-red-400'}`} />
              <span className="text-xs font-mono text-gray-300 flex-1">{id}</span>
              <span className="text-xs text-gray-500">{info.total_sent.toLocaleString()} alertes</span>
              <span className={`text-xs ${info.online ? 'text-gray-600' : 'text-red-400'}`}>
                {info.online ? `vu il y a ${info.last_seen_ago}s` : `HORS LIGNE ${Math.round(info.last_seen_ago)}s`}
              </span>
              {!info.online && <AlertTriangle className="w-3 h-3 text-red-400" />}
            </div>
          ))}
        </div>
      </div>

      {/* Recommandations */}
      {status.recommendations.length > 0 && (
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-green-400" />
            Recommandations système
          </h3>
          <ul className="space-y-1">
            {status.recommendations.map((rec, i) => (
              <li key={i} className="text-xs text-gray-400 flex items-start gap-2">
                <span className="text-blue-400 mt-0.5">→</span>
                {rec}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Guide déploiement */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 text-xs text-gray-600 font-mono space-y-1">
        <div className="text-gray-500 font-sans font-semibold mb-2">Déploiement 10 000 machines :</div>
        <div><span className="text-green-400"># 1.</span> Déployer les collectors régionaux (1 VM par 500 agents)</div>
        <div>python collector/src/main.py --id collector-eu-1 --central http://cluster:8000 --port 8001</div>
        <div className="pt-1"><span className="text-green-400"># 2.</span> Configurer les agents vers leur collector</div>
        <div>{"{ \"collector_url\": \"http://collector-eu-1:8001\", \"fallback\": [\"http://collector-eu-2:8001\"] }"}</div>
        <div className="pt-1"><span className="text-green-400"># 3.</span> Cluster central (3 instances derrière Nginx)</div>
        <div>uvicorn server.src.main:app --workers 4 --port 8000</div>
      </div>
    </div>
  )
}
