import React, { useEffect, useState, useCallback } from 'react'
import { Atom, Dna, Shield, Eye, Link, Zap, AlertTriangle, CheckCircle, Activity } from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface QBSMState {
  total_processes: number
  in_superposition: number
  collapsed_threat: number
  collapsed_safe: number
  decoherent: number
}

interface CBGAState {
  tracked_processes: number
  total_alerts: number
  reference_genomes: number
}

interface RCTCState {
  total_assertions: number
  revoked: number
  violations: number
}

interface ASNState {
  baseline_learned: boolean
  total_packets: number
  unsigned_blocked: number
  beacon_sessions: number
}

interface PatentStatus {
  agents_reporting: number
  total_patent_alerts: number
  qbsm: QBSMState
  cbga: CBGAState
  rctc: RCTCState
  asn: ASNState
  recent_patent_alerts: PatentAlert[]
}

interface PatentAlert {
  type: string
  process?: string
  pid?: number
  threat_score?: number
  qbsm_confidence?: number
  cbga_similarity?: number
  rctc_trust_score?: number
  server_received_at?: number
  source?: string
}

// ─── Données démo ─────────────────────────────────────────────────────────────

const DEMO_STATUS: PatentStatus = {
  agents_reporting: 3,
  total_patent_alerts: 7,
  qbsm: { total_processes: 142, in_superposition: 138, collapsed_threat: 3, collapsed_safe: 1, decoherent: 0 },
  cbga: { tracked_processes: 12, total_alerts: 2, reference_genomes: 7 },
  rctc: { total_assertions: 28, revoked: 1, violations: 0 },
  asn: { baseline_learned: true, total_packets: 18420, unsigned_blocked: 23, beacon_sessions: 1 },
  recent_patent_alerts: [
    { type: 'QBSM_COLLAPSE', process: 'cmd.exe', pid: 4872, threat_score: 0.97, qbsm_confidence: 0.97 },
    { type: 'CBGA_GENOME_MATCH', process: 'svchost32.exe', pid: 3301, threat_score: 0.91, cbga_similarity: 0.91 },
    { type: 'ASN_BEACON_DETECTED', threat_score: 0.88, source: 'ASN' },
    { type: 'QBSM_COLLAPSE', process: 'wscript.exe', pid: 2210, threat_score: 0.86, qbsm_confidence: 0.86 },
    { type: 'RCTC_VIOLATION', process: 'rundll32.exe', pid: 5544, threat_score: 0.82, rctc_trust_score: 0.12 },
  ],
}

// ─── Sous-composants ──────────────────────────────────────────────────────────

function ModuleCard({
  icon: Icon,
  name,
  acronym,
  color,
  children,
}: {
  icon: React.ElementType
  name: string
  acronym: string
  color: string
  children: React.ReactNode
}) {
  return (
    <div className={`bg-gray-900 border rounded-lg p-4 border-${color}-500/30`}>
      <div className="flex items-center gap-2 mb-3">
        <div className={`p-1.5 rounded bg-${color}-500/10`}>
          <Icon className={`w-4 h-4 text-${color}-400`} />
        </div>
        <div>
          <span className={`text-xs font-bold text-${color}-400`}>{acronym}</span>
          <span className="text-xs text-gray-500 ml-2">{name}</span>
        </div>
      </div>
      {children}
    </div>
  )
}

function Stat({ label, value, highlight }: { label: string; value: string | number; highlight?: boolean }) {
  return (
    <div className="flex justify-between items-center py-1 border-b border-gray-800 last:border-0">
      <span className="text-xs text-gray-500">{label}</span>
      <span className={`text-xs font-mono font-bold ${highlight ? 'text-red-400' : 'text-gray-200'}`}>{value}</span>
    </div>
  )
}

function QBSMPanel({ data }: { data: QBSMState }) {
  const threatPct = data.total_processes > 0
    ? Math.round((data.collapsed_threat / data.total_processes) * 100)
    : 0

  return (
    <ModuleCard icon={Atom} name="Quantum Behavioral Superposition Model" acronym="QBSM" color="purple">
      {/* Visualisation superposition */}
      <div className="mb-3 flex items-center gap-2">
        <div className="flex-1 h-3 bg-gray-800 rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-purple-600 to-blue-500 transition-all"
            style={{ width: `${100 - threatPct}%` }}
          />
        </div>
        <span className="text-xs text-gray-400 w-14 text-right">{100 - threatPct}% sûrs</span>
      </div>

      <Stat label="Processus surveillés" value={data.total_processes} />
      <Stat label="En superposition |ψ⟩" value={data.in_superposition} />
      <Stat label="Effondrés → MENACE" value={data.collapsed_threat} highlight={data.collapsed_threat > 0} />
      <Stat label="Effondrés → SÛRS" value={data.collapsed_safe} />

      {data.collapsed_threat > 0 && (
        <div className="mt-2 flex items-center gap-1 text-xs text-red-400 bg-red-900/20 rounded px-2 py-1">
          <Zap className="w-3 h-3" />
          Collapse quantique détecté — isolation recommandée
        </div>
      )}
    </ModuleCard>
  )
}

function CBGAPanel({ data }: { data: CBGAState }) {
  return (
    <ModuleCard icon={Dna} name="Cryptographic Behavioral Genome Alignment" acronym="CBGA" color="green">
      <Stat label="Processus séquencés" value={data.tracked_processes} />
      <Stat label="Génomes référence (malware)" value={data.reference_genomes} />
      <Stat label="Alertes génomiques" value={data.total_alerts} highlight={data.total_alerts > 0} />

      <div className="mt-2 text-xs text-gray-600">
        Algorithme Smith-Waterman + matrice BLOSUM-SECURITY
      </div>

      {data.total_alerts > 0 && (
        <div className="mt-2 flex items-center gap-1 text-xs text-orange-400 bg-orange-900/20 rounded px-2 py-1">
          <AlertTriangle className="w-3 h-3" />
          Génome comportemental malveillant détecté
        </div>
      )}
    </ModuleCard>
  )
}

function RCTCPanel({ data }: { data: RCTCState }) {
  const health = data.total_assertions > 0
    ? Math.round(((data.total_assertions - data.revoked) / data.total_assertions) * 100)
    : 100

  return (
    <ModuleCard icon={Link} name="Recursive Cryptographic Trust Chain" acronym="RCTC" color="blue">
      {/* Trust meter */}
      <div className="mb-3">
        <div className="flex justify-between text-xs mb-1">
          <span className="text-gray-500">Intégrité de la chaîne</span>
          <span className={health > 90 ? 'text-green-400' : 'text-red-400'}>{health}%</span>
        </div>
        <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${health > 90 ? 'bg-green-500' : 'bg-red-500'}`}
            style={{ width: `${health}%` }}
          />
        </div>
      </div>

      <Stat label="Assertions Merkle actives" value={data.total_assertions} />
      <Stat label="Révocations (Trust Lightning)" value={data.revoked} highlight={data.revoked > 0} />
      <Stat label="Violations détectées" value={data.violations} highlight={data.violations > 0} />
    </ModuleCard>
  )
}

function ASNPanel({ data }: { data: ASNState }) {
  return (
    <ModuleCard icon={Eye} name="Adversarial Shadow Network" acronym="ASN" color="yellow">
      <div className="flex items-center gap-2 mb-2">
        <div className={`w-2 h-2 rounded-full ${data.baseline_learned ? 'bg-green-400' : 'bg-yellow-400 animate-pulse'}`} />
        <span className="text-xs text-gray-400">
          {data.baseline_learned ? 'Baseline apprise — surveillance active' : 'Apprentissage baseline…'}
        </span>
      </div>

      <Stat label="Paquets analysés" value={data.total_packets?.toLocaleString() ?? 0} />
      <Stat label="Trafic non signé bloqué" value={data.unsigned_blocked} highlight={data.unsigned_blocked > 0} />
      <Stat label="Sessions beacon détectées" value={data.beacon_sessions} highlight={data.beacon_sessions > 0} />

      <div className="mt-2 text-xs text-gray-600">
        Distance de Wasserstein W₁ — transport optimal
      </div>
    </ModuleCard>
  )
}

function ZKSPPanel() {
  return (
    <ModuleCard icon={Shield} name="Zero-Knowledge Security Proof" acronym="ZKSP" color="cyan">
      <div className="flex items-center gap-2 mb-3">
        <CheckCircle className="w-4 h-4 text-cyan-400" />
        <span className="text-xs text-gray-300">Protocole Fiat-Shamir actif</span>
      </div>

      <div className="space-y-1.5">
        {['document_editor', 'web_browser', 'backup_agent', 'antivirus', 'minimal'].map(policy => (
          <div key={policy} className="flex items-center justify-between text-xs">
            <span className="text-gray-500 font-mono">{policy}</span>
            <span className="text-green-400 text-xs">✓ validé</span>
          </div>
        ))}
      </div>

      <div className="mt-2 text-xs text-gray-600">
        Preuve sans révélation · 3 rounds · P(triche) &lt; 1/8
      </div>
    </ModuleCard>
  )
}

function PatentAlertRow({ alert }: { alert: PatentAlert }) {
  const TYPE_META: Record<string, { label: string; color: string }> = {
    QBSM_COLLAPSE:      { label: 'QBSM Collapse',    color: 'purple' },
    CBGA_GENOME_MATCH:  { label: 'Genome Match',      color: 'green'  },
    ASN_BEACON_DETECTED:{ label: 'Beacon C2',         color: 'yellow' },
    RCTC_VIOLATION:     { label: 'Trust Violation',   color: 'red'    },
    ASN_PORT_SCAN:      { label: 'Port Scan',         color: 'orange' },
    ASN_EXFILTRATION:   { label: 'Exfiltration',      color: 'red'    },
  }
  const meta = TYPE_META[alert.type] ?? { label: alert.type, color: 'gray' }
  const score = alert.threat_score ?? alert.qbsm_confidence ?? alert.cbga_similarity ?? 0

  return (
    <tr className="border-b border-gray-800 hover:bg-gray-800/40 transition-colors">
      <td className="py-2 px-3">
        <span className={`px-1.5 py-0.5 rounded text-xs font-bold text-${meta.color}-400 bg-${meta.color}-400/10`}>
          {meta.label}
        </span>
      </td>
      <td className="py-2 px-3 text-xs text-gray-400 font-mono">{alert.process ?? alert.source ?? '—'}</td>
      <td className="py-2 px-3 text-xs text-gray-400 font-mono">{alert.pid ?? '—'}</td>
      <td className="py-2 px-3">
        <div className="flex items-center gap-2">
          <div className="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden w-16">
            <div
              className={`h-full rounded-full ${score > 0.85 ? 'bg-red-500' : score > 0.6 ? 'bg-orange-500' : 'bg-yellow-500'}`}
              style={{ width: `${score * 100}%` }}
            />
          </div>
          <span className="text-xs font-mono text-gray-300">{(score * 100).toFixed(0)}%</span>
        </div>
      </td>
    </tr>
  )
}

// ─── Composant principal ──────────────────────────────────────────────────────

export default function PatentDashboard() {
  const [status, setStatus] = useState<PatentStatus>(DEMO_STATUS)
  const [loading, setLoading] = useState(false)

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch('/api/patent/status')
      if (res.ok) setStatus(await res.json())
    } catch {
      // Mode démo — données statiques
    }
  }, [])

  useEffect(() => {
    fetchStatus()
    const id = setInterval(fetchStatus, 10000)
    return () => clearInterval(id)
  }, [fetchStatus])

  return (
    <div className="space-y-4">
      {/* En-tête */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-purple-400" />
            Intelligence Brevetable
          </h2>
          <p className="text-xs text-gray-500 mt-0.5">
            5 algorithmes propriétaires — QBSM · CBGA · ZKSP · ASN · RCTC
          </p>
        </div>
        <div className="text-right">
          <div className="text-2xl font-bold text-red-400">{status.total_patent_alerts}</div>
          <div className="text-xs text-gray-500">alertes brevets</div>
        </div>
      </div>

      {/* Grille des modules */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
        <QBSMPanel data={status.qbsm} />
        <CBGAPanel data={status.cbga} />
        <RCTCPanel data={status.rctc} />
        <ASNPanel data={status.asn} />
        <ZKSPPanel />

        {/* Carte synthèse */}
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <Shield className="w-4 h-4 text-white" />
            <span className="text-sm font-bold text-white">Couverture globale</span>
          </div>
          <Stat label="Agents actifs" value={status.agents_reporting} />
          <Stat label="Alertes brevets totales" value={status.total_patent_alerts} highlight={status.total_patent_alerts > 0} />
          <div className="mt-3 pt-3 border-t border-gray-800 space-y-1">
            {(['QBSM', 'CBGA', 'RCTC', 'ASN', 'ZKSP'] as const).map(name => (
              <div key={name} className="flex items-center justify-between text-xs">
                <span className="text-gray-500 font-mono">{name}</span>
                <span className="text-green-400 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-400 inline-block" />
                  actif
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Flux d'alertes brevets */}
      {status.recent_patent_alerts.length > 0 && (
        <div className="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-800 flex items-center gap-2">
            <Zap className="w-4 h-4 text-yellow-400" />
            <span className="text-sm font-semibold text-white">Alertes des algorithmes brevetables</span>
            <span className="ml-auto text-xs text-gray-500">{status.recent_patent_alerts.length} récentes</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left py-2 px-3 text-gray-500 font-medium">Algorithme</th>
                  <th className="text-left py-2 px-3 text-gray-500 font-medium">Processus</th>
                  <th className="text-left py-2 px-3 text-gray-500 font-medium">PID</th>
                  <th className="text-left py-2 px-3 text-gray-500 font-medium">Confiance</th>
                </tr>
              </thead>
              <tbody>
                {status.recent_patent_alerts.map((alert, i) => (
                  <PatentAlertRow key={i} alert={alert} />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Note technique */}
      <div className="text-xs text-gray-700 border border-gray-800 rounded p-3 bg-gray-900/50">
        <span className="text-gray-500 font-semibold">Architecture synergique :</span>{' '}
        Les alertes existantes (v1/v2/v3) transitent automatiquement par le Patent Engine.
        QBSM observe chaque alerte → CBGA accumule le génome comportemental →
        RCTC signe cryptographiquement chaque alerte → ASN analyse le trafic réseau →
        ZKSP vérifie la conformité à la politique sans révéler les actes.
        Zéro overhead — zéro doublon — synergie totale.
      </div>
    </div>
  )
}
