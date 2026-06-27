import { useEffect, useState } from "react";
import {
  AlertTriangle, Shield, Clock, Activity, CheckCircle,
  XCircle, ChevronDown, ChevronUp, Zap
} from "lucide-react";

interface TimelineEntry {
  ts: number;
  action: string;
  detail: string;
  auto: boolean;
}

interface Incident {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  status: "open" | "investigating" | "contained" | "closed";
  affected_agents: string[];
  alert_count: number;
  kill_chain_phase: string | null;
  mitre_tactics: string[];
  first_seen: number;
  last_updated: number;
  timeline: TimelineEntry[];
  response_actions: string[];
  playbook: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ff4444",
  high:     "#ff8800",
  medium:   "#ffcc00",
  low:      "#44bb44",
};

const STATUS_LABELS: Record<string, string> = {
  open:          "Ouvert",
  investigating: "En cours",
  contained:     "Contenu",
  closed:        "Fermé",
};

const DEMO_INCIDENTS: Incident[] = [
  {
    id: "ag-eu-001:RANSOMWARE",
    title: "[RANSOMWARE] — ag-eu-west-00042",
    severity: "critical",
    status: "investigating",
    affected_agents: ["ag-eu-west-00042"],
    alert_count: 7,
    kill_chain_phase: "Actions on Objectives",
    mitre_tactics: ["T1486", "T1490"],
    first_seen: Date.now() / 1000 - 420,
    last_updated: Date.now() / 1000 - 30,
    playbook: "ransomware",
    response_actions: ["kill_process", "isolate_agent", "snapshot", "preserve_evidence", "notify_soc"],
    timeline: [
      { ts: Date.now() / 1000 - 420, action: "incident_opened", detail: "Corrélation: QBSM_COLLAPSE, RANSOMWARE_DETECTED en 60s", auto: true },
      { ts: Date.now() / 1000 - 419, action: "kill_process", detail: "SIGKILL envoyé à locker.exe (PID 4872)", auto: true },
      { ts: Date.now() / 1000 - 418, action: "isolate_agent", detail: "Agent ag-eu-west-00042 mis en quarantaine réseau", auto: true },
      { ts: Date.now() / 1000 - 418, action: "snapshot", detail: "Image disque initiée sur ag-eu-west-00042", auto: true },
      { ts: Date.now() / 1000 - 417, action: "preserve_evidence", detail: "Snapshot mémoire + logs capturés", auto: true },
      { ts: Date.now() / 1000 - 417, action: "notify_soc", detail: "Incident notifié au SOC", auto: true },
      { ts: Date.now() / 1000 - 60,  action: "new_alert", detail: "FILE_THREAT sur ag-eu-west-00042", auto: true },
    ],
  },
  {
    id: "ag-us-002:SUPPLY_CHAIN_ATTACK",
    title: "[SUPPLY CHAIN] — ag-us-east-00117",
    severity: "critical",
    status: "contained",
    affected_agents: ["ag-us-east-00117"],
    alert_count: 2,
    kill_chain_phase: "Delivery",
    mitre_tactics: ["T1195", "T1574"],
    first_seen: Date.now() / 1000 - 3600,
    last_updated: Date.now() / 1000 - 1800,
    playbook: "supply_chain",
    response_actions: ["kill_process", "quarantine_file", "preserve_evidence", "notify_soc"],
    timeline: [
      { ts: Date.now() / 1000 - 3600, action: "incident_opened", detail: "SUPPLY_CHAIN_DLL_HIJACK détecté", auto: true },
      { ts: Date.now() / 1000 - 3599, action: "kill_process", detail: "SIGKILL envoyé à updater.exe (PID 2240)", auto: true },
      { ts: Date.now() / 1000 - 3598, action: "quarantine_file", detail: "DLL malveillante mise en quarantaine", auto: true },
      { ts: Date.now() / 1000 - 1800, action: "status_change", detail: "→ contained — DLL supprimée et vérifiée", auto: false },
    ],
  },
  {
    id: "ag-ap-003:DECEPTION_HIT",
    title: "[HONEYPOT] — ag-ap-south-00312",
    severity: "high",
    status: "open",
    affected_agents: ["ag-ap-south-00312"],
    alert_count: 1,
    kill_chain_phase: "Reconnaissance",
    mitre_tactics: ["T1083", "T1040"],
    first_seen: Date.now() / 1000 - 120,
    last_updated: Date.now() / 1000 - 115,
    playbook: "deception",
    response_actions: ["block_network", "preserve_evidence", "investigate", "notify_soc"],
    timeline: [
      { ts: Date.now() / 1000 - 120, action: "incident_opened", detail: "HONEYTOKEN_TRIGGERED — accès fichier appât", auto: true },
      { ts: Date.now() / 1000 - 119, action: "block_network", detail: "Règles NAC activées sur ag-ap-south-00312", auto: true },
      { ts: Date.now() / 1000 - 119, action: "preserve_evidence", detail: "Snapshot mémoire capturé", auto: true },
      { ts: Date.now() / 1000 - 119, action: "notify_soc", detail: "Incident notifié au SOC", auto: true },
    ],
  },
];

function formatAge(ts: number): string {
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60) return `il y a ${s}s`;
  if (s < 3600) return `il y a ${Math.floor(s / 60)}min`;
  return `il y a ${Math.floor(s / 3600)}h`;
}

function formatTs(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString("fr-FR");
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span style={{
      background: SEVERITY_COLORS[severity] + "22",
      color: SEVERITY_COLORS[severity],
      border: `1px solid ${SEVERITY_COLORS[severity]}55`,
      borderRadius: 4,
      padding: "2px 8px",
      fontSize: 11,
      fontWeight: 700,
      textTransform: "uppercase",
    }}>
      {severity}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    open: "#ff4444", investigating: "#ff8800", contained: "#44bb44", closed: "#888",
  };
  return (
    <span style={{
      background: colors[status] + "22",
      color: colors[status],
      border: `1px solid ${colors[status]}55`,
      borderRadius: 4,
      padding: "2px 8px",
      fontSize: 11,
    }}>
      {STATUS_LABELS[status] ?? status}
    </span>
  );
}

function IncidentCard({ incident }: { incident: Incident }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div style={{
      background: "#0d1117",
      border: `1px solid ${SEVERITY_COLORS[incident.severity]}44`,
      borderRadius: 8,
      marginBottom: 12,
      overflow: "hidden",
    }}>
      {/* Header */}
      <div
        style={{
          padding: "12px 16px",
          display: "flex",
          alignItems: "center",
          gap: 12,
          cursor: "pointer",
          borderLeft: `3px solid ${SEVERITY_COLORS[incident.severity]}`,
        }}
        onClick={() => setExpanded(!expanded)}
      >
        <AlertTriangle size={16} color={SEVERITY_COLORS[incident.severity]} />
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 600, fontSize: 13, color: "#e6edf3" }}>
            {incident.title}
          </div>
          <div style={{ fontSize: 11, color: "#7d8590", marginTop: 2 }}>
            {incident.kill_chain_phase} · {incident.alert_count} alertes ·{" "}
            {formatAge(incident.first_seen)}
          </div>
        </div>
        <SeverityBadge severity={incident.severity} />
        <StatusBadge status={incident.status} />
        {expanded ? <ChevronUp size={14} color="#7d8590" /> : <ChevronDown size={14} color="#7d8590" />}
      </div>

      {/* Expanded */}
      {expanded && (
        <div style={{ padding: "0 16px 16px", borderTop: "1px solid #21262d" }}>
          {/* Métadonnées */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, margin: "12px 0" }}>
            <div>
              <div style={{ fontSize: 10, color: "#7d8590", marginBottom: 4 }}>AGENTS AFFECTÉS</div>
              {incident.affected_agents.map(a => (
                <div key={a} style={{ fontSize: 12, color: "#58a6ff" }}>{a}</div>
              ))}
            </div>
            <div>
              <div style={{ fontSize: 10, color: "#7d8590", marginBottom: 4 }}>MITRE ATT&CK</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {incident.mitre_tactics.map(t => (
                  <span key={t} style={{
                    fontSize: 10, background: "#21262d", color: "#8b949e",
                    padding: "2px 6px", borderRadius: 4,
                  }}>{t}</span>
                ))}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: "#7d8590", marginBottom: 4 }}>PLAYBOOK</div>
              <div style={{ fontSize: 12, color: "#d2a8ff", textTransform: "uppercase" }}>
                {incident.playbook}
              </div>
            </div>
          </div>

          {/* Actions exécutées */}
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 10, color: "#7d8590", marginBottom: 6 }}>ACTIONS DE RÉPONSE</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {incident.response_actions.map(a => (
                <span key={a} style={{
                  fontSize: 11, background: "#1f6feb22", color: "#58a6ff",
                  border: "1px solid #1f6feb55", padding: "2px 8px", borderRadius: 4,
                }}>
                  ✓ {a.replace(/_/g, " ")}
                </span>
              ))}
            </div>
          </div>

          {/* Timeline */}
          <div>
            <div style={{ fontSize: 10, color: "#7d8590", marginBottom: 6 }}>CHRONOLOGIE</div>
            {incident.timeline.map((entry, i) => (
              <div key={i} style={{
                display: "flex", gap: 10, fontSize: 11, marginBottom: 4, alignItems: "flex-start",
              }}>
                <span style={{ color: "#7d8590", minWidth: 60 }}>{formatTs(entry.ts)}</span>
                <span style={{
                  color: entry.auto ? "#3fb950" : "#f0883e",
                  minWidth: 16, marginTop: 1,
                }}>
                  {entry.auto ? "⚡" : "👤"}
                </span>
                <span style={{ color: "#8b949e" }}>
                  <strong style={{ color: "#e6edf3" }}>{entry.action.replace(/_/g, " ")}</strong>
                  {" — "}{entry.detail}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function IncidentView() {
  const [incidents, setIncidents] = useState<Incident[]>(DEMO_INCIDENTS);
  const [filter, setFilter] = useState<string>("all");

  useEffect(() => {
    const fetchIncidents = () => {
      fetch("/api/incidents")
        .then(r => r.json())
        .then(data => { if (data?.length) setIncidents(data); })
        .catch(() => {});
    };
    fetchIncidents();
    const timer = setInterval(fetchIncidents, 10_000);
    return () => clearInterval(timer);
  }, []);

  const stats = {
    total:    incidents.length,
    open:     incidents.filter(i => i.status === "open").length,
    critical: incidents.filter(i => i.severity === "critical").length,
    contained:incidents.filter(i => i.status === "contained").length,
  };

  const filtered = filter === "all" ? incidents
    : incidents.filter(i => i.status === filter || i.severity === filter);

  return (
    <div style={{ padding: 24, color: "#e6edf3" }}>
      <h2 style={{ margin: "0 0 20px", display: "flex", alignItems: "center", gap: 8 }}>
        <Zap size={20} color="#ff8800" />
        Réponse aux Incidents
      </h2>

      {/* Métriques */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 20 }}>
        {[
          { label: "Total", value: stats.total, color: "#7d8590" },
          { label: "Ouverts", value: stats.open, color: "#ff4444" },
          { label: "Critiques", value: stats.critical, color: "#ff8800" },
          { label: "Contenus", value: stats.contained, color: "#44bb44" },
        ].map(m => (
          <div key={m.label} style={{
            background: "#161b22", border: "1px solid #21262d",
            borderRadius: 8, padding: "12px 16px", textAlign: "center",
          }}>
            <div style={{ fontSize: 28, fontWeight: 700, color: m.color }}>{m.value}</div>
            <div style={{ fontSize: 11, color: "#7d8590", marginTop: 2 }}>{m.label}</div>
          </div>
        ))}
      </div>

      {/* Filtres */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {["all", "open", "investigating", "contained", "critical"].map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            style={{
              background: filter === f ? "#1f6feb" : "#21262d",
              color: filter === f ? "#fff" : "#7d8590",
              border: "1px solid #30363d",
              borderRadius: 6, padding: "4px 12px", fontSize: 12, cursor: "pointer",
            }}
          >
            {f === "all" ? "Tous" : STATUS_LABELS[f] ?? f}
          </button>
        ))}
      </div>

      {/* Liste incidents */}
      {filtered.length === 0 ? (
        <div style={{
          textAlign: "center", color: "#7d8590", padding: 40,
          border: "1px dashed #21262d", borderRadius: 8,
        }}>
          <CheckCircle size={32} color="#3fb950" style={{ marginBottom: 8 }} />
          <div>Aucun incident actif</div>
        </div>
      ) : (
        filtered.map(inc => <IncidentCard key={inc.id} incident={inc} />)
      )}
    </div>
  );
}
