import { create } from "zustand";

export interface Alert {
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
  cmdline?: string;
}

export interface Agent {
  agent_id: string;
  ip: string;
  hostname?: string;
  online: boolean;
  os_info?: string;
  last_seen?: number;
  stats?: Record<string, any>;
}

interface SecurityStore {
  alerts: Alert[];
  agents: Agent[];
  stats: Record<string, any>;
  addAlert: (alert: Alert) => void;
  setAgents: (agents: Agent[]) => void;
  setStats: (stats: Record<string, any>) => void;
  clearAlerts: () => void;
}

export const useSecurityStore = create<SecurityStore>((set) => ({
  alerts: [],
  agents: [],
  stats: {},

  addAlert: (alert) =>
    set((state) => ({
      alerts: [alert, ...state.alerts].slice(0, 500), // max 500 en mémoire
    })),

  setAgents: (agents) => set({ agents }),

  setStats: (stats) =>
    set((state) => ({ stats: { ...state.stats, ...stats } })),

  clearAlerts: () => set({ alerts: [] }),
}));
