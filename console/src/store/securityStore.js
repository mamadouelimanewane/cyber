import { create } from "zustand";
export const useSecurityStore = create((set) => ({
    alerts: [],
    agents: [],
    stats: {},
    addAlert: (alert) => set((state) => ({
        alerts: [alert, ...state.alerts].slice(0, 500), // max 500 en mémoire
    })),
    setAgents: (agents) => set({ agents }),
    setStats: (stats) => set((state) => ({ stats: { ...state.stats, ...stats } })),
    clearAlerts: () => set({ alerts: [] }),
}));
