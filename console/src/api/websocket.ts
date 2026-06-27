const WS_URL = import.meta.env.VITE_WS_URL || "ws://localhost:8000/ws";

interface WSOptions {
  onMessage: (msg: any) => void;
  onOpen?: () => void;
  onClose?: () => void;
}

export function connectWebSocket(options: WSOptions): WebSocket {
  const ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    console.log("[Gravity WS] Connecté");
    options.onOpen?.();
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      options.onMessage(msg);
    } catch (e) {
      console.error("[Gravity WS] Erreur parsing:", e);
    }
  };

  ws.onclose = () => {
    console.log("[Gravity WS] Déconnecté");
    options.onClose?.();
  };

  ws.onerror = (err) => {
    console.error("[Gravity WS] Erreur:", err);
  };

  return ws;
}

export async function apiFetch<T>(endpoint: string): Promise<T> {
  const base = import.meta.env.VITE_API_URL || "http://localhost:8000";
  const res = await fetch(`${base}${endpoint}`);
  if (!res.ok) throw new Error(`API ${endpoint}: ${res.status}`);
  return res.json();
}
