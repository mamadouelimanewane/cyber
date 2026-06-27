import React, { useState, useRef, useEffect } from "react";
import { Brain, Send, Sparkles, Clock, ChevronRight } from "lucide-react";

interface Message {
  role: "user" | "assistant";
  content: string;
  timestamp: number;
  count?: number;
  recommendations?: string[];
  suggested_queries?: string[];
}

const EXAMPLE_QUERIES = [
  "Y a-t-il eu des tentatives de ransomware aujourd'hui ?",
  "Montre-moi les processus PowerShell suspects des dernières 24h",
  "Quel est l'agent le plus à risque en ce moment ?",
  "Y a-t-il eu du mouvement latéral cette semaine ?",
  "Quelqu'un a-t-il déclenché un honeytoken ?",
  "Combien d'alertes critiques depuis hier soir ?",
  "Y a-t-il des anomalies UEBA (comptes compromis) ?",
  "Montre les menaces en mémoire (fileless malware)",
];

export default function ThreatHunterChat() {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content:
        "Bonjour, je suis le **AI Threat Hunter** de Gravity Security.\n\nPostez vos questions en langage naturel pour investiguer les menaces. Je peux analyser les alertes, identifier des patterns d'attaque, et vous guider dans votre réponse à incidents.",
      timestamp: Date.now(),
      suggested_queries: EXAMPLE_QUERIES.slice(0, 4),
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const sendMessage = async (text: string) => {
    if (!text.trim() || loading) return;
    const userMsg: Message = { role: "user", content: text, timestamp: Date.now() };
    setMessages((m) => [...m, userMsg]);
    setInput("");
    setLoading(true);

    try {
      const res = await fetch("/api/ai-hunter/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: text }),
      });

      if (res.ok) {
        const data = await res.json();
        setMessages((m) => [
          ...m,
          {
            role: "assistant",
            content: data.text || "Aucun résultat trouvé.",
            timestamp: Date.now(),
            count: data.count,
            recommendations: data.recommendations,
            suggested_queries: data.suggested_queries,
          },
        ]);
      } else {
        throw new Error("API non disponible");
      }
    } catch {
      // Mode démo — réponse simulée
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content: generateDemoResponse(text),
          timestamp: Date.now(),
          recommendations: getDemoRecommendations(text),
          suggested_queries: EXAMPLE_QUERIES.slice(0, 3),
        },
      ]);
    }
    setLoading(false);
    inputRef.current?.focus();
  };

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-800 flex flex-col h-[70vh]">
      {/* Header */}
      <div className="p-4 border-b border-gray-800 flex items-center gap-3">
        <div className="w-8 h-8 rounded-full bg-purple-500/20 border border-purple-500/40 flex items-center justify-center">
          <Brain className="w-4 h-4 text-purple-400" />
        </div>
        <div>
          <h2 className="text-sm font-semibold text-white">AI Threat Hunter</h2>
          <p className="text-xs text-gray-500">Investigation en langage naturel</p>
        </div>
        <span className="ml-auto flex items-center gap-1 text-xs text-purple-400">
          <Sparkles className="w-3 h-3" /> Gravity AI
        </span>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((msg, idx) => (
          <div key={idx} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
            <div className={`max-w-[85%] ${msg.role === "user" ? "order-2" : ""}`}>
              {msg.role === "assistant" && (
                <div className="w-6 h-6 rounded-full bg-purple-500/30 flex items-center justify-center mb-1">
                  <Brain className="w-3 h-3 text-purple-400" />
                </div>
              )}
              <div
                className={`rounded-xl px-4 py-3 text-sm ${
                  msg.role === "user"
                    ? "bg-emerald-600/20 border border-emerald-500/30 text-emerald-100"
                    : "bg-gray-800 border border-gray-700 text-gray-200"
                }`}
              >
                <MessageContent content={msg.content} />
              </div>

              {/* Recommandations */}
              {msg.recommendations && msg.recommendations.length > 0 && (
                <div className="mt-2 space-y-1">
                  {msg.recommendations.map((rec, i) => (
                    <div key={i} className="text-xs bg-orange-500/10 border border-orange-500/20 text-orange-300 rounded-lg px-3 py-1.5">
                      {rec}
                    </div>
                  ))}
                </div>
              )}

              {/* Suggestions */}
              {msg.suggested_queries && msg.suggested_queries.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {msg.suggested_queries.map((q, i) => (
                    <button
                      key={i}
                      onClick={() => sendMessage(q)}
                      className="text-xs bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-400 hover:text-gray-200 rounded-lg px-2 py-1 transition-colors flex items-center gap-1"
                    >
                      <ChevronRight className="w-2.5 h-2.5" />
                      {q}
                    </button>
                  ))}
                </div>
              )}

              <div className="text-xs text-gray-600 mt-1 flex items-center gap-1">
                <Clock className="w-2.5 h-2.5" />
                {new Date(msg.timestamp).toLocaleTimeString("fr-FR")}
              </div>
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex justify-start">
            <div className="bg-gray-800 border border-gray-700 rounded-xl px-4 py-3">
              <div className="flex gap-1">
                {[0, 1, 2].map((i) => (
                  <div
                    key={i}
                    className="w-2 h-2 bg-purple-400 rounded-full animate-bounce"
                    style={{ animationDelay: `${i * 0.15}s` }}
                  />
                ))}
              </div>
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="p-4 border-t border-gray-800">
        <div className="flex gap-2">
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && sendMessage(input)}
            placeholder="Posez une question sur les menaces..."
            className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500 transition-colors"
          />
          <button
            onClick={() => sendMessage(input)}
            disabled={!input.trim() || loading}
            className="bg-purple-600 hover:bg-purple-500 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg px-4 py-2.5 transition-colors"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

function MessageContent({ content }: { content: string }) {
  const parts = content.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return (
    <span>
      {parts.map((part, i) => {
        if (part.startsWith("**") && part.endsWith("**"))
          return <strong key={i} className="font-semibold text-white">{part.slice(2, -2)}</strong>;
        if (part.startsWith("`") && part.endsWith("`"))
          return <code key={i} className="bg-gray-700 px-1 rounded text-emerald-300 text-xs">{part.slice(1, -1)}</code>;
        return part.split("\n").map((line, j) => (
          <React.Fragment key={j}>{line}{j < part.split("\n").length - 1 && <br />}</React.Fragment>
        ));
      })}
    </span>
  );
}

function generateDemoResponse(question: string): string {
  const q = question.toLowerCase();
  if (q.includes("ransomware")) return "**0 alertes de ransomware** détectées dans les dernières 24h.\n\nLa surveillance VSS, bcdedit et les suppressions de sauvegardes est active. Aucune activité suspecte.";
  if (q.includes("powershell")) return "**3 processus PowerShell suspects** détectés :\n\n- `powershell.exe` lancé par `winword.exe` — score 92%\n- Commande encodée base64 détectée\n- Téléchargement via WebClient bloqué\n\n→ Deux machines impliquées : PC-RH-02, PC-HP-001";
  if (q.includes("honeytoken") || q.includes("piège")) return "**1 honeytoken déclenché** — `passwords_backup.txt` accédé il y a 12 minutes.\n\nForensics collectés :\n- Processus: `explorer.exe` → `cmd.exe`\n- Utilisateur: HR_User_03\n- Connexions actives vers 185.220.101.47\n\n⚠ Incident confirmé — activer le plan de réponse";
  if (q.includes("latéral") || q.includes("lateral")) return "**2 tentatives de mouvement latéral** détectées cette semaine.\n\n- SMB depuis PC-HP-001 vers SRV-AD-01 (bloqué par NAC)\n- WMI remote execution tentée (bloquée)\n\nLe NAC Chaos Engine a bloqué automatiquement les deux tentatives.";
  if (q.includes("risque")) return "L'agent le plus à risque est **PC-RH-02** (192.168.1.18) avec 7 alertes en 24h.\n\nProfil :\n- 3 alertes critiques\n- PowerShell encodé détecté 2×\n- Connexion vers IP étrangère bloquée\n\n→ Isolation recommandée en attente de forensics.";
  if (q.includes("mémoire") || q.includes("fileless") || q.includes("ram")) return "**1 menace mémoire (fileless)** détectée sur PC-DEV-03.\n\nDétails :\n- Région mémoire RWX dans `explorer.exe`\n- Shellcode prolog x64 identifié @ 0x7FF4A200\n- Technique MITRE : T1055 — Process Injection\n\n→ Forensics RAM recommandée — `explorer.exe` potentiellement compromis.";
  return "**Recherche en cours**...\n\nConnectez le serveur Gravity pour des résultats en temps réel.\n\nEn mode démo, les données simulées montrent un réseau protégé avec surveillance active.";
}

function getDemoRecommendations(question: string): string[] {
  const q = question.toLowerCase();
  if (q.includes("honeytoken")) return ["🚨 Incident confirmé — Activer le plan de réponse immédiatement", "🔍 Collecter forensics réseau — capturer trafic de PC-RH-02"];
  if (q.includes("mémoire") || q.includes("ram")) return ["💾 Dump mémoire RAM recommandé sur PC-DEV-03", "🔒 Isoler la machine du réseau en attendant l'analyse"];
  if (q.includes("powershell")) return ["⚙️ Activer PowerShell Constrained Language Mode", "📋 Activer Script Block Logging sur tous les endpoints"];
  return [];
}
