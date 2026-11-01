import { useCallback, useEffect, useRef, useState } from "react";
import type { ActivityEvent, ChatItem } from "./types";

export type Stage = "loading" | "signin" | "ready";

export interface Sentinel {
  stage: Stage;
  connected: boolean;
  agentsOnline: boolean;
  items: ChatItem[];
  activity: ActivityEvent[];
  typing: boolean;
  incidentId: string | null;
  send: (text: string) => void;
  decide: (incidentId: string, action: "approve" | "reject") => Promise<string | null>;
  reset: () => Promise<void>;
  login: (password: string) => Promise<string | null>;
}

const detail = async (resp: Response) => {
  const body = await resp.json().catch(() => ({}));
  return (body.detail as string) ?? `HTTP ${resp.status}`;
};

/** One WebSocket to the backend. The server owns the conversation, so a page refresh loses nothing. */
export function useSentinel(): Sentinel {
  const [stage, setStage] = useState<Stage>("loading");
  const [connected, setConnected] = useState(false);
  const [agentsOnline, setAgentsOnline] = useState(true);
  const [items, setItems] = useState<ChatItem[]>([]);
  const [activity, setActivity] = useState<ActivityEvent[]>([]);
  const [typing, setTyping] = useState(false);
  const [incidentId, setIncidentId] = useState<string | null>(null);
  const socket = useRef<WebSocket | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/session").then((r) => r.json()).then((s) => {
      if (!cancelled) setStage(s.auth_required && !s.signed_in ? "signin" : "ready");
    }).catch(() => { if (!cancelled) setStage("ready"); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (stage !== "ready") return;
    let closed = false;
    let retry: number | undefined;
    const connect = () => {
      const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
      socket.current = ws;
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        setTyping(false);
        if (!closed) retry = window.setTimeout(connect, 1500);
      };
      ws.onmessage = (e) => {
        const ev = JSON.parse(e.data);
        switch (ev.type) {
          case "hello":
            setItems(ev.items);
            setActivity(ev.activity);
            setAgentsOnline(ev.agents_online);
            setIncidentId(ev.incident_id);
            setTyping(ev.typing);
            break;
          case "item":
            setItems((all) => {
              const at = all.findIndex((i) => i.id === ev.item.id);
              return at < 0 ? [...all, ev.item] : all.map((i, n) => (n === at ? ev.item : i));
            });
            break;
          case "new_case":
            setIncidentId(ev.incident_id);
            setActivity([]);
            break;
          case "activity": setActivity((all) => [...all, ev.event]); break;
          case "typing": setTyping(ev.typing); break;
          case "status": setAgentsOnline(ev.agents_online); break;
        }
      };
    };
    connect();
    return () => { closed = true; window.clearTimeout(retry); socket.current?.close(); };
  }, [stage]);

  const send = useCallback((text: string) => {
    const ws = socket.current;
    if (ws?.readyState === WebSocket.OPEN && text.trim()) ws.send(JSON.stringify({ type: "user_message", text }));
  }, []);

  const decide = useCallback(async (id: string, action: "approve" | "reject") => {
    const resp = await fetch(`/api/incidents/${id}/decision`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action }),
    });
    return resp.ok ? null : detail(resp);
  }, []);

  const reset = useCallback(async () => { await fetch("/api/reset", { method: "POST" }); }, []);

  const login = useCallback(async (password: string) => {
    const resp = await fetch("/api/login", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password }),
    });
    if (!resp.ok) return detail(resp);
    setStage("ready");
    return null;
  }, []);

  return { stage, connected, agentsOnline, items, activity, typing, incidentId, send, decide, reset, login };
}
