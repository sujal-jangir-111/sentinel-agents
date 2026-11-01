import { Activity, Compass, Search, ShieldCheck, Wrench, type LucideIcon } from "lucide-react";
import type { ActivityEvent, Incident } from "./types";

export type AgentStatus = "waiting" | "working" | "done" | "failed" | "skipped";

export interface AgentMeta { id: string; name: string; job: string; icon: LucideIcon }

// Friendly names for the five agents (Agent_1 ... Agent_5 in the code).
export const AGENTS: AgentMeta[] = [
  { id: "Agent_1", name: "Manager", job: "Coordinates the team", icon: Compass },
  { id: "Agent_2", name: "Health Checker", job: "Tests your live service", icon: Activity },
  { id: "Agent_3", name: "Detective", job: "Finds the cause", icon: Search },
  { id: "Agent_4", name: "Security Inspector", job: "Finds risks and tests the fix", icon: ShieldCheck },
  { id: "Agent_5", name: "Fixer", job: "Writes the fix", icon: Wrench },
];

export interface AgentState extends AgentMeta { status: AgentStatus; latest: string; log: ActivityEvent[] }

const skipped = (id: string, incident: Incident | null) => {
  if (!incident) return false;
  if (id === "Agent_2") return !incident.service_url;
  return id === "Agent_5" && incident.mode === "security_audit";
};

/** Folds the live event stream into each agent's current status. */
export function agentStates(activity: ActivityEvent[], incident: Incident | null): AgentState[] {
  const live = incident?.phase === "running" || incident?.phase === "publishing";
  return AGENTS.map((meta) => {
    const log = activity.filter((e) => e.agent === meta.id);
    const last = log[log.length - 1];
    let status: AgentStatus = last ? (last.status === "working" ? "working" : last.status) : "waiting";
    if (status === "working" && !live) status = "done";
    if (status === "waiting" && skipped(meta.id, incident)) status = "skipped";
    return { ...meta, status, log, latest: last?.text ?? "" };
  });
}

/** The newest thing anyone is doing, for the short line on the chat card. */
export function latestActivity(activity: ActivityEvent[]): string {
  const last = activity[activity.length - 1];
  if (!last) return "Getting the team together";
  return `${AGENTS.find((a) => a.id === last.agent)?.name ?? last.agent}: ${last.text}`;
}
