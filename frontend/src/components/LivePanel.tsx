import { useEffect, useState } from "react";
import { Check, ChevronDown, Minus, X } from "lucide-react";
import { agentStates, latestActivity, type AgentState, type AgentStatus } from "../agents";
import type { ActivityEvent, Incident } from "../types";

const STATUS_LABEL: Record<AgentStatus, string> = {
  waiting: "Waiting", working: "Working", done: "Done", failed: "Stopped", skipped: "Not needed",
};

function headline(incident: Incident | null) {
  switch (incident?.phase) {
    case "running": return { text: "Agents are working", tone: "text-accent" };
    case "publishing": return { text: "Publishing your fix", tone: "text-accent" };
    case "needs_approval": return { text: "Waiting for you", tone: "text-warn" };
    case "done": return { text: "Finished", tone: "text-good" };
    case "failed": return { text: "Stopped", tone: "text-bad" };
    case "cancelled": return { text: "Cancelled", tone: "text-faint" };
    default: return { text: "Ready", tone: "text-faint" };
  }
}

function useElapsed(activity: ActivityEvent[], live: boolean) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!live) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [live]);
  if (!activity.length) return "";
  const end = live ? now : activity[activity.length - 1].ts * 1000;
  const seconds = Math.max(0, Math.round((end - activity[0].ts * 1000) / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

function Marker({ agent }: { agent: AgentState }) {
  const Icon = agent.icon;
  const base = "relative z-10 flex h-9 w-9 shrink-0 items-center justify-center rounded-full border transition-colors duration-300";
  switch (agent.status) {
    case "working": return <span className={`${base} breathe border-accent bg-accent text-on-accent`}><Icon size={17} /></span>;
    case "done": return <span className={`${base} border-good-soft bg-good-soft text-good`}><Check size={17} strokeWidth={2.5} /></span>;
    case "failed": return <span className={`${base} border-bad-soft bg-bad-soft text-bad`}><X size={17} strokeWidth={2.5} /></span>;
    case "skipped": return <span className={`${base} border-line bg-surface text-faint`}><Minus size={16} /></span>;
    default: return <span className={`${base} border-line bg-surface text-faint`}><Icon size={17} /></span>;
  }
}

function AgentRow({ agent, last }: { agent: AgentState; last: boolean }) {
  const [open, setOpen] = useState(false);
  const working = agent.status === "working";
  const history = agent.log.slice(0, -1);
  const expanded = open && history.length > 0;
  return (
    <li className="relative flex gap-3 pb-5 last:pb-0">
      {!last && <span aria-hidden="true" className="absolute top-9 bottom-0 left-[17.5px] w-px bg-line" />}
      <Marker agent={agent} />
      <div className="min-w-0 flex-1 pt-0.5">
        <div className="flex items-baseline justify-between gap-2">
          <p className={`text-sm font-medium ${agent.status === "waiting" || agent.status === "skipped" ? "text-soft" : "text-ink"}`}>{agent.name}</p>
          <p className={`shrink-0 text-xs ${working ? "text-accent" : "text-faint"}`}>{STATUS_LABEL[agent.status]}</p>
        </div>
        <p className={`mt-0.5 text-[13px] leading-snug ${working ? "text-ink" : "text-faint"}`}>{agent.latest || agent.job}</p>
        {history.length > 0 && (
          <button type="button" onClick={() => setOpen(!open)} aria-expanded={expanded}
            className="mt-1 flex items-center gap-1 text-xs text-faint hover:text-soft">
            {history.length} earlier {history.length === 1 ? "step" : "steps"}
            <ChevronDown size={12} className={`transition-transform ${expanded ? "rotate-180" : ""}`} />
          </button>
        )}
        {expanded && (
          <ul className="mt-1.5 space-y-1 border-l border-line pl-2.5">
            {history.map((e) => <li key={e.ts + e.text} className="text-xs leading-snug text-faint">{e.text}</li>)}
          </ul>
        )}
      </div>
    </li>
  );
}

/** Live view of the team: every line is a real event sent by that agent as it works. */
export function LivePanel({ activity, incident }: { activity: ActivityEvent[]; incident: Incident | null }) {
  const agents = agentStates(activity, incident);
  const live = incident?.phase === "running" || incident?.phase === "publishing";
  const elapsed = useElapsed(activity, live);
  const { text, tone } = headline(incident);
  const [expanded, setExpanded] = useState(false);

  return (
    <aside aria-label="Live agent activity" className="border-b border-line bg-surface lg:h-full lg:overflow-y-auto lg:border-b-0 lg:border-l">
      <button type="button" onClick={() => setExpanded(!expanded)} aria-expanded={expanded}
        className="flex w-full items-center gap-3 px-5 py-3 text-left lg:hidden">
        <span className={`text-sm font-medium ${tone}`}>{text}</span>
        <span className="min-w-0 flex-1 truncate text-xs text-faint">{latestActivity(activity)}</span>
        <ChevronDown size={16} className={`shrink-0 text-faint transition-transform ${expanded ? "rotate-180" : ""}`} />
      </button>
      <div className={`${expanded ? "block" : "hidden"} px-5 pt-1 pb-5 lg:block lg:pt-5`}>
        <div className="mb-5 hidden items-baseline justify-between lg:flex">
          <h2 className={`text-sm font-medium ${tone}`} aria-live="polite">{text}</h2>
          {elapsed && <span className="font-mono text-xs text-faint">{elapsed}</span>}
        </div>
        <ol>{agents.map((a, i) => <AgentRow key={a.id} agent={a} last={i === agents.length - 1} />)}</ol>
      </div>
    </aside>
  );
}
