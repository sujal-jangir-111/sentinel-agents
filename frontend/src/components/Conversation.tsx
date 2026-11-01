import { useEffect, useRef, type ReactNode } from "react";
import { IncidentCard } from "./IncidentCard";
import { Logo } from "./Logo";
import { Markdown } from "./Markdown";
import { latestActivity } from "../agents";
import type { ActivityEvent, ChatItem } from "../types";

function Assistant({ children }: { children: ReactNode }) {
  return (
    <div className="flex gap-3">
      <Logo className="mt-0.5 h-6 w-6 shrink-0" />
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}

export function Conversation({ items, typing, activity, incidentId, onDecide }: {
  items: ChatItem[]; typing: boolean; activity: ActivityEvent[]; incidentId: string | null;
  onDecide: (id: string, action: "approve" | "reject") => Promise<string | null>;
}) {
  const end = useRef<HTMLDivElement>(null);
  const size = items.length;
  const lastPhase = items.filter((i) => i.kind === "incident").at(-1);
  const phase = lastPhase?.kind === "incident" ? lastPhase.incident.phase : "";
  useEffect(() => { end.current?.scrollIntoView({ behavior: "smooth", block: "end" }); }, [size, typing, phase]);

  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 px-5 py-6">
      {items.map((item) => {
        if (item.kind === "incident") {
          return (
            <Assistant key={item.id}>
              <IncidentCard incident={item.incident} onDecide={(a) => onDecide(item.incident.id, a)}
                line={item.incident.id === incidentId ? latestActivity(activity) : ""} />
            </Assistant>
          );
        }
        if (item.kind === "user") {
          return (
            <div key={item.id} className="rise flex justify-end">
              <p className="max-w-[85%] whitespace-pre-wrap break-words rounded-2xl rounded-br-md bg-sunken px-4 py-2.5 text-[15px] leading-relaxed text-ink">{item.text}</p>
            </div>
          );
        }
        return <div key={item.id} className="rise"><Assistant><Markdown text={item.text} /></Assistant></div>;
      })}
      {typing && (
        <Assistant>
          <span className="flex h-6 items-center gap-1" aria-label="Sentinel is typing">
            <span className="typing-dot h-1.5 w-1.5 rounded-full bg-faint" />
            <span className="typing-dot h-1.5 w-1.5 rounded-full bg-faint" />
            <span className="typing-dot h-1.5 w-1.5 rounded-full bg-faint" />
          </span>
        </Assistant>
      )}
      <div ref={end} />
    </div>
  );
}
