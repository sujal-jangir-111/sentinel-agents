import { useState } from "react";
import { Plus, WifiOff } from "lucide-react";
import { useSentinel } from "./useSentinel";
import { Composer } from "./components/Composer";
import { Conversation } from "./components/Conversation";
import { Home } from "./components/Home";
import { LivePanel } from "./components/LivePanel";
import { Logo } from "./components/Logo";
import { SignIn } from "./components/SignIn";
import type { Incident } from "./types";

export default function App() {
  const s = useSentinel();
  const [draft, setDraft] = useState("");

  if (s.stage === "loading") return null;
  if (s.stage === "signin") return <SignIn onLogin={s.login} />;

  const send = () => {
    s.send(draft.trim());
    setDraft("");
  };
  const started = s.items.length > 0;
  const current = s.items.find((i) => i.kind === "incident" && i.id === s.incidentId);
  const incident: Incident | null = current?.kind === "incident" ? current.incident : null;
  const offline = !s.connected || !s.agentsOnline;

  return (
    <div className="flex h-full flex-col">
      <header className="flex h-14 shrink-0 items-center gap-2.5 border-b border-line px-5">
        <Logo />
        <span className="font-semibold tracking-tight text-ink">Sentinel</span>
        {started && (
          <button type="button" onClick={s.reset}
            className="ml-auto flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-sm text-soft transition-colors hover:bg-sunken hover:text-ink">
            <Plus size={16} /> New chat
          </button>
        )}
      </header>

      {offline && (
        <p role="status" className="flex items-center justify-center gap-2 bg-warn-soft px-5 py-2 text-sm text-warn">
          <WifiOff size={15} /> {s.connected ? "The agents are starting up. This can take a few minutes." : "Reconnecting…"}
        </p>
      )}

      {!started ? (
        <main className="min-h-0 flex-1 overflow-y-auto">
          <Home value={draft} onChange={setDraft} onSend={send} disabled={offline} />
        </main>
      ) : (
        <div className="flex min-h-0 flex-1 flex-col lg:grid lg:grid-cols-[minmax(0,1fr)_21.5rem]">
          {incident && <div className="lg:order-2 lg:min-h-0"><LivePanel activity={s.activity} incident={incident} /></div>}
          <main className={`flex min-h-0 flex-1 flex-col lg:order-1 ${incident ? "" : "lg:col-span-2"}`}>
            <div className="min-h-0 flex-1 overflow-y-auto">
              <Conversation items={s.items} typing={s.typing} activity={s.activity} incidentId={s.incidentId} onDecide={s.decide} />
            </div>
            <div className="mx-auto w-full max-w-3xl px-5 pb-4">
              <Composer value={draft} onChange={setDraft} onSend={send} disabled={offline} placeholder="Ask Sentinel" />
            </div>
          </main>
        </div>
      )}
    </div>
  );
}
