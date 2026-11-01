import { Eye, MessageSquareText, ThumbsUp } from "lucide-react";
import { Composer } from "./Composer";
import { Logo } from "./Logo";

const EXAMPLES = [
  { label: "Fix a bug", text: "My checkout page crashes after login. https://github.com/" },
  { label: "Check security", text: "Run a security check on https://github.com/" },
];

const STEPS = [
  { icon: MessageSquareText, title: "Tell it the problem", text: "Paste your GitHub link and describe what's wrong." },
  { icon: Eye, title: "Watch the agents", text: "See each one work, live, as it finds the cause." },
  { icon: ThumbsUp, title: "You decide", text: "Review the fix. Nothing changes without your OK." },
];

export function Home({ value, onChange, onSend, disabled }: {
  value: string; onChange: (v: string) => void; onSend: () => void; disabled: boolean;
}) {
  return (
    <div className="flex min-h-full flex-col items-center justify-center px-5 py-10">
      <div className="rise w-full max-w-2xl">
        <div className="mb-8 text-center">
          <Logo className="mx-auto mb-5 h-11 w-11" />
          <h1 className="text-3xl font-semibold tracking-tight text-ink sm:text-4xl">What's broken?</h1>
          <p className="mx-auto mt-3 max-w-md text-[15px] leading-relaxed text-soft">
            Share your GitHub link and describe the problem. A team of AI agents will find the cause and write a fix.
          </p>
        </div>

        <Composer value={value} onChange={onChange} onSend={onSend} disabled={disabled} autoFocus
          placeholder="Describe the problem and paste your GitHub link" />

        <div className="mt-3 flex flex-wrap justify-center gap-2">
          {EXAMPLES.map((e) => (
            <button key={e.label} type="button" onClick={() => onChange(e.text)}
              className="rounded-full border border-line bg-surface px-3.5 py-1.5 text-sm text-soft transition-colors hover:border-accent hover:text-ink">
              {e.label}
            </button>
          ))}
        </div>

        <ol className="mt-12 grid gap-6 sm:grid-cols-3">
          {STEPS.map(({ icon: Icon, title, text }) => (
            <li key={title} className="text-center">
              <span className="mx-auto mb-2 flex h-9 w-9 items-center justify-center rounded-full bg-sunken text-soft">
                <Icon size={17} />
              </span>
              <p className="text-sm font-medium text-ink">{title}</p>
              <p className="mt-1 text-[13px] leading-snug text-faint">{text}</p>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}
