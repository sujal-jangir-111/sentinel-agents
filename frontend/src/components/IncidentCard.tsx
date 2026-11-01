import { useState, type ReactNode } from "react";
import { AlertTriangle, CheckCircle2, ChevronDown, Download, ExternalLink, GitPullRequest, Loader2, ShieldCheck, XCircle } from "lucide-react";
import { Markdown } from "./Markdown";
import type { Cause, Fix, Incident, Security, Service } from "../types";

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h3 className="mb-1 text-[13px] font-medium text-faint">{title}</h3>
      {children}
    </section>
  );
}

function Disclosure({ label, open: startOpen = false, children }: { label: string; open?: boolean; children: ReactNode }) {
  const [open, setOpen] = useState(startOpen);
  return (
    <div>
      <button type="button" onClick={() => setOpen(!open)} aria-expanded={open}
        className="flex items-center gap-1 text-sm font-medium text-accent hover:opacity-80">
        {label}
        <ChevronDown size={15} className={`transition-transform ${open ? "rotate-180" : ""}`} />
      </button>
      {open && <div className="mt-2">{children}</div>}
    </div>
  );
}

function DiffView({ diff }: { diff: string }) {
  return (
    <pre className="max-h-96 overflow-auto rounded-xl bg-sunken p-3 font-mono text-xs leading-5">
      {diff.split("\n").map((line, i) => {
        const tone = line.startsWith("+++") || line.startsWith("---") ? "text-faint"
          : line.startsWith("+") ? "bg-good-soft text-good"
          : line.startsWith("-") ? "bg-bad-soft text-bad"
          : line.startsWith("@@") ? "text-accent" : "text-soft";
        return <div key={i} className={tone}>{line || " "}</div>;
      })}
    </pre>
  );
}

function ServiceLine({ service }: { service: Service }) {
  if (service.status === "failing") {
    return <p className="text-sm text-soft">Your service confirms it: <code className="font-mono text-[13px]">{service.endpoint}</code> returned error {service.code} on {service.failing} of {service.total} test requests.</p>;
  }
  return <p className="text-sm text-soft">{service.status === "healthy" ? "Your live service responded normally, so I worked from your description." : "I couldn't reach your live service, so I worked from your description."}</p>;
}

function CauseSection({ cause, service }: { cause: Cause; service: Service | null }) {
  return (
    <Section title="What went wrong">
      <p className="text-[15px] leading-relaxed text-ink">{cause.summary}</p>
      <p className="mt-1.5 text-[13px] text-faint">
        <code className="font-mono">{cause.file}</code>
        {cause.commit && <> · <a href={cause.commit.url} target="_blank" rel="noreferrer" className="underline underline-offset-2 hover:text-soft">{cause.commit.sha}</a> {cause.commit.title}</>}
        {!cause.certain && " · best match from your description"}
      </p>
      {service && <div className="mt-2"><ServiceLine service={service} /></div>}
    </Section>
  );
}

function FixSection({ fix }: { fix: Fix }) {
  const upgrades = Object.entries(fix.upgrades);
  return (
    <Section title="The fix">
      {fix.explanation && <p className="mb-2 text-[15px] leading-relaxed text-ink">{fix.explanation}</p>}
      {upgrades.length > 0 && <p className="mb-2 text-sm text-soft">Also upgrades {upgrades.map(([name, version]) => `${name} to ${version}`).join(", ")}.</p>}
      <p className="flex items-center gap-1.5 text-sm text-good">
        <ShieldCheck size={15} /> Passed the security check{fix.attempts > 1 ? ` on attempt ${fix.attempts}` : ""}
      </p>
      <p className="mb-2 mt-0.5 text-[13px] text-faint">I haven't run this code, so test it before you merge.</p>
      {fix.diff && <Disclosure label="See the code change"><DiffView diff={fix.diff} /></Disclosure>}
    </Section>
  );
}

function SecuritySection({ security, open }: { security: Security; open: boolean }) {
  const count = security.reachable + security.unverified + security.code;
  const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
  const dependencies = security.dependencies === 1 ? "1 pinned dependency" : `${security.dependencies} pinned dependencies`;
  const coverage = security.files ? `Checked ${plural(security.files, "file")} and ${dependencies}.` : `Checked ${dependencies}. I can't read this language's source code yet.`;
  if (!security.files && !security.dependencies) {
    return <p className="flex items-center gap-1.5 text-sm text-warn"><AlertTriangle size={15} className="shrink-0" /> I found no Python code or pinned dependencies to check, so I can't say whether this repository is safe.</p>;
  }
  if (!count) {
    return (
      <p className="flex items-start gap-1.5 text-sm text-soft">
        <CheckCircle2 size={15} className="mt-0.5 shrink-0 text-good" />
        <span>No security problems found. {coverage}{security.known ? ` ${security.known} known ${security.known === 1 ? "issue is" : "issues are"} in packages this code doesn't use.` : ""}</span>
      </p>
    );
  }
  return (
    <Disclosure label={`${count} security ${count === 1 ? "problem" : "problems"} found. ${coverage}`} open={open}>
      {security.unverified > 0 && <p className="mb-2 text-[13px] text-soft">These are known issues in your dependencies. I can only trace imports in Python, so I can't tell whether your code actually uses them.</p>}
      <ul className="space-y-2">
        {security.items.map((item, i) => (
          <li key={i} className="rounded-xl bg-sunken px-3 py-2">
            <p className="text-sm font-medium text-ink">{item.title}</p>
            <p className="text-[13px] text-soft">{item.advice}</p>
            <p className="mt-0.5 font-mono text-xs text-faint">{item.severity.toLowerCase()} · {item.where}</p>
          </li>
        ))}
        {security.more > 0 && <li className="text-[13px] text-faint">and {security.more} more</li>}
      </ul>
    </Disclosure>
  );
}

function Decision({ incident, onDecide }: { incident: Incident; onDecide: (a: "approve" | "reject") => Promise<string | null> }) {
  const [busy, setBusy] = useState<"approve" | "reject" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const act = async (action: "approve" | "reject") => {
    setBusy(action);
    const problem = await onDecide(action);
    if (problem) { setError(problem); setBusy(null); }
  };
  return (
    <div className="rounded-xl bg-warn-soft p-3.5">
      <p className="text-sm font-medium text-ink">Should I open a pull request with this fix?</p>
      <p className="mt-0.5 text-[13px] text-soft">It goes to a new branch on <code className="font-mono">{incident.repo}</code> for you to review. Nothing is merged.</p>
      <div className="mt-3 flex flex-wrap gap-2">
        <button type="button" disabled={!!busy} onClick={() => act("approve")}
          className="flex items-center gap-1.5 rounded-lg bg-accent px-3.5 py-2 text-sm font-medium text-on-accent transition hover:opacity-90 disabled:opacity-60">
          {busy === "approve" ? <Loader2 size={15} className="animate-spin" /> : <GitPullRequest size={15} />} Approve
        </button>
        <button type="button" disabled={!!busy} onClick={() => act("reject")}
          className="rounded-lg border border-line bg-surface px-3.5 py-2 text-sm text-soft transition-colors hover:text-ink disabled:opacity-60">
          Reject
        </button>
      </div>
      {error && <p role="alert" className="mt-2 text-[13px] text-bad">{error}</p>}
    </div>
  );
}

function Downloads({ incident }: { incident: Incident }) {
  return (
    <div className="rounded-xl bg-sunken p-3.5">
      <p className="text-sm font-medium text-ink">Your fix is ready</p>
      <p className="mt-0.5 text-[13px] text-soft">
        Sentinel can only read <code className="font-mono">{incident.repo}</code>, so it can't open a pull request there. Download the fixed {incident.fix!.files.length > 1 ? "files" : "file"} and replace yours.
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        {incident.fix!.files.map((name, i) => (
          <a key={name} href={`/api/incidents/${incident.id}/files/${i}`} download
            className="flex items-center gap-1.5 rounded-lg bg-accent px-3.5 py-2 text-sm font-medium text-on-accent transition hover:opacity-90">
            <Download size={15} /> {name.split("/").pop()}
          </a>
        ))}
      </div>
    </div>
  );
}

function Banner({ tone, icon, children }: { tone: "good" | "bad" | "muted"; icon: ReactNode; children: ReactNode }) {
  const styles = { good: "bg-good-soft", bad: "bg-bad-soft", muted: "bg-sunken" }[tone];
  return <div className={`flex gap-2.5 rounded-xl p-3.5 ${styles}`}><span className="mt-0.5 shrink-0">{icon}</span><div className="min-w-0 flex-1 text-sm text-ink">{children}</div></div>;
}

function Running({ line, publishing }: { line: string; publishing: boolean }) {
  return (
    <div className="flex items-start gap-2.5">
      <Loader2 size={16} className="mt-0.5 shrink-0 animate-spin text-accent" />
      <div className="min-w-0">
        <p className="text-sm font-medium text-ink">{publishing ? "Opening your pull request" : "Investigating"}</p>
        <p className="text-[13px] text-faint" aria-live="polite">{line}</p>
      </div>
    </div>
  );
}

function Outcome({ incident }: { incident: Incident }) {
  const outcome = incident.outcome;
  if (incident.phase === "failed") {
    return (
      <Banner tone="bad" icon={<AlertTriangle size={16} className="text-bad" />}>
        <Markdown text={incident.failure?.message || "The pull request is open, but the service is still failing."} />
        {incident.failure?.hint && <div className="mt-1 text-soft"><Markdown text={incident.failure.hint} /></div>}
        {outcome?.kind === "pr" && <a href={outcome.pr_url} target="_blank" rel="noreferrer" className="mt-1 inline-flex items-center gap-1 text-accent underline underline-offset-2">View the pull request <ExternalLink size={13} /></a>}
      </Banner>
    );
  }
  if (incident.phase === "cancelled") {
    return <Banner tone="muted" icon={<XCircle size={16} className="text-faint" />}>{incident.expired ? "This fix expired after 30 minutes without a decision. Nothing was changed." : "Rejected. Nothing was changed."}</Banner>;
  }
  if (outcome?.kind === "no_bug") {
    return (
      <Banner tone="muted" icon={<CheckCircle2 size={16} className="text-soft" />}>
        <p className="font-medium">I didn't find this problem in the code, so I'm not proposing a change</p>
        <p className="text-soft">I read <code className="font-mono text-[13px]">{outcome.file}</code>. {outcome.why}</p>
        <p className="mt-1 text-soft">If it still happens, paste the exact error message or a link to where you see it.</p>
      </Banner>
    );
  }
  if (outcome?.kind === "pr") {
    return (
      <Banner tone="good" icon={<CheckCircle2 size={16} className="text-good" />}>
        <p className="font-medium">Pull request opened</p>
        <p className="text-soft">{outcome.verified ? "I re-tested your service and it has recovered." : "Merge it and deploy to fix your service."}</p>
        <a href={outcome.pr_url} target="_blank" rel="noreferrer" className="mt-2 inline-flex items-center gap-1.5 rounded-lg bg-accent px-3.5 py-2 font-medium text-on-accent transition hover:opacity-90">
          Review on GitHub <ExternalLink size={14} />
        </a>
      </Banner>
    );
  }
  return null;
}

/** One case, in the conversation. It changes in place as the case moves on, and the decision happens right here. */
export function IncidentCard({ incident, line, onDecide }: {
  incident: Incident; line: string; onDecide: (a: "approve" | "reject") => Promise<string | null>;
}) {
  const { phase, cause, service, security, fix, outcome, mode } = incident;
  if (phase === "running") {
    return <div className="rise rounded-2xl border border-line bg-surface p-4"><Running line={line} publishing={false} /></div>;
  }
  const audit = mode === "security_audit";
  return (
    <div className="rise space-y-4 rounded-2xl border border-line bg-surface p-4 sm:p-5">
      {audit && phase === "done" && (
        <Section title="Security check">
          <p className="text-[15px] leading-relaxed text-ink">Finished checking <code className="font-mono text-[13px]">{incident.repo}</code>.</p>
        </Section>
      )}
      {cause && <CauseSection cause={cause} service={service} />}
      {fix?.approved && <FixSection fix={fix} />}
      {fix && !fix.approved && fix.reasons.length > 0 && (
        <Section title="Why the drafts were rejected">
          <ul className="list-disc space-y-1 pl-5 text-sm text-soft">{fix.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
        </Section>
      )}
      {security && <SecuritySection security={security} open={audit} />}
      {phase === "needs_approval" && <Decision incident={incident} onDecide={onDecide} />}
      {phase === "publishing" && <Running line={line} publishing />}
      {phase === "done" && outcome?.kind === "files" && fix && <Downloads incident={incident} />}
      <Outcome incident={incident} />
    </div>
  );
}
