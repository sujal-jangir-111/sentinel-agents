import { useState, type FormEvent } from "react";
import { Logo } from "./Logo";

export function SignIn({ onLogin }: { onLogin: (password: string) => Promise<string | null> }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(await onLogin(password));
    setBusy(false);
  };

  return (
    <div className="flex h-full items-center justify-center px-5">
      <form onSubmit={submit} className="rise w-full max-w-sm text-center">
        <Logo className="mx-auto mb-5 h-11 w-11" />
        <h1 className="text-2xl font-semibold tracking-tight text-ink">Sign in to Sentinel</h1>
        <p className="mt-2 text-sm text-soft">Enter the access password to continue.</p>
        <input
          type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus
          aria-label="Password" placeholder="Password"
          className="mt-6 w-full rounded-xl border border-line bg-surface px-4 py-2.5 text-[15px] text-ink outline-none placeholder:text-faint focus:border-accent"
        />
        <button type="submit" disabled={busy || !password}
          className="mt-3 w-full rounded-xl bg-accent py-2.5 text-[15px] font-medium text-on-accent transition hover:opacity-90 disabled:bg-sunken disabled:text-faint">
          Continue
        </button>
        {error && <p role="alert" className="mt-3 text-sm text-bad">{error}</p>}
      </form>
    </div>
  );
}
