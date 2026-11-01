import { useEffect, useRef, type KeyboardEvent } from "react";
import { ArrowUp } from "lucide-react";

export function Composer({ value, onChange, onSend, disabled, placeholder, autoFocus }: {
  value: string; onChange: (v: string) => void; onSend: () => void;
  disabled?: boolean; placeholder: string; autoFocus?: boolean;
}) {
  const box = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, 180)}px`;
  }, [value]);

  useEffect(() => { if (autoFocus) box.current?.focus(); }, [autoFocus]);

  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      if (value.trim() && !disabled) onSend();
    }
  };

  return (
    <div className="flex items-end gap-2 rounded-2xl border border-line bg-surface p-2 pl-4 shadow-sm transition-colors focus-within:border-accent">
      <textarea
        ref={box} rows={1} value={value} placeholder={placeholder} aria-label="Message Sentinel"
        onChange={(e) => onChange(e.target.value)} onKeyDown={onKey}
        className="max-h-44 min-h-9 flex-1 resize-none bg-transparent py-1.5 text-[15px] leading-6 text-ink outline-none placeholder:text-faint"
      />
      <button
        type="button" aria-label="Send" disabled={disabled || !value.trim()} onClick={onSend}
        className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-accent text-on-accent transition hover:opacity-90 disabled:bg-sunken disabled:text-faint"
      >
        <ArrowUp size={18} strokeWidth={2.5} />
      </button>
    </div>
  );
}
