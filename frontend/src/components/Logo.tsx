export function Logo({ className = "h-6 w-6" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden="true">
      <path fill="var(--accent)" d="M16 2.5 5 6.6v8.2c0 6.9 4.5 12.3 11 14.7 6.5-2.4 11-7.8 11-14.7V6.6L16 2.5Z" />
      <path fill="none" stroke="var(--on-accent)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" d="m10.8 16 3.6 3.6 6.8-7.2" />
    </svg>
  );
}
