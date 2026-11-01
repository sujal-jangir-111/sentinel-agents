// What the backend sends (web/views.py, web/console.py).

export type Phase = "running" | "needs_approval" | "publishing" | "done" | "failed" | "cancelled";

export interface Cause {
  summary: string;
  file: string;
  certain: boolean;
  commit: { sha: string; url: string; title: string; author: string } | null;
}

export type Service =
  | { status: "failing"; endpoint: string; code: number; failing: number; total: number }
  | { status: "healthy" | "unreachable" };

export interface SecurityItem { severity: string; title: string; where: string; advice: string }

export interface Security { known: number; reachable: number; unverified: number; code: number; items: SecurityItem[]; more: number; files: number; dependencies: number }

export interface Fix {
  approved: boolean;
  attempts: number;
  explanation: string;
  file: string;
  reasons: string[];
  diff: string;
  files: string[];
  upgrades: Record<string, string>;
  open_issues?: number;
}

export type Outcome =
  | { kind: "pr"; pr_url: string; verified: boolean | null }
  | { kind: "files" }
  | { kind: "audit" }
  | { kind: "no_bug"; file: string; why: string }
  | { kind?: undefined; pr_url?: string };

export interface Incident {
  id: string;
  phase: Phase;
  mode: string;
  repo: string;
  branch: string;
  service_url: string;
  cause: Cause | null;
  service: Service | null;
  security: Security | null;
  fix: Fix | null;
  outcome: Outcome | null;
  failure?: { message: string; hint: string };
  expired?: boolean;
}

export type ChatItem =
  | { id: string; kind: "user" | "assistant"; text: string; ts: number }
  | { id: string; kind: "incident"; incident: Incident; ts: number };

export interface ActivityEvent { agent: string; status: "working" | "done" | "failed"; text: string; ts: number }
