// Typed client for the SecureHire API.
// The token lives in sessionStorage (cleared when the tab closes) and is sent
// as a Bearer header — including for the live event stream, which uses fetch
// streaming instead of EventSource so the token never appears in a URL.

const BASE = (import.meta.env.VITE_API_URL ?? "").replace(/\/$/, "");
const TOKEN_KEY = "securehire.token";

export type Step = {
  seq: number;
  kind: "run" | "llm" | "tool" | "security";
  tool: string | null;
  status: string;
  detail: Record<string, unknown>;
  created_at: string;
};

export type Run = {
  id: string;
  status: "queued" | "running" | "succeeded" | "failed";
  phase: string;
  step_count: number;
  attempts: number;
  target_role: string;
  error: string | null;
  created_at: string;
  finished_at: string | null;
  analysis_id: string | null;
};

export type RunDetail = Run & { steps: Step[] };

export type PlanDay = { day: number; focus: string; tasks: string[]; kind?: string | null };
export type Question = { skill: string; question: string; difficulty: string; why: string };

export type AnalysisSummary = {
  id: string;
  run_id: string;
  target_role: string;
  match_score: number;
  missing_skills: string[];
  security_flags: number;
  created_at: string;
};

export type Analysis = AnalysisSummary & {
  matched_skills: string[];
  prep_plan: PlanDay[];
  questions: Question[];
  summary: string;
};

export type AuditRow = {
  id: number;
  ts: string;
  event: string;
  tool: string | null;
  decision: string;
  reason: string | null;
  latency_ms: number | null;
  entry_hash: string;
};

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export const auth = {
  get token(): string | null {
    try {
      return sessionStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },
  set token(value: string | null) {
    try {
      if (value) sessionStorage.setItem(TOKEN_KEY, value);
      else sessionStorage.removeItem(TOKEN_KEY);
    } catch {
      /* storage unavailable: session lasts for this page only */
    }
  },
};

let onUnauthorized: () => void = () => {};
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

function headers(extra?: HeadersInit): Headers {
  const h = new Headers(extra);
  const t = auth.token;
  if (t) h.set("Authorization", `Bearer ${t}`);
  return h;
}

async function errorMessage(res: Response): Promise<string> {
  try {
    const body = await res.json();
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) {
      return body.detail
        .map((d: { loc?: unknown[]; msg?: string }) => `${(d.loc ?? []).slice(1).join(".")}: ${d.msg}`)
        .join("; ");
    }
  } catch {
    /* fall through */
  }
  return `Request failed (${res.status})`;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(BASE + path, { ...init, headers: headers(init.headers) });
  if (res.status === 401 && auth.token) {
    auth.token = null;
    onUnauthorized();
  }
  if (!res.ok) throw new ApiError(res.status, await errorMessage(res));
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  body: JSON.stringify(body),
  headers: { "Content-Type": "application/json" },
});

export const api = {
  async register(email: string, password: string) {
    const r = await request<{ access_token: string }>("/api/auth/register", json({ email, password }));
    auth.token = r.access_token;
  },
  async login(email: string, password: string) {
    const r = await request<{ access_token: string }>("/api/auth/login", json({ email, password }));
    auth.token = r.access_token;
  },
  me: () => request<{ id: number; created_at: string }>("/api/auth/me"),
  createRun: (form: FormData) => request<{ id: string }>("/api/runs", { method: "POST", body: form }),
  createSample: (scenario: "clean" | "injection", target_role: string) =>
    request<{ id: string }>("/api/runs/sample", json({ scenario, target_role })),
  samples: () => request<{ scenarios: Record<string, string>; job_description: string }>("/api/samples"),
  run: (id: string) => request<RunDetail>(`/api/runs/${encodeURIComponent(id)}`),
  runs: () => request<{ items: Run[]; next_cursor: string | null }>("/api/runs?limit=50"),
  runAudit: (id: string) => request<AuditRow[]>(`/api/runs/${encodeURIComponent(id)}/audit`),
  verifyAudit: () => request<{ ok: boolean; first_bad_row: number | null }>("/api/audit/verify"),
  analysis: (id: string) => request<Analysis>(`/api/analyses/${encodeURIComponent(id)}`),
  analyses: () => request<{ items: AnalysisSummary[]; next_cursor: string | null }>("/api/analyses?limit=50"),
  deleteAnalysis: (id: string) => request<void>(`/api/analyses/${encodeURIComponent(id)}`, { method: "DELETE" }),
  sampleUrl: (scenario: string) => `${BASE}/api/samples/${scenario}.pdf`,
};

/**
 * Follow a run's Server-Sent Events. Reconnects with Last-Event-ID until the
 * server sends `end` or the signal is aborted.
 */
export async function streamRunEvents(
  runId: string,
  onStep: (step: Step) => void,
  signal: AbortSignal,
): Promise<string | null> {
  let lastId = 0;
  for (let attempt = 0; attempt < 20 && !signal.aborted; attempt++) {
    try {
      const res = await fetch(`${BASE}/api/runs/${encodeURIComponent(runId)}/events`, {
        headers: headers(lastId ? { "Last-Event-ID": String(lastId) } : undefined),
        signal,
      });
      if (!res.ok || !res.body) throw new ApiError(res.status, await errorMessage(res));
      const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
      let buffer = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += value;
        let idx: number;
        while ((idx = buffer.indexOf("\n\n")) >= 0) {
          const raw = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 2);
          let event = "message";
          let data = "";
          for (const line of raw.split("\n")) {
            if (line.startsWith("event: ")) event = line.slice(7);
            else if (line.startsWith("data: ")) data += line.slice(6);
            else if (line.startsWith("id: ")) lastId = Number(line.slice(4)) || lastId;
          }
          if (event === "step" && data) onStep(JSON.parse(data) as Step);
          if (event === "end") return (JSON.parse(data) as { status: string }).status;
        }
      }
    } catch (err) {
      if (signal.aborted) return null;
      if (err instanceof ApiError && err.status < 500) throw err;
    }
    await new Promise((r) => setTimeout(r, Math.min(1000 * 2 ** attempt, 8000)));
  }
  return null;
}
