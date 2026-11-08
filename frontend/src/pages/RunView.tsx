import { useEffect, useMemo, useState } from "react";
import { Analysis, api, AuditRow, RunDetail, Step, streamRunEvents } from "../api";

type Tone = "ok" | "bad" | "warn" | "info" | "busy";

const TOOL_LABEL: Record<string, string> = {
  parse_resume: "Parse resume",
  extract_skills: "Extract skills",
  compare_to_jd: "Compare to job description",
  fetch_past_analyses: "Fetch past analyses",
  generate_prep_plan: "Generate prep plan",
  generate_questions: "Generate questions",
};

const fmtCounts = (c: unknown) =>
  Object.entries((c ?? {}) as Record<string, number>)
    .map(([k, v]) => `${k.toLowerCase()}${v > 1 ? ` ×${v}` : ""}`)
    .join(", ");

const list = (v: unknown) => (Array.isArray(v) ? v.join(", ") : "");

function describe(s: Step): { title: string; text?: string; tone: Tone } {
  const d = s.detail as Record<string, any>;
  const tool = s.tool ? TOOL_LABEL[s.tool] ?? s.tool : "";
  switch (`${s.kind}:${s.status}`) {
    case "run:queued": return { title: "Queued", text: "Waiting for a worker", tone: "info" };
    case "run:started": return { title: "Agent started", text: `LLM provider: ${d.provider}`, tone: "info" };
    case "run:resumed": return { title: "Resumed from checkpoint", text: `after step ${d.step}`, tone: "warn" };
    case "run:succeeded":
      return { title: "Finished", text: `${d.steps} steps · ${d.security_flags} security event(s)`, tone: "ok" };
    case "run:failed": return { title: "Run failed", text: String(d.error ?? ""), tone: "bad" };
    case "llm:thinking":
      return { title: `Step ${d.step}: model deciding`, text: `Tools offered: ${list(d.offered) || "none"}`, tone: "info" };
    case "llm:no_tool_call":
      return { title: "Model answered without a tool", text: `Still required: ${list(d.remaining)}`, tone: "warn" };
    case "llm:retrying":
    case "tool:retrying":
      return { title: `Retrying${tool ? ` ${tool}` : " model call"}`, text: `attempt ${d.attempt}: ${d.error}`, tone: "warn" };
    case "tool:running": return { title: `${tool}…`, tone: "busy" };
    case "tool:error": return { title: `${tool} failed`, text: String(d.error), tone: "bad" };
    case "tool:rejected": return { title: `Rejected ${s.tool} call`, text: `${d.code}: ${d.message}`, tone: "warn" };
    case "security:flagged":
      return {
        title: `Injection patterns found in ${d.source}`,
        text: `${list(d.categories)} · treated as data${d.action === "redact" ? " and redacted" : ""}`,
        tone: "warn",
      };
    case "security:blocked":
      return { title: `Blocked call to ${s.tool}`, text: `${d.code}: ${d.message}`, tone: "bad" };
    case "tool:ok": {
      const ms = typeof d.latency_ms === "number" ? ` · ${d.latency_ms} ms` : "";
      const text: Record<string, string> = {
        parse_resume: `${d.chars} chars · personal data removed: ${fmtCounts(d.pii_redacted) || "none"}`,
        extract_skills: `${d.skills} skills across ${list(d.categories)}`,
        compare_to_jd: `${d.match_score}% match · ${d.matched} matched, ${d.missing} missing`,
        fetch_past_analyses: `${d.previous} previous · recurring gaps: ${list(d.recurring_gaps) || "none"}`,
        generate_prep_plan: `${d.days}-day plan (${d.source})`,
        generate_questions: `${d.questions} questions (${d.source})`,
      };
      return { title: tool, text: (text[s.tool ?? ""] ?? "") + ms, tone: "ok" };
    }
    default: return { title: `${s.kind} ${s.status}`, tone: "info" };
  }
}

export default function RunView({ runId }: { runId: string }) {
  const [run, setRun] = useState<RunDetail | null>(null);
  const [steps, setSteps] = useState<Step[]>([]);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [audit, setAudit] = useState<AuditRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    const add = (s: Step) =>
      setSteps((prev) => (prev.some((p) => p.seq === s.seq) ? prev : [...prev, s].sort((a, b) => a.seq - b.seq)));
    (async () => {
      try {
        await streamRunEvents(runId, add, ctrl.signal);
        if (ctrl.signal.aborted) return;
        const detail = await api.run(runId);
        setRun(detail);
        if (detail.analysis_id) setAnalysis(await api.analysis(detail.analysis_id));
      } catch (err) {
        if (!ctrl.signal.aborted) setError(err instanceof Error ? err.message : "Could not load the run");
      }
    })();
    api.run(runId).then(setRun).catch(() => {});
    return () => ctrl.abort();
  }, [runId]);

  // Hide "running" rows once the matching result has arrived.
  const visible = useMemo(
    () => steps.filter((s, i) => !(s.kind === "tool" && s.status === "running" && i < steps.length - 1)),
    [steps],
  );
  const security = steps.filter((s) => s.kind === "security");
  const pii = steps.find((s) => s.tool === "parse_resume" && s.status === "ok")?.detail.pii_redacted;
  const finished = steps.find((s) => s.kind === "run" && (s.status === "succeeded" || s.status === "failed"));
  const status = finished?.status ?? (steps.some((s) => s.status === "started") ? "running" : run?.status ?? "queued");

  if (error) return <div className="alert error">{error}</div>;

  return (
    <div className="stack-lg">
      <div className="row between">
        <div>
          <h1>{run?.target_role || "Analysis"}</h1>
          <p className="muted small">Run {runId.slice(0, 8)} · {run ? new Date(run.created_at).toLocaleString() : ""}</p>
        </div>
        <span className={`pill ${status}`}>{status}</span>
      </div>

      <div className="grid-run">
        <section className="card">
          <h2>Agent timeline</h2>
          <ol className="timeline">
            {visible.map((s) => {
              const d = describe(s);
              return (
                <li key={s.seq} className={`t-${d.tone}`}>
                  <span className="dot" aria-hidden />
                  <div>
                    <div className="t-title">{d.title}</div>
                    {d.text && <div className="t-text">{d.text}</div>}
                  </div>
                </li>
              );
            })}
            {!finished && <li className="t-busy"><span className="dot" aria-hidden /><div className="t-title">Working…</div></li>}
          </ol>
        </section>

        <section className="card">
          <h2>Privacy &amp; security</h2>
          <dl className="facts">
            <dt>Personal data removed before the AI saw it</dt>
            <dd>{pii ? fmtCounts(pii) || "none found" : "—"}</dd>
            <dt>Injection attempts detected</dt>
            <dd>{security.filter((s) => s.status === "flagged").length}</dd>
            <dt>Tool calls blocked</dt>
            <dd className={security.some((s) => s.status === "blocked") ? "bad-text" : ""}>
              {security.filter((s) => s.status === "blocked").length}
            </dd>
            <dt>Uploaded files</dt>
            <dd>{finished ? "deleted" : "held until the run ends"}</dd>
          </dl>
          {security.some((s) => s.status === "blocked") && (
            <div className="alert warn">
              The model was manipulated by text inside the document and tried to call a tool it wasn't allowed to.
              The call was refused before it ran — nothing from another account was read.
            </div>
          )}
          <button className="link" onClick={() => (audit ? setAudit(null) : api.runAudit(runId).then(setAudit))}>
            {audit ? "Hide audit trail" : "Show audit trail"}
          </button>
          {audit && <AuditTable rows={audit} />}
        </section>
      </div>

      {run?.status === "failed" && <div className="alert error">This run failed: {run.error}</div>}
      {analysis && <Report a={analysis} />}
    </div>
  );
}

function AuditTable({ rows }: { rows: AuditRow[] }) {
  return (
    <div className="table-wrap">
      <table className="audit">
        <thead>
          <tr><th>Event</th><th>Tool</th><th>Decision</th><th>Detail</th><th>Hash</th></tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td>{r.event}</td>
              <td>{r.tool ?? ""}</td>
              <td><span className={`tag ${r.decision}`}>{r.decision}</span></td>
              <td>{r.reason ?? ""}{r.latency_ms != null ? ` (${r.latency_ms} ms)` : ""}</td>
              <td className="mono">{r.entry_hash.slice(0, 10)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="hint">Hash-chained and append-only. Users and runs appear only as keyed hashes.</p>
    </div>
  );
}

export function ScoreRing({ score }: { score: number }) {
  const tone = score >= 70 ? "var(--ok)" : score >= 40 ? "var(--warn)" : "var(--bad)";
  return (
    <div className="ring" style={{ background: `conic-gradient(${tone} ${score * 3.6}deg, var(--track) 0)` }}>
      <div><strong>{Math.round(score)}%</strong><span>match</span></div>
    </div>
  );
}

function Report({ a }: { a: Analysis }) {
  return (
    <div className="stack-lg">
      <section className="card report-head">
        <ScoreRing score={a.match_score} />
        <div className="stack">
          <p>{a.summary}</p>
          <div>
            <h4>Matched</h4>
            <div className="chips">{a.matched_skills.map((s) => <span key={s} className="chip ok">{s}</span>)}</div>
          </div>
          <div>
            <h4>Missing</h4>
            <div className="chips">
              {a.missing_skills.length ? a.missing_skills.map((s) => <span key={s} className="chip bad">{s}</span>)
                : <span className="muted">Nothing — great fit.</span>}
            </div>
          </div>
        </div>
      </section>

      <section className="card">
        <h2>{a.prep_plan.length}-day prep plan</h2>
        <ol className="plan">
          {a.prep_plan.map((d) => (
            <li key={d.day}>
              <div className="day">Day {d.day}</div>
              <div>
                <strong>{d.focus}</strong>
                {d.kind === "refresh" && <span className="tag info">refresh</span>}
                <ul>{d.tasks.map((t, i) => <li key={i}>{t}</li>)}</ul>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section className="card">
        <h2>Practice questions</h2>
        <ol className="questions">
          {a.questions.map((q, i) => (
            <li key={i}>
              <p>{q.question}</p>
              <div className="chips">
                <span className="chip">{q.skill}</span>
                <span className="chip muted-chip">{q.difficulty}</span>
                <span className="hint">{q.why}</span>
              </div>
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}
