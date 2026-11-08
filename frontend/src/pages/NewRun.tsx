import { FormEvent, useEffect, useRef, useState } from "react";
import { api } from "../api";
import { navigate } from "../App";

export default function NewRun() {
  const [sampleJd, setSampleJd] = useState("");
  const [role, setRole] = useState("Senior Backend Engineer");
  const [jd, setJd] = useState("");
  const [days, setDays] = useState(7);
  const [count, setCount] = useState(8);
  const [difficulty, setDifficulty] = useState("mixed");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    api.samples().then((s) => setSampleJd(s.job_description)).catch(() => {});
  }, []);

  async function start(fn: () => Promise<{ id: string }>, label: string) {
    setError(null);
    setBusy(label);
    try {
      const { id } = await fn();
      navigate(`/runs/${id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start the analysis");
    } finally {
      setBusy(null);
    }
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file) return setError("Choose a PDF or DOCX resume");
    const form = new FormData();
    form.append("resume", file);
    form.append("jd_text", jd);
    form.append("target_role", role);
    form.append("days", String(days));
    form.append("question_count", String(count));
    form.append("difficulty", difficulty);
    start(() => api.createRun(form), "upload");
  }

  return (
    <div className="stack-lg">
      <section>
        <h1>Prepare for your next interview</h1>
        <p className="muted">
          Upload a resume and a job description. The agent parses the resume, maps your skills, scores the match,
          checks your past analyses for recurring gaps, and writes a day-by-day plan with practice questions. You can
          watch every step live.
        </p>
      </section>

      <section className="grid-2">
        <div className="card demo">
          <span className="badge ok">Demo</span>
          <h3>Normal resume</h3>
          <p className="muted">A fictional resume full of personal details. Watch them get stripped before the model sees anything.</p>
          <div className="row">
            <button className="primary" disabled={!!busy}
                    onClick={() => start(() => api.createSample("clean", role), "clean")}>
              {busy === "clean" ? "Starting…" : "Run demo"}
            </button>
            <a href={api.sampleUrl("clean")} className="link">View PDF</a>
          </div>
        </div>
        <div className="card demo danger">
          <span className="badge bad">Attack</span>
          <h3>Prompt-injection resume</h3>
          <p className="muted">
            The same resume with hidden text telling the AI to fetch <em>another user's</em> data and award a perfect
            score. The model falls for it; the guardrails don't.
          </p>
          <div className="row">
            <button className="primary danger" disabled={!!busy}
                    onClick={() => start(() => api.createSample("injection", role), "injection")}>
              {busy === "injection" ? "Starting…" : "Run attack demo"}
            </button>
            <a href={api.sampleUrl("injection")} className="link">View PDF</a>
          </div>
        </div>
      </section>

      <form className="card stack" onSubmit={submit}>
        <h2>Analyse your own resume</h2>
        <div className="grid-2">
          <label>
            Resume (PDF or DOCX, max 2 MB)
            <input ref={fileRef} type="file" accept=".pdf,.docx" required />
          </label>
          <label>
            Target role
            <input value={role} onChange={(e) => setRole(e.target.value)} maxLength={80} required />
          </label>
        </div>
        <label>
          <span className="label-row">
            Job description
            {sampleJd && <button type="button" className="link" onClick={() => setJd(sampleJd)}>Use sample</button>}
          </span>
          <textarea rows={8} value={jd} onChange={(e) => setJd(e.target.value)} maxLength={20000} required
                    placeholder="Paste the job description here" />
        </label>
        <div className="grid-3">
          <label>
            Plan length (days)
            <input type="number" min={1} max={30} value={days} onChange={(e) => setDays(Number(e.target.value))} />
          </label>
          <label>
            Questions
            <input type="number" min={1} max={15} value={count} onChange={(e) => setCount(Number(e.target.value))} />
          </label>
          <label>
            Difficulty
            <select value={difficulty} onChange={(e) => setDifficulty(e.target.value)}>
              <option value="mixed">Mixed</option>
              <option value="junior">Junior</option>
              <option value="mid">Mid</option>
              <option value="senior">Senior</option>
            </select>
          </label>
        </div>
        {error && <div className="alert error">{error}</div>}
        <div>
          <button className="primary" disabled={!!busy}>{busy === "upload" ? "Uploading…" : "Start analysis"}</button>
        </div>
      </form>
    </div>
  );
}
