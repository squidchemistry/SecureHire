import { useEffect, useState } from "react";
import { AnalysisSummary, api, Run } from "../api";

export default function History() {
  const [analyses, setAnalyses] = useState<AnalysisSummary[] | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = () =>
    Promise.all([api.analyses(), api.runs()])
      .then(([a, r]) => {
        setAnalyses(a.items);
        setRuns(r.items.filter((x) => x.status !== "succeeded"));
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Could not load history"));

  useEffect(() => {
    load();
  }, []);

  async function remove(id: string) {
    if (!confirm("Delete this analysis? This cannot be undone.")) return;
    await api.deleteAnalysis(id).catch((e) => setError(e.message));
    load();
  }

  if (error) return <div className="alert error">{error}</div>;
  if (!analyses) return <p className="muted">Loading…</p>;

  return (
    <div className="stack-lg">
      <h1>History</h1>
      {analyses.length === 0 && runs.length === 0 && (
        <div className="card empty">
          No analyses yet. <a href="#/">Start one</a> — the demo takes a few seconds.
        </div>
      )}
      {analyses.length > 0 && (
        <div className="card table-wrap">
          <table>
            <thead>
              <tr><th>Role</th><th>Score</th><th>Top gaps</th><th>Security</th><th>Date</th><th /></tr>
            </thead>
            <tbody>
              {analyses.map((a) => (
                <tr key={a.id}>
                  <td><a href={`#/runs/${a.run_id}`}>{a.target_role}</a></td>
                  <td><strong>{Math.round(a.match_score)}%</strong></td>
                  <td className="muted">{a.missing_skills.slice(0, 3).join(", ") || "—"}</td>
                  <td>{a.security_flags ? <span className="tag deny">{a.security_flags} event(s)</span> : <span className="tag allow">clean</span>}</td>
                  <td className="muted">{new Date(a.created_at).toLocaleDateString()}</td>
                  <td><button className="link danger-text" onClick={() => remove(a.id)}>Delete</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {runs.length > 0 && (
        <div className="card">
          <h2>Other runs</h2>
          <ul className="plain">
            {runs.map((r) => (
              <li key={r.id}>
                <a href={`#/runs/${r.id}`}>{r.target_role || r.id.slice(0, 8)}</a>{" "}
                <span className={`pill ${r.status}`}>{r.status}</span>{" "}
                <span className="muted small">{r.error ?? ""}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
