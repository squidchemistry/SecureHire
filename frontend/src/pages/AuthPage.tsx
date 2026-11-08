import { FormEvent, useState } from "react";
import { api } from "../api";

export default function AuthPage({ onAuthed }: { onAuthed: () => void }) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === "login") await api.login(email, password);
      else await api.register(email, password);
      onAuthed();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth">
      <div className="auth-card card">
        <div className="brand big">
          <img src="/favicon.svg" alt="" width={36} height={36} />
          SecureHire
        </div>
        <p className="muted">
          An AI agent that turns your resume and a job description into a match score, a prep plan and practice
          questions — built to resist prompt injection and to keep your personal data away from the model.
        </p>
        <div className="tabs" role="tablist">
          <button role="tab" aria-selected={mode === "login"} className={mode === "login" ? "on" : ""}
                  onClick={() => setMode("login")}>Sign in</button>
          <button role="tab" aria-selected={mode === "register"} className={mode === "register" ? "on" : ""}
                  onClick={() => setMode("register")}>Create account</button>
        </div>
        <form onSubmit={submit} className="stack">
          <label>
            Email
            <input type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <label>
            Password
            <input type="password" required minLength={8} maxLength={128}
                   autoComplete={mode === "login" ? "current-password" : "new-password"}
                   value={password} onChange={(e) => setPassword(e.target.value)} />
            {mode === "register" && <span className="hint">At least 8 characters.</span>}
          </label>
          {error && <div className="alert error">{error}</div>}
          <button className="primary" disabled={busy}>
            {busy ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"}
          </button>
        </form>
        <p className="hint center">Your email is stored only as a keyed hash.</p>
      </div>
    </div>
  );
}
