import { useEffect, useState } from "react";
import { auth, setUnauthorizedHandler } from "./api";
import AuthPage from "./pages/AuthPage";
import History from "./pages/History";
import NewRun from "./pages/NewRun";
import RunView from "./pages/RunView";

type Route = { name: "new" } | { name: "history" } | { name: "run"; id: string };

function parseHash(): Route {
  const h = window.location.hash.replace(/^#\/?/, "");
  const [first, second] = h.split("/");
  if (first === "runs" && second) return { name: "run", id: decodeURIComponent(second) };
  if (first === "history") return { name: "history" };
  return { name: "new" };
}

export function navigate(path: string) {
  window.location.hash = path;
}

export default function App() {
  const [signedIn, setSignedIn] = useState(() => Boolean(auth.token));
  const [route, setRoute] = useState<Route>(parseHash);

  useEffect(() => {
    const onHash = () => setRoute(parseHash());
    window.addEventListener("hashchange", onHash);
    setUnauthorizedHandler(() => setSignedIn(false));
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  if (!signedIn) return <AuthPage onAuthed={() => setSignedIn(true)} />;

  const signOut = () => {
    auth.token = null;
    setSignedIn(false);
    navigate("/");
  };

  return (
    <div className="app">
      <header className="topbar">
        <a className="brand" href="#/">
          <img src="/favicon.svg" alt="" width={24} height={24} />
          SecureHire
        </a>
        <nav>
          <a href="#/" className={route.name === "new" ? "active" : ""}>New analysis</a>
          <a href="#/history" className={route.name === "history" ? "active" : ""}>History</a>
          <button className="link" onClick={signOut}>Sign out</button>
        </nav>
      </header>
      <main className="container">
        {route.name === "new" && <NewRun />}
        {route.name === "history" && <History />}
        {route.name === "run" && <RunView key={route.id} runId={route.id} />}
      </main>
      <footer className="footer">
        Personal data is stripped before any AI call · uploads are deleted when the run ends · every tool call is audited
      </footer>
    </div>
  );
}
