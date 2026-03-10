import React, { useState } from "react";
import { Header } from "./components/Header.jsx";
import { ScanForm } from "./components/ScanForm.jsx";
import { ResultsPanel } from "./components/ResultsPanel.jsx";
import { HistoryPanel } from "./components/HistoryPanel.jsx";
import { Clock, History, ScanLine } from "lucide-react";

export default function App() {
  const [view, setView] = useState("scan"); // "scan" | "history"
  const [currentResult, setCurrentResult] = useState(null);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="sidebar-logo-ascii">{`[ CSE ]`}</div>
          <div className="sidebar-subtitle">AI Code Security Reviewer</div>
        </div>
        <nav className="sidebar-nav">
          <button
            className={view === "scan" ? "active" : ""}
            onClick={() => setView("scan")}
          >
            <ScanLine size={16} />
            New Scan
          </button>
          <button
            className={view === "history" ? "active" : ""}
            onClick={() => setView("history")}
          >
            <History size={16} />
            History
          </button>
        </nav>
        <div className="sidebar-footer">
          <div>Time to first insight: &lt; 60s.</div>
          <div>
            Powered by <span>Groq + Llama 3</span>.
          </div>
        </div>
      </aside>

      <main className="main-area">
        <Header />
        <section className="main-content">
          <div className="panel-card">
            {view === "scan" ? (
              <ScanForm onResult={setCurrentResult} />
            ) : (
              <>
                <div className="panel-header">
                  <div className="panel-title">History</div>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      fontSize: 11,
                      color: "#9ca3af",
                    }}
                  >
                    <Clock size={14} />
                    Recent AI scans
                  </div>
                </div>
                <div className="panel-body">
                  <HistoryPanel />
                </div>
              </>
            )}
          </div>
          <ResultsPanel result={currentResult} />
        </section>
      </main>
    </div>
  );
}

