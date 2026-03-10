import React from "react";
import { FindingCard } from "./FindingCard.jsx";
import { SummaryTable } from "./SummaryTable.jsx";
import { PDFExport } from "./PDFExport.jsx";

export function ResultsPanel({ result }) {
  if (!result) {
    return (
      <div className="panel-card">
        <div className="panel-header">
          <div className="panel-title">Results</div>
          <span className="badge-muted">Awaiting first scan…</span>
        </div>
        <div className="panel-body empty-state">
          Launch a scan to see AI-enriched findings here.
        </div>
      </div>
    );
  }

  const findings = result.findings || [];
  const ts = result.timestamp
    ? new Date(result.timestamp).toLocaleString()
    : "Unknown";
  const total = findings.length;

  const primarySource =
    (findings[0]?.filename &&
      findings[0].filename.split(/[\\/]/).slice(-1)[0]) ||
    result.source ||
    "scan";

  return (
    <div className="panel-card">
      <div className="panel-header">
        <div>
          <div className="panel-title">Results</div>
          <div
            style={{
              fontSize: 11,
              color: "#9ca3af",
              marginTop: 3,
              display: "flex",
              gap: 8,
            }}
          >
            <span>📂 {primarySource}</span>
            <span>🕐 {ts}</span>
            <span>📊 {total} findings</span>
          </div>
        </div>
        <PDFExport scanId={result.id} />
      </div>
      <div className="panel-body">
        {total === 0 ? (
          <div className="success-text" style={{ marginTop: 8 }}>
            ✓ No vulnerabilities found in this scan.
          </div>
        ) : (
          <div style={{ marginTop: 4 }}>
            {findings.map((f) => (
              <FindingCard key={`${f.name}-${f.line_number}-${f.cwe_id}`} finding={f} />
            ))}
          </div>
        )}
        <div style={{ marginTop: 10 }}>
          <SummaryTable summary={result.summary} />
        </div>
      </div>
    </div>
  );
}

