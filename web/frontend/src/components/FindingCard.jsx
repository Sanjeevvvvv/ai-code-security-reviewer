import React, { useEffect, useRef } from "react";
import hljs from "highlight.js/lib/core";
import python from "highlight.js/lib/languages/python";
import javascript from "highlight.js/lib/languages/javascript";

hljs.registerLanguage("python", python);
hljs.registerLanguage("javascript", javascript);

const SEVERITY_META = {
  critical: { emoji: "🔴", className: "severity-critical" },
  high: { emoji: "🟠", className: "severity-high" },
  medium: { emoji: "🟡", className: "severity-medium" },
  low: { emoji: "🔵", className: "severity-low" },
};

export function FindingCard({ finding }) {
  const codeRef = useRef(null);

  useEffect(() => {
    if (codeRef.current) {
      hljs.highlightElement(codeRef.current);
    }
  }, [finding?.code_snippet]);

  const severityKey = String(finding.severity || "low").toLowerCase();
  const meta = SEVERITY_META[severityKey] ?? SEVERITY_META.low;

  return (
    <div className={`finding-card ${meta.className}`}>
      <div className="finding-header">
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div className={`severity-chip ${meta.className}`}>
            <span>{meta.emoji}</span>
            <span style={{ fontSize: 11 }}>{finding.severity?.toUpperCase()}</span>
          </div>
          <div className="finding-title">{finding.name}</div>
        </div>
        <div className="finding-meta">
          <span style={{ opacity: 0.8 }}>
            {finding.owasp_category || "OWASP ?"} · {finding.cwe_id || "CWE-?"}
          </span>
        </div>
      </div>

      <div className="finding-body">
        <div style={{ display: "flex", justifyContent: "space-between" }}>
          <span>
            Line {finding.line_number ?? "?"} · confidence{" "}
            {Number(finding.confidence_score || 0).toFixed(2)}
          </span>
          {finding.filename && (
            <span className="badge-muted">
              {finding.filename.split(/[\\/]/).slice(-1)[0]}
            </span>
          )}
        </div>

        {finding.code_snippet && (
          <pre className="finding-code">
            <code ref={codeRef} className="language-python">
              {finding.code_snippet}
            </code>
          </pre>
        )}

        {finding.description && (
          <div className="finding-desc">⚠ {finding.description}</div>
        )}
        {finding.fix_suggestion && (
          <div className="finding-fix">✔ {finding.fix_suggestion}</div>
        )}
      </div>
    </div>
  );
}

