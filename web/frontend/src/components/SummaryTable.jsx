import React, { useEffect, useState } from "react";

const rows = [
  { key: "critical", label: "Critical", weight: 25, className: "summary-row-critical" },
  { key: "high", label: "High", weight: 15, className: "summary-row-high" },
  { key: "medium", label: "Medium", weight: 7, className: "summary-row-medium" },
  { key: "low", label: "Low", weight: 3, className: "summary-row-low" },
];

export function SummaryTable({ summary }) {
  const sevCounts = summary?.vulnerabilities_by_severity || {};
  const targetRisk = Number(summary?.overall_risk_score || 0);
  const [riskScore, setRiskScore] = useState(0);

  useEffect(() => {
    let raf;
    const duration = 600;
    const start = performance.now();
    const animate = (ts) => {
      const progress = Math.min(1, (ts - start) / duration);
      setRiskScore(Math.round(progress * targetRisk));
      if (progress < 1) {
        raf = requestAnimationFrame(animate);
      }
    };
    raf = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(raf);
  }, [targetRisk]);

  return (
    <div>
      <table className="summary-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th style={{ textAlign: "right" }}>Count</th>
            <th style={{ textAlign: "right" }}>Risk Weight</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key} className={row.className}>
              <td>{row.label}</td>
              <td style={{ textAlign: "right" }}>
                {Number(sevCounts[row.key] || 0).toLocaleString()}
              </td>
              <td style={{ textAlign: "right" }}>{row.weight}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="summary-footer">Overall Risk Score: {riskScore}/100</div>
    </div>
  );
}

