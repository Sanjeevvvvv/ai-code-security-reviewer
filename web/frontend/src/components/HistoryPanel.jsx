import React, { useEffect, useState } from "react";
import axios from "axios";
import { ChevronDown, ChevronUp, Trash2, FileDown } from "lucide-react";
import { FindingCard } from "./FindingCard.jsx";
import { SummaryTable } from "./SummaryTable.jsx";
import { PDFExport } from "./PDFExport.jsx";

export function HistoryPanel() {
  const [items, setItems] = useState([]);
  const [expandedId, setExpandedId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await axios.get("/api/history");
      setItems(res.data || []);
    } catch (err) {
      const msg =
        err?.response?.data?.detail ||
        err?.message ||
        "Failed to load scan history.";
      setError(String(msg));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleDelete = async (id, e) => {
    e.stopPropagation();
    try {
      await axios.delete(`/api/history/${id}`);
      setItems((prev) => prev.filter((x) => x.id !== id));
      if (expandedId === id) setExpandedId(null);
    } catch (err) {
      alert("Failed to delete history item.");
      console.error(err);
    }
  };

  return (
    <div className="panel-card">
      <div className="panel-header">
        <div className="panel-title">History</div>
        <button className="button-ghost" onClick={load} disabled={loading}>
          {loading ? (
            <span className="spinner" />
          ) : (
            <>
              <FileDown size={14} />
              Refresh
            </>
          )}
        </button>
      </div>
      <div className="panel-body">
        {error && <div className="error-text">{error}</div>}
        {!error && !loading && items.length === 0 && (
          <div className="empty-state">No scan history yet.</div>
        )}
        {items.map((item) => {
          const ts = item.timestamp
            ? new Date(item.timestamp).toLocaleString()
            : "Unknown";
          const counts = item.summary?.vulnerabilities_by_severity || {};
          const total = item.findings?.length || 0;
          const risk = item.risk_score ?? item.summary?.overall_risk_score ?? 0;

          return (
            <div
              key={item.id}
              className="history-card"
              onClick={() =>
                setExpandedId((prev) => (prev === item.id ? null : item.id))
              }
            >
              <div className="history-card-header">
                <div>
                  <div className="history-card-title">
                    {item.source || "scan"}
                  </div>
                  <div className="history-card-sub">
                    {ts} · {total} findings
                  </div>
                </div>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 6,
                  }}
                >
                  <span className="risk-badge">
                    Risk {risk}/100 · C:{counts.critical || 0} H:{counts.high || 0} M:
                    {counts.medium || 0} L:{counts.low || 0}
                  </span>
                  <PDFExport scanId={item.id} compact />
                  <button
                    className="button-ghost"
                    style={{ paddingInline: 8 }}
                    onClick={(e) => handleDelete(item.id, e)}
                    title="Delete scan"
                  >
                    <Trash2 size={14} />
                  </button>
                  {expandedId === item.id ? (
                    <ChevronUp size={16} />
                  ) : (
                    <ChevronDown size={16} />
                  )}
                </div>
              </div>
              {expandedId === item.id && (
                <div style={{ marginTop: 8 }}>
                  <div style={{ marginBottom: 6 }}>
                    <SummaryTable summary={item.summary} />
                  </div>
                  <div style={{ maxHeight: 260, overflow: "auto", marginTop: 4 }}>
                    {(item.findings || []).map((f) => (
                      <FindingCard
                        key={`${f.name}-${f.line_number}-${f.cwe_id}`}
                        finding={f}
                      />
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

