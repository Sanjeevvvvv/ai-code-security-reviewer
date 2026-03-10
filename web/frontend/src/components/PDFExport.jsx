import React, { useState } from "react";
import axios from "axios";

export function PDFExport({ scanId, compact = false }) {
  const [loading, setLoading] = useState(false);

  const handleDownload = async (e) => {
    e.stopPropagation?.();
    if (!scanId || loading) return;
    setLoading(true);
    try {
      const res = await axios.get(`/api/history/${scanId}/pdf`, {
        responseType: "blob",
      });
      const blob = new Blob([res.data], { type: "application/pdf" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cse_scan_${scanId}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Failed to download PDF", err);
      alert("Failed to generate PDF report. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <button
      className={compact ? "button-ghost" : "button-primary"}
      onClick={handleDownload}
      disabled={!scanId || loading}
      title="Download PDF report"
    >
      {loading ? (
        <span className="spinner" />
      ) : (
        <span style={{ fontSize: 12 }}>Download PDF</span>
      )}
    </button>
  );
}

