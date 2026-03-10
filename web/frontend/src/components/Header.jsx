import React, { useEffect, useState } from "react";
import axios from "axios";

export function Header() {
  const [online, setOnline] = useState(true);

  useEffect(() => {
    let cancelled = false;

    const check = async () => {
      try {
        const res = await axios.get("/api/health");
        if (!cancelled) {
          setOnline(res.data?.status === "ok");
        }
      } catch {
        if (!cancelled) {
          setOnline(false);
        }
      }
    };

    check();
    const id = setInterval(check, 30_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const statusColor = online ? "#22c55e" : "#f97373";

  return (
    <header
      style={{
        borderRadius: 14,
        border: "1px solid rgba(42,42,58,0.9)",
        padding: "10px 14px",
        background:
          "radial-gradient(circle at top left, rgba(0,229,255,0.25), transparent 60%)",
        boxShadow: "0 0 0 1px rgba(15,23,42,0.9), 0 0 30px rgba(0,229,255,0.35)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
      }}
    >
      <div>
        <div
          style={{
            fontFamily: '"JetBrains Mono", ui-monospace, monospace',
            letterSpacing: "0.16em",
            textTransform: "uppercase",
            color: "#00e5ff",
            textShadow: "0 0 18px rgba(0,229,255,0.9)",
            fontSize: 12,
          }}
        >
          {"<CSE /> AI CODE SECURITY"}
        </div>
        <div
          style={{
            marginTop: 4,
            fontSize: 11,
            color: "#b3b3d1",
          }}
        >
          AI Code Security Reviewer | Powered by Groq + Llama 3
        </div>
      </div>

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          fontSize: 11,
          color: "#9ca3af",
        }}
      >
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            padding: "4px 10px",
            borderRadius: 999,
            border: "1px solid rgba(55,65,81,0.8)",
            background: "rgba(15,23,42,0.9)",
          }}
        >
          <span
            className={`status-dot ${online ? "pulsing" : ""}`}
            style={{ backgroundColor: statusColor }}
          />
          <span style={{ fontSize: 11 }}>{online ? "AI Ready" : "Offline"}</span>
        </div>
      </div>
    </header>
  );
}

