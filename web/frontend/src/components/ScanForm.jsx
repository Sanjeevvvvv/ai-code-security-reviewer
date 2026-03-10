import React, { useCallback, useState } from "react";
import axios from "axios";

const MODES = {
  code: "code",
  file: "file",
  github: "github",
};

export function ScanForm({ onResult }) {
  const [mode, setMode] = useState(MODES.code);
  const [code, setCode] = useState("");
  const [filename, setFilename] = useState("pasted_code.py");
  const [language, setLanguage] = useState("python");
  const [file, setFile] = useState(null);
  const [githubUrl, setGithubUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    const f = e.dataTransfer.files?.[0];
    if (f) {
      setFile(f);
      setError("");
    }
  }, []);

  const handleBrowseChange = (e) => {
    const f = e.target.files?.[0];
    if (f) {
      setFile(f);
      setError("");
    }
  };

  const handleScan = async () => {
    setLoading(true);
    setError("");
    try {
      if (mode === MODES.code) {
        const res = await axios.post("/api/scan", {
          mode: "code",
          content: code,
          filename,
          language,
        });
        onResult?.(res.data);
      } else if (mode === MODES.file) {
        if (!file) {
          setError("Please select a file to upload.");
          return;
        }
        const form = new FormData();
        form.append("file", file);
        const res = await axios.post("/api/scan/upload", form, {
          headers: { "Content-Type": "multipart/form-data" },
        });
        onResult?.(res.data);
      } else if (mode === MODES.github) {
        const res = await axios.post("/api/scan", {
          mode: "github",
          github_url: githubUrl,
        });
        onResult?.(res.data);
      }
    } catch (err) {
      const msg =
        err?.response?.data?.detail ||
        err?.message ||
        "Scan failed. Please check the backend logs.";
      setError(String(msg));
    } finally {
      setLoading(false);
    }
  };

  const currentButtonLabel =
    mode === MODES.code
      ? "Scan Code"
      : mode === MODES.file
      ? "Scan File"
      : "Scan Repository";

  const codeLines = code.split("\n").length || 1;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <div className="panel-header">
        <div className="panel-title">New Scan</div>
        <div className="tab-strip">
          <button
            className={`tab-button ${mode === MODES.code ? "active" : ""}`}
            onClick={() => setMode(MODES.code)}
          >
            Paste Code
          </button>
          <button
            className={`tab-button ${mode === MODES.file ? "active" : ""}`}
            onClick={() => setMode(MODES.file)}
          >
            Upload File
          </button>
          <button
            className={`tab-button ${mode === MODES.github ? "active" : ""}`}
            onClick={() => setMode(MODES.github)}
          >
            GitHub URL
          </button>
        </div>
      </div>

      {mode === MODES.code && (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <div style={{ display: "flex", gap: 8 }}>
            <div style={{ flex: 1 }}>
              <div className="field-label">Filename</div>
              <input
                className="text-input"
                value={filename}
                onChange={(e) => setFilename(e.target.value)}
                placeholder="pasted_code.py"
              />
            </div>
            <div>
              <div className="field-label">Language</div>
              <select
                className="select-input"
                value={language}
                onChange={(e) => setLanguage(e.target.value)}
              >
                <option value="python">Python</option>
                <option value="javascript">JavaScript</option>
              </select>
            </div>
          </div>

          <div className="field-label">Code</div>
          <div
            className="code-editor-wrap"
            style={{ maxHeight: 380, overflow: "hidden" }}
          >
            <div className="code-editor-linenos">
              {Array.from({ length: Math.max(3, codeLines) }).map((_, idx) => (
                <div key={idx}>{idx + 1}</div>
              ))}
            </div>
            <textarea
              className="code-editor code-editor-inner"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="# Paste a Python or JavaScript file here..."
            />
          </div>
        </div>
      )}

      {mode === MODES.file && (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div
            className="dropzone"
            onDragOver={(e) => {
              e.preventDefault();
              e.stopPropagation();
            }}
            onDrop={handleDrop}
            onClick={() => document.getElementById("cse-file-input")?.click()}
          >
            <div style={{ fontSize: 13, marginBottom: 2 }}>
              Drag &amp; drop a file here
            </div>
            <div style={{ fontSize: 11 }}>
              or <span style={{ color: "#00e5ff" }}>click to browse</span>
            </div>
            {file && (
              <div style={{ marginTop: 6, fontSize: 11, color: "#e5e7eb" }}>
                Selected: <span style={{ color: "#00e5ff" }}>{file.name}</span>
              </div>
            )}
          </div>
          <input
            id="cse-file-input"
            type="file"
            style={{ display: "none" }}
            onChange={handleBrowseChange}
          />
        </div>
      )}

      {mode === MODES.github && (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <div className="field-label">GitHub Repository URL</div>
          <input
            className="text-input"
            placeholder="https://github.com/username/repo"
            value={githubUrl}
            onChange={(e) => setGithubUrl(e.target.value)}
          />
        </div>
      )}

      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginTop: 4,
        }}
      >
        <button
          className="button-primary"
          onClick={handleScan}
          disabled={loading}
        >
          {loading ? <span className="spinner" /> : currentButtonLabel}
        </button>
        {error ? (
          <div className="error-text">{error}</div>
        ) : (
          <div className="success-text" style={{ opacity: 0.7 }}>
            Tip: Use MOCK MODE if GROQ_API_KEY is not set.
          </div>
        )}
      </div>
    </div>
  );
}

