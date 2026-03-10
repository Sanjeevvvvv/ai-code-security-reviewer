# AI Code Security Reviewer (CLI)

A fully functional CLI tool that scans Python (`.py`) and JavaScript (`.js`) files for security issues using:

- **Fast static detectors** (regex + Python AST) for common vulnerability patterns
- **Groq** (`llama3-70b-8192`) for deeper, contextual review
- **MOCK MODE** that produces realistic findings when `GROQ_API_KEY` is not set (so the tool always works)

Findings are enriched with **OWASP Top 10** categories and **CWE** mappings, confidence scoring, de-duplication, and rich terminal output.

## Setup

### 1) Install dependencies

```bash
cd ai-code-security-reviewer
python -m venv venv
venv\\Scripts\\activate
pip install -r requirements.txt
```

### 2) Configure Groq (optional)

Copy `.env.example` to `.env` and set your key:

```bash
copy .env.example .env
```

Then edit `.env`:

```text
GROQ_API_KEY=your_groq_api_key_here
```

If you don’t set `GROQ_API_KEY`, the tool will run in **MOCK MODE** and display:
**"Running in MOCK MODE — set GROQ_API_KEY in .env for real analysis"**

## Usage

Run from the project folder:

### Scan a single file

```bash
python main.py scan tests/vulnerable_samples/sql_vuln.py
```

### Scan a directory (recursively)

```bash
python main.py scan tests/vulnerable_samples
```

### Scan a GitHub repo (clone + scan)

```bash
python main.py scan --github https://github.com/user/repo
```

### Output formats

- **Terminal (default)**:

```bash
python main.py scan tests/vulnerable_samples/sql_vuln.py
```

- **JSON**:

```bash
python main.py scan tests/vulnerable_samples/sql_vuln.py --output json
```

- **Markdown**:

```bash
python main.py scan tests/vulnerable_samples/sql_vuln.py --output markdown
```

### Severity filtering

Only show findings at or above a minimum severity:

```bash
python main.py scan tests/vulnerable_samples --severity high
```

### Verbose mode

Includes confidence reasoning and more details:

```bash
python main.py scan tests/vulnerable_samples/sql_vuln.py --verbose
```

## Output (what you’ll see)

When you run:

```bash
python main.py scan tests/vulnerable_samples/sql_vuln.py
```

You’ll get:

- A header panel with **files scanned** and **timestamp**
- One Rich panel per vulnerability with:
  - Title: **vulnerability name + severity badge**
  - Body: **description, line number, code snippet, fix suggestion**
  - Footer: **OWASP category + CWE ID + confidence score**
- A summary table with totals and an **overall risk score (0-100)**

*(Screenshot description: a cyan header panel, followed by red/orange/yellow/blue bordered finding panels, ending with a “Scan Summary” table and an “OWASP Category Breakdown” table.)*

## Web UI (FastAPI + React)

You can run a cyberpunk-inspired web dashboard on top of the same analyzer pipeline.

### 1) Install backend extras

From the virtualenv:

```bash
cd ai-code-security-reviewer
pip install fastapi uvicorn reportlab python-multipart
```

### 2) Install frontend dependencies

```bash
cd ai-code-security-reviewer/web/frontend
npm install
```

### 3) Run both servers

From the repository root (one level above `ai-code-security-reviewer`):

```bash
./run.sh
```

On Windows (PowerShell or Command Prompt):

```bat
run.bat
```

This will:

- Start the FastAPI backend at `http://localhost:8000` (`uvicorn web.backend.main:app --reload --port 8000`)
- Start the Vite/React frontend at `http://localhost:5173`

Open the browser at `http://localhost:5173` to:

- Paste code, upload files, or scan GitHub repositories
- View AI-enriched findings with OWASP/CWE metadata
- Inspect scan history and download PDF reports

## Running tests

```bash
pytest -q
```

The tests validate:
- Vulnerabilities are found in the provided vulnerable samples
- **MOCK MODE** works without an API key
- JSON output is valid JSON
- Severity filtering works

