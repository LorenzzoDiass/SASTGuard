# Demo Script (5–10 minutes)

A step-by-step walkthrough for the presentation. Have the stack running
(`docker compose up --build`) or the local backend (`uvicorn app.main:app`) plus
the frontend (`npm run dev`).

> Tip: pull the model beforehand so step 9 is fast —
> `docker compose exec ollama ollama pull llama3`.

---

### 1. Open the dashboard
Go to http://localhost:3000 (Docker) or http://localhost:5173 (local). Show the
cybersecurity-themed dashboard: severity cards, charts, top critical files.

### 2. Start a scan of the vulnerable project
Click **New Scan**. Keep **Server path** = `/app/vulnerable_samples` (Docker) and
set a project name like `demo-fiap`. Click **Start scan**.

### 3. Watch processing
The scan runs through the worker (Celery) or synchronously. The app routes you to
the findings view when the scan completes (status `COMPLETED`).

### 4. Review findings
On **Findings**, show the table: Severity, Vulnerability, File, Line, CWE, Engine,
Status. Point out that several findings show `ast+bandit` under Engine — proof of
multi-engine detection and **deduplication**.

### 5. Open the SQL Injection
Click the `TAINT-SQLI` row (`sql_injection.py`). The detail modal opens.

### 6. Show the vulnerable code
Point to the **Vulnerable code** block:
```python
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
```

### 7. Show CWE / severity
Highlight **CWE-89**, **CRITICAL**, OWASP **A03:2021 – Injection**, confidence, and
the detecting engine (`taint`).

### 8. Show Source → Propagation → Sink
Scroll to the **Taint path** section:
```
SOURCE:      request.args.get("id")
PROPAGATION: user_id -> query
SINK:        cursor.execute(...)
```
This is the data-flow analysis differentiator.

### 9. Run AI analysis
Click **Run AI analysis**. With Ollama up, the model returns explanation, impact,
false-positive assessment, remediation and corrected code. If Ollama is down, show
the graceful fallback message `"AI analysis unavailable"` — the finding is never
lost.

### 10. Show the explanation
Read the AI **explanation** and **impact** — a plain-language description of why
this is exploitable.

### 11. Show the suggested fixed code
Show the **Suggested fix** block (parameterized query), e.g.:
```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### 12. Run the Security Gate
Open **Security Gate**, select the scan, click **Evaluate gate**. Show the result:
**FAIL** with reasons (`≥1 critical`, `≥3 high`).

### 13. Demonstrate FAIL in CI
Optionally run the CLI to mirror the pipeline:
```bash
python -m app.cli scan ../vulnerable_samples --gate
# Security Gate: FAIL  -> exit code 1
```

### 14. Fix the vulnerability
Edit `vulnerable_samples/sql_injection.py` to use a parameterized query:
```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### 15. Run again
Re-run the scan (dashboard **New Scan**, or re-run the CLI). The SQL injection is
gone from the taint results.

### 16. Show the improved result
Compare: the `TAINT-SQLI` finding disappears and, on a clean target, the gate
returns **PASS** (exit code 0). This proves the scanner distinguishes insecure
from secure code.

---

## Backup / talking points

- **No code is executed** — analysis is purely static over the AST.
- **Three engines, one model** — native AST+taint, Bandit, Semgrep, deduplicated.
- **AI is a second opinion** — deterministic detection stays authoritative.
- **CI-ready** — CLI exit codes drive the GitHub Actions gate; reports are
  uploaded as artifacts (JSON/HTML/SARIF).
- **Resilient** — missing Redis or Ollama degrades gracefully.
