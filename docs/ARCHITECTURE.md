# Architecture

SASTGuard separates concerns into clear layers: the **API**, the **SAST engine**,
the **AI analyzer**, **persistence**, and **async processing**. The SAST engine is
fully decoupled from the web/DB layers so it can run standalone from the CLI.

## C4 — Context (Level 1)

```mermaid
flowchart TD
    user([Developer / Security Engineer])
    subgraph SASTGuard
      app[SASTGuard Platform]
    end
    ollama[(Ollama / Llama 3 - local)]
    ci[CI/CD - GitHub Actions]

    user -->|uploads code, reviews findings| app
    app -->|AI second opinion| ollama
    ci -->|runs CLI, enforces gate| app
```

## C4 — Containers (Level 2)

```mermaid
flowchart TD
    user([User])
    fe[Frontend - React/Vite<br/>nginx]
    api[Backend API - FastAPI]
    worker[SAST Worker - Celery]
    redis[(Redis - broker)]
    pg[(PostgreSQL)]
    ollama[(Ollama)]

    user --> fe
    fe -->|REST /api| api
    api -->|enqueue scan| redis
    redis --> worker
    worker --> pg
    api --> pg
    api -->|AI analysis| ollama
    worker -->|AI enrichment| ollama
```

## C4 — Components (Level 3, backend)

```mermaid
flowchart TD
    api[FastAPI routers]
    scansvc[Scan Service]
    gatesvc[Security Gate Service]
    upload[Upload Service]
    repo[Scan Repository]
    engine[SAST Engine]
    rules[AST Rules]
    taint[Taint Analysis]
    bandit[Bandit Scanner]
    semgrep[Semgrep Scanner]
    dedup[Deduplicator]
    ai[AI Analyzer]

    api --> scansvc
    api --> gatesvc
    api --> upload
    api --> ai
    scansvc --> engine
    scansvc --> repo
    engine --> rules
    engine --> taint
    engine --> bandit
    engine --> semgrep
    engine --> dedup
    ai --> rules
```

## Scan sequence

```mermaid
sequenceDiagram
    participant U as User
    participant FE as Frontend
    participant API as FastAPI
    participant Q as Redis/Celery
    participant W as Worker
    participant E as SAST Engine
    participant DB as PostgreSQL

    U->>FE: Start scan
    FE->>API: POST /api/scans
    API->>DB: create Scan (PENDING)
    API->>Q: dispatch scan task
    API-->>FE: scan id
    Q->>W: run_scan
    W->>DB: status RUNNING
    W->>E: scan_path()
    E->>E: AST rules + taint + bandit + semgrep + dedup
    E-->>W: findings
    W->>DB: persist findings, status COMPLETED
    FE->>API: GET /api/scans/{id}
    API->>DB: fetch findings
    API-->>FE: findings
```

> When a Celery broker is unavailable (e.g. local dev without Redis), the API
> runs the scan synchronously so the workflow still completes.

## Data model

```mermaid
erDiagram
    SCAN ||--o{ FINDING : has
    FINDING ||--o| AIANALYSIS : enriched_by
    SCAN ||--o{ SECURITYGATERESULT : evaluated_by

    SCAN {
      string id PK
      string project_name
      string status
      datetime created_at
      datetime finished_at
      int total_files
      int total_findings
    }
    FINDING {
      string id PK
      string rule_id
      string title
      string file_path
      int line
      string severity
      string original_severity
      float confidence
      string cwe
      string owasp
      json engines
      json taint_path
    }
    AIANALYSIS {
      string id PK
      bool available
      string ai_severity
      float confidence
      bool possible_false_positive
      text explanation
      text remediation
      text fixed_code
    }
    SECURITYGATERESULT {
      string id PK
      string status
      int critical
      int high
      int medium
      json reasons
    }
```

## Design principles

- **Determinism first.** The AST + taint engine is the source of truth; the LLM
  only annotates.
- **Fail open for availability.** Missing Redis or Ollama degrades gracefully
  instead of breaking the platform.
- **Never execute analysed code.** All analysis is static over the AST.
- **Normalize + deduplicate.** All engines produce the same `Finding` shape and
  overlapping results merge, recording every engine that reported them.
