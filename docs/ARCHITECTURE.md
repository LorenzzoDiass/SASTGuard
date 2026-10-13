# Architecture — SASTGuard

O SASTGuard separa responsabilidades entre **API**, **motor SAST**, **analisador de IA**, **persistência** e **processamento de análises**. O motor SAST não depende da interface web nem do banco de dados e também pode ser executado pela CLI.

> **Duas formas de execução:** a arquitetura completa de desenvolvimento usa Docker Compose, Redis/Celery e Ollama; a implantação online de demonstração utiliza Vercel (frontend), Render (API e PostgreSQL), execução síncrona quando não há broker Redis e Groq como provedor de LLM. Não há evidência de Redis/Celery ou Ollama hospedados na implantação online.

## C4 — Context (Level 1)

```mermaid
flowchart TD
    user([Desenvolvedor / Analista de Segurança])
    app[SASTGuard Platform]
    ci[GitHub Actions - CI/CD]
    ollama[Ollama / Llama 3 - local]
    groq[Groq API - online]

    user -->|envia código e consulta findings| app
    ci -->|executa CLI e Security Gate| app
    app -.->|segunda opinião por IA, ambiente local| ollama
    app -->|segunda opinião por IA, implantação online| groq
```

O serviço de IA é **consultivo**: a detecção e a severidade original do motor determinístico são preservadas. A indisponibilidade da IA não impede a análise SAST.

## C4 — Containers (Level 2, Docker Compose)

```mermaid
flowchart TD
    user([Usuário])
    fe[Frontend - React/Vite + nginx]
    api[Backend API - FastAPI]
    worker[SAST Worker - Celery]
    redis[(Redis - broker)]
    pg[(PostgreSQL)]
    ollama[Ollama - LLM local]

    user --> fe
    fe -->|REST /api| api
    api -->|enfileira análise| redis
    redis --> worker
    worker -->|persiste resultados| pg
    api -->|consulta resultados| pg
    api -->|análise com IA| ollama
    worker -.->|enriquecimento quando configurado| ollama
```

Este diagrama representa a **arquitetura containerizada do projeto**, não a infraestrutura que está rodando no Render.

## Implantação online de demonstração

```mermaid
flowchart TD
    user([Usuário / Professor])
    vercel[Frontend React/Vite - Vercel]
    render[Backend FastAPI - Render]
    postgres[(PostgreSQL - Render)]
    sast[Motor SAST: AST + Taint + Bandit + Semgrep]
    groq[Groq API - LLM]

    user -->|HTTPS| vercel
    vercel -->|REST HTTPS| render
    render -->|análises, fallback síncrono sem Redis| sast
    render -->|persistência| postgres
    render -->|análise consultiva de findings| groq
```

- Frontend: <https://sast-guard.vercel.app>
- API: <https://sastguard-api.onrender.com>
- A API online e o banco PostgreSQL foram testados com análises reais; a análise de IA por Groq também foi testada.
- **Redis/Celery e Ollama não foram implantados na nuvem** nesta configuração. O sistema usa o caminho de execução sem broker disponível, descrito abaixo.
- O plano gratuito do Render pode suspender a API por inatividade, causando demora na primeira requisição. Antes da apresentação, abrir o sistema e aguardar a API responder.
- A chave da Groq deve ficar apenas em variáveis de ambiente privadas do Render, nunca no repositório ou em capturas de tela. Chaves expostas devem ser revogadas e substituídas.

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
    provider[Provedor configurado: Ollama ou Groq]

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
    ai --> provider
```

## Scan sequence — processamento com Celery

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
    FE->>API: POST /api/scans (ou upload)
    API->>DB: create Scan (PENDING)
    API->>Q: dispatch scan task
    API-->>FE: scan id
    Q->>W: run_scan
    W->>DB: status RUNNING
    W->>E: scan_path()
    E->>E: AST rules + taint + Bandit + Semgrep + dedup
    E-->>W: findings
    W->>DB: persist findings, status COMPLETED
    FE->>API: GET /api/scans/{id}
    API->>DB: fetch findings
    API-->>FE: findings
```

### Caminho alternativo — sem Redis/Celery disponível

Quando o broker Celery não está disponível, o serviço de análise tem um **fallback síncrono**. A API aciona o motor SAST diretamente, persiste os resultados e permite consultá-los pelo frontend. Esse caminho foi validado na implantação online com uma análise concluída. A duração da requisição e a ordem exata das atualizações de status dependem da implementação do serviço.

```mermaid
flowchart LR
    FE[Frontend] --> API[FastAPI]
    API --> ENG[SAST Engine - execução síncrona]
    ENG --> DB[(PostgreSQL)]
    DB --> API
    API --> FE
```

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

## CI/CD e Security Gate

O workflow `.github/workflows/security.yml` executa testes, analisa o diretório `vulnerable_samples`, gera relatórios **JSON, HTML e SARIF**, publica artefatos e aplica o Security Gate. A política padrão reprova quando encontra **1 ou mais Critical** ou **3 ou mais High**.

O diretório `vulnerable_samples` contém código **intencionalmente vulnerável**. Portanto, uma execução vermelha por `Security Gate failed (exit 1)` é o **resultado esperado para essa demonstração**, não evidência de que a aplicação hospedada parou de funcionar. A execução do GitHub Actions com bloqueio e a geração do relatório HTML foram verificadas. A publicação SARIF na aba Code Scanning depende também das permissões e recursos disponíveis no repositório.

## Design principles

- **Determinism first.** O motor AST + taint é a fonte primária dos findings; a IA oferece uma segunda opinião e recomendações.
- **Disponibilidade com fallback.** A falta de Redis ou de um provedor de IA não deve interromper a análise determinística; falha da IA não significa PASS no Security Gate.
- **Never execute analysed code.** A análise é estática e não executa os arquivos enviados.
- **Normalize + deduplicate.** AST, Bandit e Semgrep produzem findings normalizados e resultados sobrepostos são deduplicados.
- **Segredos fora do repositório.** Tokens e chaves ficam em variáveis de ambiente privadas; credenciais expostas devem ser rotacionadas.

## Limitações conhecidas

- O motor próprio analisa código Python; a taint analysis é predominantemente intraprocedural e não modela todos os fluxos possíveis.
- A análise por LLM pode produzir sugestões incorretas; recomendações precisam de revisão humana.
- A implantação gratuita não reproduz todos os serviços do Docker Compose, e a primeira requisição ao Render pode ser lenta.
- O endpoint público de upload deve ser utilizado apenas com código autorizado, sem segredos reais ou dados sensíveis.
