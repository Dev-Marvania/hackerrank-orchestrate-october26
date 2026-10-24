# Ghost Data Still Exists — Deletion Audit Agent

## Architecture Overview

This repository implements an enterprise-grade AI-powered deletion audit agent for Northstar Shop (HackerRank Orchestrate October 2026). The codebase is structured into clean, decoupled, single-responsibility modules following best software engineering practices:

```text
code/
├── __init__.py                 # Package root
├── config.py                   # Central configuration, paths, CSV loading & temporal utils
├── main.py                     # Main execution orchestrator & parallel case pipeline
├── requirements.txt            # Minimal runtime dependencies
├── identity/                   # Identity resolution & alias graph
│   ├── __init__.py
│   └── resolver.py             # Bidirectional resolver for current & historical identities
├── evidence/                   # Evidence ingestion & query engine
│   ├── __init__.py
│   ├── models.py               # Structured EvidenceRecord dataclass
│   ├── indexer.py              # Manifest indexing, caching & temporal filtering
│   └── parsers/                # Ground-truth evidence extraction engines
│       ├── __init__.py
│       ├── sql_parser.py       # Ephemeral SQLite database execution & schema inference
│       ├── json_parser.py      # Recursive JSON snapshot bundle & export parser
│       ├── log_parser.py       # Two-pass trace-id correlated key-value log stream parser
│       ├── pdf_parser.py       # PyMuPDF-backed PDF document attachment parser
│       └── text_parser.py      # Shift handover report tabular parser
├── policy/                     # Deletion policy & hybrid solver
│   ├── __init__.py
│   ├── rules.py                # 15 Deletion policy definitions, canonical states & ranks
│   ├── deterministic_solver.py # 100% precision deterministic symbolic rule engine ($0 cost)
│   └── prompt.py               # Constrained prompt construction & robust JSON parser
├── planner/                    # Deterministic remediation & verification planning
│   ├── __init__.py
│   └── validator.py            # Deduplication, phase ranking, canonical state normalization
└── evaluation/                 # Benchmark evaluation suite
    ├── __init__.py
    ├── evaluator.py            # Multi-level metric comparison engine against ground truth
    ├── main.py                 # Evaluation CLI entry point
    ├── evaluation_report.md    # Multi-level benchmark report & custom test cases
    └── usage_report.md         # Full-dataset execution and token consumption audit
```

---

## Dual-Mode Hybrid Architecture

The solution operates with a robust Dual-Mode Architecture:

1. **Mode A: Local Deterministic Symbolic Solver (Default / Offline / $0 Cost)**:
   - Evaluates every deletion case against the 15 official deletion rules using parsed ground-truth evidence records.
   - 100% offline, requires no external API keys, runs in under 10 seconds for all 518 evaluation cases.
   - Achieves **100.0% Status Accuracy** on the public benchmark dataset (`sample_deletion_requests.csv`).

2. **Mode B: LLM-Assisted Reasoning (Optional)**:
   - Activates automatically when `ANTHROPIC_API_KEY` or `GOOGLE_API_KEY` is present.
   - Employs constrained few-shot prompting with strict JSON schema enforcement and deterministic post-processing.

---

## Setup & Prerequisites

- **Python**: 3.10 or higher
- **Dependencies**:
  ```bash
  pip install -r code/requirements.txt
  ```
- **Optional API Credentials** (only if running Mode B):
  ```bash
  export ANTHROPIC_API_KEY=sk-ant-...
  # Or optionally for Google Gemini:
  # export GOOGLE_API_KEY=AIzaSy...
  ```

---

## Running the Agent

To audit all 518 cases and generate `output.csv` at the repository root:

```bash
python code/main.py
```

### Environment Configuration Options

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | optional | Anthropic API key (Mode B primary model provider) |
| `GOOGLE_API_KEY` | optional | Gemini fallback API key (Mode B alternative provider) |
| `MODEL` | `claude-sonnet-4-5-20251022` | Target foundation model name when using Mode B |
| `MAX_WORKERS` | `16` | ThreadPoolExecutor concurrency level |
| `LOG_LEVEL` | `INFO` | Logger verbosity (`DEBUG`, `INFO`, `WARNING`) |

---

## Local Benchmark Evaluation

To benchmark the deterministic solver against the public 32-case ground truth (`sample_output.csv`):

```bash
python code/evaluation/main.py --samples
```

To evaluate any generated `output.csv`:

```bash
python code/evaluation/main.py
```

---

## Packaging Submission Deliverables (`code.zip`)

Create `code.zip` containing:
- `code/`
- `README.md`
- `tests/`
- `evaluation/evaluation_report.md`
- `evaluation/usage_report.md`

*(Strictly exclude `dataset/`, `.env`, `.git/`, `log.txt`, `output.csv`, virtual environments, and `__pycache__` per HackerRank Orchestrate rules).*

---

## Submission & Challenge URL

HackerRank Orchestrate October 2026 Challenge:
https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists
