#!/usr/bin/env python3
"""
Ghost Data Still Exists — Dual-Mode Deletion Audit Agent
HackerRank Orchestrate October 2026

Architecture:
    code.config      -> Global paths, CSV loading, temporal utils, logging
    code.identity    -> IdentityIndex (bidirectional historical alias graph)
    code.evidence    -> EvidenceIndex (manifest indexing, parsers for SQL/JSON/log/text)
    code.policy      -> Dual-mode policy reasoning:
                        1. Deterministic Symbolic Solver (Local / $0 cost / Offline)
                        2. LLM-Assisted Prompting (Claude / Gemini API)
    code.planner     -> Step ordering, canonical state enforcement & validation
    code.evaluation  -> Benchmark accuracy runner & metrics calculator

Usage:
    cd <repo-root>
    python code/main.py
"""

from __future__ import annotations

import csv
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure repository root is on sys.path
REPO_DIR = Path(__file__).resolve().parent.parent
if str(REPO_DIR) not in sys.path:
    sys.path.insert(0, str(REPO_DIR))

from code.config import (
    DATASET_DIR,
    OUTPUT_PATH,
    EVAL_DIR,
    before_or_equal,
    get_logger,
    load_csv,
)
from code.evidence import EvidenceIndex
from code.identity import IdentityIndex
from code.planner import validate_and_order_steps
from code.policy import (
    build_analysis_prompt,
    evaluate_case_deterministically,
    parse_llm_json,
)

log = get_logger("orchestrator")

# Thread-safe token tracking
_token_lock = threading.Lock()
_total_in_tokens = 0
_total_out_tokens = 0


def load_env_file() -> None:
    """Safely populate os.environ from repo root .env if present without external dependencies."""
    env_file = REPO_DIR / ".env"
    if env_file.exists():
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if k and k not in os.environ:
                            os.environ[k] = v
        except Exception as e:
            log.warning(f"Could not load .env: {e}")


def get_llm_client() -> Tuple[Optional[Any], str, str]:
    """
    Attempt to initialize LLM provider client.
    Prioritizes Gemini (Google) as primary provider per configuration.
    Returns (client, provider_name, model_name) or (None, 'deterministic', 'symbolic-engine').
    """
    load_env_file()

    # 1. Primary Provider: Google Gemini
    gkey = os.environ.get("GOOGLE_API_KEY", "").strip() or os.environ.get("GEMINI_API_KEY", "").strip()
    if gkey and not gkey.startswith("AQ.") and not gkey.startswith("your_"):
        model = os.environ.get("MODEL", "gemini-2.5-pro")
        # Attempt google.generativeai SDK first if installed
        try:
            import google.generativeai as genai
            genai.configure(api_key=gkey)
            log.info(f"Initialized Google GenAI SDK with model: {model}")
            return genai, "google", model
        except ImportError:
            log.info(f"google.generativeai SDK not found; using standard HTTP REST client for model: {model}")
            return {"api_key": gkey, "type": "rest"}, "google", model
        except Exception as e:
            log.warning(f"Could not initialize Gemini client: {e}")

    # 2. Secondary Provider: Anthropic (fallback)
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if api_key:
        try:
            import anthropic
            model = os.environ.get("MODEL", "claude-sonnet-4-5-20251022")
            return anthropic.Anthropic(api_key=api_key), "anthropic", model
        except Exception as e:
            log.warning(f"Could not initialize Anthropic client: {e}")

    return None, "deterministic", "symbolic-rule-solver"


def call_llm(client: Any, provider: str, model: str, prompt: str, max_tokens: int = 4096) -> Tuple[str, int, int]:
    """Invoke the target LLM and update thread-safe token metrics."""
    global _total_in_tokens, _total_out_tokens
    in_t = out_t = 0

    if provider == "anthropic":
        resp = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        text = resp.content[0].text
        in_t = resp.usage.input_tokens
        out_t = resp.usage.output_tokens
    elif provider == "google":
        if isinstance(client, dict) and client.get("type") == "rest":
            import urllib.request
            api_key = client["api_key"]
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"maxOutputTokens": max_tokens}
            }
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                candidates = data.get("candidates", [])
                text = ""
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        text = parts[0].get("text", "")
                usage = data.get("usageMetadata", {})
                in_t = usage.get("promptTokenCount", len(prompt) // 4)
                out_t = usage.get("candidatesTokenCount", len(text) // 4)
        else:
            m = client.GenerativeModel(model)
            resp = m.generate_content(prompt)
            text = resp.text
            in_t = getattr(resp.usage_metadata, "prompt_token_count", len(prompt) // 4) if hasattr(resp, "usage_metadata") else len(prompt) // 4
            out_t = getattr(resp.usage_metadata, "candidates_token_count", len(text) // 4) if hasattr(resp, "usage_metadata") else len(text) // 4
    else:
        raise ValueError(f"Unsupported provider: {provider}")

    with _token_lock:
        _total_in_tokens += in_t
        _total_out_tokens += out_t

    return text, in_t, out_t


def _token_matches_text(tok: str, text: str) -> bool:
    if not tok:
        return False
    if tok.startswith("user_"):
        return bool(re.search(r'(?<![a-zA-Z0-9])' + re.escape(tok) + r'(?![a-zA-Z0-9])', text))
    return tok in text


def filter_activity(user_tokens: set[str], all_activity: List[Dict[str, str]], cutoff: str, reported_at: str = "", reported_status: str = "") -> List[Dict[str, str]]:
    """Filter system activity rows matching user tokens and captured before cutoff."""
    relevant = []
    for row in all_activity:
        et = row.get("event_time", "")
        if not before_or_equal(et, cutoff):
            continue
        line_text = (row.get("details", "") + " " + row.get("resource_id", "")).lower()
        if any(_token_matches_text(tok, line_text) for tok in user_tokens):
            relevant.append(row)

    # Correlate deletion worker account submission around reported_at
    if reported_at:
        try:
            from datetime import datetime
            rep_dt = datetime.fromisoformat(reported_at.replace("Z", "+00:00"))
            target_result = None
            if reported_status == "COMPLETE":
                target_result = "SUCCESS"
            elif reported_status == "PARTIALLY_COMPLETE":
                target_result = "PARTIAL_SUCCESS"
            elif reported_status == "NOT_STARTED":
                target_result = "FAILED"

            best_acct_act = None
            min_diff = float("inf")
            for a in all_activity:
                if a.get("target_system") == "account_service" and a.get("source_system") == "deletion_worker":
                    if target_result and a.get("reported_result", "").upper() != target_result:
                        continue
                    a_dt = datetime.fromisoformat(a["event_time"].replace("Z", "+00:00"))
                    diff = (rep_dt - a_dt).total_seconds()
                    if -600 <= diff <= 5400 and abs(diff) < min_diff:
                        min_diff = abs(diff)
                        best_acct_act = a
            if best_acct_act and best_acct_act not in relevant:
                relevant.append(best_acct_act)
        except Exception:
            pass

    return relevant


def process_case(case: Dict[str, str], identity_index: IdentityIndex,
                 evidence_index: EvidenceIndex, all_activity: List[Dict[str, str]],
                 client: Optional[Any], provider: str, model: str) -> Dict[str, Any]:
    """Execute deletion audit for a single case using Dual-Mode logic."""
    case_id = case["case_id"]
    email = case["email"]
    audit_at = case["audit_at"]
    reported_at = case.get("reported_at", "")

    # 1. Identity resolution & evidence scoping
    reported_status = case.get("reported_status", "")
    user = identity_index.resolve(email)
    if user:
        user_tokens = identity_index.get_search_tokens(user)
        matched_evidence = evidence_index.query_for_user(user_tokens, audit_at)
        matched_activity = filter_activity(user_tokens, all_activity, audit_at, reported_at, reported_status)
    else:
        user_tokens = {email.lower()}
        matched_evidence = []
        matched_activity = filter_activity(user_tokens, all_activity, audit_at, reported_at, reported_status)

    # 2. Mode selection: Deterministic Solver vs LLM-Assisted
    if client is None or provider == "deterministic":
        # Pure deterministic symbolic evaluation ($0 cost, local, instant)
        res = evaluate_case_deterministically(case, user, matched_evidence, matched_activity)
        log.info(f"[{case_id}] Deterministic: {res['deletion_status']}")
        return res

    # LLM-Assisted Mode
    prompt = build_analysis_prompt(case, user, matched_evidence, matched_activity)
    raw_text = ""
    in_t = out_t = 0

    for attempt in range(3):
        try:
            raw_text, in_t, out_t = call_llm(client, provider, model, prompt)
            break
        except Exception as e:
            log.warning(f"[{case_id}] LLM attempt {attempt + 1} error: {e}")
            time.sleep(2 ** attempt)
    else:
        log.warning(f"[{case_id}] LLM failed after 3 attempts. Gracefully falling back to Deterministic Solver.")
        return evaluate_case_deterministically(case, user, matched_evidence, matched_activity)

    # Parse and validate LLM output
    parsed = parse_llm_json(raw_text)
    status = parsed.get("deletion_status", "INCOMPLETE").upper()
    if status not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
        status = "INCOMPLETE"

    raw_steps = parsed.get("steps", []) if status != "NOT_APPLICABLE" else []
    validated_steps = validate_and_order_steps(raw_steps, status)
    steps_json = json.dumps(validated_steps, separators=(",", ":"), ensure_ascii=False)

    log.info(f"[{case_id}] LLM: {status} ({len(validated_steps)} steps)")
    return {
        "case_id": case_id,
        "deletion_status": status,
        "steps_json": steps_json,
        "in_tokens": in_t,
        "out_tokens": out_t,
    }


def main():
    start_time = time.time()
    log.info("=== Starting Ghost Data Still Exists Deletion Audit Agent ===")

    # Load environment variables (.env if present)
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    # Load dataset manifests and records
    requests = load_csv(DATASET_DIR / "deletion_requests.csv")
    identities = load_csv(DATASET_DIR / "user_identities.csv")
    audit_log = load_csv(DATASET_DIR / "user_audit_log.csv")
    all_activity = load_csv(DATASET_DIR / "system_activity.csv")
    evidence_manifest = load_csv(DATASET_DIR / "evidence_files.csv")

    log.info(f"Dataset loaded: {len(requests)} requests, {len(identities)} users, {len(evidence_manifest)} evidence files.")

    # Initialize modular indexes
    identity_index = IdentityIndex(identities, audit_log)
    evidence_index = EvidenceIndex(evidence_manifest, DATASET_DIR)

    # Initialize Dual-Mode LLM Engine
    if "--deterministic" in sys.argv or os.environ.get("USE_DETERMINISTIC", "").lower() in ("1", "true", "yes"):
        client, provider, model = None, "deterministic", "symbolic-rule-solver"
    else:
        client, provider, model = get_llm_client()
    if client is not None:
        log.info(f"Operating in Mode: LLM-Assisted ({provider} / {model})")
        max_workers = int(os.environ.get("MAX_WORKERS", "8"))
    else:
        log.info("Operating in Mode: Deterministic Symbolic Solver (Local / $0 cost / Offline)")
        max_workers = 16  # Local execution is CPU/in-memory bound

    # Process all cases in parallel
    results: List[Dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_case = {
            executor.submit(
                process_case, case, identity_index, evidence_index, all_activity, client, provider, model
            ): case["case_id"]
            for case in requests
        }
        for future in as_completed(future_to_case):
            cid = future_to_case[future]
            try:
                res = future.result()
                results.append(res)
            except Exception as exc:
                log.error(f"[{cid}] Unhandled error: {exc}")
                results.append({
                    "case_id": cid,
                    "deletion_status": "INCOMPLETE",
                    "steps_json": "[]",
                    "in_tokens": 0,
                    "out_tokens": 0,
                })

    # Sort strictly by case_id numerically/naturally matching deletion_requests.csv
    results.sort(key=lambda r: int(r["case_id"].split("_")[1]) if "_" in r["case_id"] and r["case_id"].split("_")[1].isdigit() else r["case_id"])

    # Verify complete 518-case coverage
    assert len(results) == len(requests), f"Mismatch in output rows: got {len(results)}, expected {len(requests)}"

    # Write output.csv to repository root
    with open(OUTPUT_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for row in results:
            writer.writerow([row["case_id"], row["deletion_status"], row["steps_json"]])

    elapsed = time.time() - start_time
    log.info(f"Successfully generated {OUTPUT_PATH} ({len(results)} rows) in {elapsed:.2f}s")

    # Generate / update evaluation usage report
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    total_in = sum(r.get("in_tokens", 0) for r in results)
    total_out = sum(r.get("out_tokens", 0) for r in results)
    n = len(results)
    model_calls = sum(1 for r in results if r.get("in_tokens", 0) > 0)
    model_calls_display = f"{model_calls} (Deterministic Symbolic Engine)" if model_calls == 0 else str(model_calls)

    usage_report_text = f"""# Usage Report — Ghost Data Still Exists

## Run Execution Summary
- **Timestamp**: {datetime.now().isoformat()}
- **Total Cases Processed**: {n}
- **Execution Time**: {elapsed:.2f}s ({elapsed / n:.3f}s/case)

## Model Infrastructure
| Metric | Details |
|---|---|
| Provider | {provider.capitalize()} |
| Model | {model} |
| Model Calls | {model_calls_display} |
| Concurrency | {max_workers} worker threads |

## Token Statistics
| Metric | Value |
|---|---|
| Input Tokens | {total_in:,} |
| Output Tokens | {total_out:,} |
| Combined Tokens | {total_in + total_out:,} |
| Average Input / Case | {total_in // n if n else 0:,} |
| Average Output / Case | {total_out // n if n else 0:,} |

## Cost Analysis
- Input tokens: ${(total_in / 1_000_000) * 3:.2f} ($3 / M tokens)
- Output tokens: ${(total_out / 1_000_000) * 15:.2f} ($15 / M tokens)
- **Total Cost**: ${((total_in * 3) + (total_out * 15)) / 1_000_000:.2f}
- **Average Cost / Case**: ${(((total_in * 3) + (total_out * 15)) / 1_000_000) / n if n else 0:.4f}
"""
    (EVAL_DIR / "usage_report.md").write_text(usage_report_text, encoding="utf-8")
    (REPO_DIR / "code" / "evaluation" / "usage_report.md").write_text(usage_report_text, encoding="utf-8")
    log.info(f"Updated usage report at {EVAL_DIR / 'usage_report.md'}")


if __name__ == "__main__":
    main()
