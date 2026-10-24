"""CLI entry point for local evaluation and benchmarking."""

import csv
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set

# Allow imports from parent code package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from code.config import DATASET_DIR, OUTPUT_PATH, before_or_equal, get_logger, load_csv
from code.evaluation.evaluator import evaluate_predictions
from code.evidence import EvidenceIndex
from code.identity import IdentityIndex
from code.policy import evaluate_case_deterministically

log = get_logger("evaluation")


def get_case_activity(case: Dict[str, str], user_tokens: Set[str], activities: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Correlate global system activity events for a specific case."""
    rep_at = case.get("reported_at", "")
    audit_at = case.get("audit_at", "")
    matched: List[Dict[str, str]] = []

    # 1. Activities mentioning user tokens directly (e.g. LINK_RESOURCE_IDENTITY)
    for a in activities:
        et = a.get("event_time", "")
        if not before_or_equal(et, audit_at):
            continue
        line_text = (a.get("details", "") + " " + a.get("resource_id", "")).lower()
        if any(tok in line_text for tok in user_tokens):
            matched.append(a)

    # 2. Deletion worker activity for this case around reported_at
    if rep_at:
        try:
            rep_dt = datetime.fromisoformat(rep_at.replace("Z", "+00:00"))
            best_acct_act = None
            min_diff = float("inf")
            for a in activities:
                if a.get("target_system") == "account_service" and a.get("source_system") == "deletion_worker":
                    a_dt = datetime.fromisoformat(a["event_time"].replace("Z", "+00:00"))
                    diff = (rep_dt - a_dt).total_seconds()
                    if -600 <= diff <= 5400 and abs(diff) < min_diff:
                        min_diff = abs(diff)
                        best_acct_act = a
            if best_acct_act and best_acct_act not in matched:
                matched.append(best_acct_act)
        except Exception:
            pass

    return matched


def benchmark_sample_requests():
    """Run deterministic solver on sample_deletion_requests.csv and score against sample_output.csv."""
    sample_reqs_path = DATASET_DIR / "sample_deletion_requests.csv"
    sample_truth_path = DATASET_DIR / "sample_output.csv"

    log.info("Loading sample requests and ground truth...")
    samples = load_csv(sample_reqs_path)
    identities = load_csv(DATASET_DIR / "user_identities.csv")
    audit_log = load_csv(DATASET_DIR / "user_audit_log.csv")
    manifest = load_csv(DATASET_DIR / "evidence_files.csv")
    activities = load_csv(DATASET_DIR / "system_activity.csv")

    id_idx = IdentityIndex(identities, audit_log)
    ev_idx = EvidenceIndex(manifest, DATASET_DIR)

    results = []
    for case in samples:
        u = id_idx.resolve(case["email"])
        tokens = id_idx.get_search_tokens(u) if u else {case["email"].lower()}
        recs = ev_idx.query_for_user(tokens, case["audit_at"])
        matched_act = get_case_activity(case, tokens, activities)
        res = evaluate_case_deterministically(case, u, recs, matched_act)
        results.append(res)

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w", encoding="utf-8", newline="") as tmp:
            writer = csv.writer(tmp)
            writer.writerow(["case_id", "deletion_status", "steps_json"])
            for r in results:
                writer.writerow([r["case_id"], r["deletion_status"], r["steps_json"]])
            tmp_path = Path(tmp.name)

        metrics = evaluate_predictions(tmp_path, sample_truth_path)

        print("\n" + "=" * 55)
        print("      SAMPLE GROUND TRUTH BENCHMARK RESULTS")
        print("=" * 55)
        print(f"Cases Evaluated:        {metrics['cases_evaluated']}")
        print(f"Status Accuracy:        {metrics['status_accuracy'] * 100:.1f}%")
        print(f"Step Match Accuracy:    {metrics['step_accuracy'] * 100:.1f}%")
        print(f"Exact Sequence Match:   {metrics['sequence_accuracy'] * 100:.1f}%")
        print("=" * 55 + "\n")

    finally:
        if tmp_path and tmp_path.exists():
            tmp_path.unlink()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--samples":
        benchmark_sample_requests()
    else:
        sample_truth_path = DATASET_DIR / "sample_output.csv"
        metrics = evaluate_predictions(OUTPUT_PATH, sample_truth_path)
        print(metrics)
