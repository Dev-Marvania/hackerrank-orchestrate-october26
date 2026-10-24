"""Benchmark evaluation against sample ground truth and accuracy calculator."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from ..config import get_logger

log = get_logger(__name__)


def evaluate_predictions(pred_path: Path, truth_path: Path) -> Dict[str, Any]:
    """Compare predictions with ground-truth and compute multi-level metrics."""
    with open(pred_path, encoding="utf-8-sig") as f:
        preds = {r["case_id"]: r for r in csv.DictReader(f)}
    with open(truth_path, encoding="utf-8-sig") as f:
        truth = {r["case_id"]: r for r in csv.DictReader(f)}

    common_cases = [cid for cid in truth if cid in preds]
    if not common_cases:
        log.warning("No overlapping case_ids between predictions and truth!")
        return {"case_count": 0, "status_accuracy": 0.0}

    status_correct = 0
    total_steps_truth = 0
    total_steps_matched = 0
    sequence_matches = 0

    for cid in common_cases:
        p_row = preds[cid]
        t_row = truth[cid]

        # Case-level status
        if p_row["deletion_status"] == t_row["deletion_status"]:
            status_correct += 1

        p_steps = json.loads(p_row.get("steps_json", "[]"))
        t_steps = json.loads(t_row.get("steps_json", "[]"))

        total_steps_truth += len(t_steps)

        # Step matching: (phase, operation, system_id, resource_id)
        t_step_tuples = [(s.get("phase"), s.get("operation"), s.get("system_id"), s.get("resource_id")) for s in t_steps]
        p_step_tuples = [(s.get("phase"), s.get("operation"), s.get("system_id"), s.get("resource_id")) for s in p_steps]

        matched = sum(1 for t in t_step_tuples if t in p_step_tuples)
        total_steps_matched += matched

        if t_step_tuples == p_step_tuples:
            sequence_matches += 1

    total = len(common_cases)
    return {
        "cases_evaluated": total,
        "status_accuracy": status_correct / total if total else 0.0,
        "step_accuracy": total_steps_matched / total_steps_truth if total_steps_truth else 1.0,
        "sequence_accuracy": sequence_matches / total if total else 0.0,
    }
