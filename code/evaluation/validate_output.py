"""Comprehensive validation script for output.csv adhering to AGENTS.md §6."""

import csv
import json
import sys
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent.parent
OUTPUT_CSV = REPO_DIR / "output.csv"
DATASET_REQS = REPO_DIR / "dataset" / "deletion_requests.csv"

ALLOWED_OPS = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": "PRESENT",
        "REPORT_EXPOSED_PII": "PRESENT",
        "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
        "REPORT_RESTORE_RISK": "ACTIVE",
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": "DISABLED",
        "BLOCK_RESTORE": "BLOCKED",
        "DELETE_RECORD": "ABSENT",
        "REDACT_RECORD": "REDACTED",
        "ANONYMIZE_RECORD": "ANONYMIZED",
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": "ABSENT",
        "VERIFY_RECORD_PRESENT": "PRESENT",
        "VERIFY_RECORD_REDACTED": "REDACTED",
        "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
        "VERIFY_RESTORE_BLOCKED": "BLOCKED",
    },
}

VALID_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
PHASE_RANK = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}


def validate_output(csv_path: Path = OUTPUT_CSV) -> bool:
    if not csv_path.exists():
        print(f"ERROR: {csv_path} does not exist!")
        return False

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            print("ERROR: CSV is empty!")
            return False
        rows = list(reader)

    # 1. Header validation
    expected_header = ["case_id", "deletion_status", "steps_json"]
    if header != expected_header:
        print(f"FAIL: Header mismatch: {header} != {expected_header}")
        return False

    # 2. Row count validation (exactly 518 data rows)
    if len(rows) != 518:
        print(f"FAIL: Expected exactly 518 data rows, found {len(rows)}")
        return False

    # 3. Sort order matches deletion_requests.csv natural sort order
    if DATASET_REQS.exists():
        with open(DATASET_REQS, "r", encoding="utf-8") as df:
            dreader = csv.DictReader(df)
            expected_case_ids = [r["case_id"] for r in dreader]
        actual_case_ids = [r[0] for r in rows]
        if actual_case_ids != expected_case_ids:
            print(f"FAIL: case_id sequence does not match deletion_requests.csv!")
            return False

    violations = []
    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}
    total_steps = 0

    for idx, row in enumerate(rows, start=1):
        if len(row) != 3:
            violations.append(f"Row {idx}: Expected 3 columns, got {len(row)}")
            continue

        case_id, status, steps_str = row

        # Status validation
        if status not in VALID_STATUSES:
            violations.append(f"[{case_id}] Invalid deletion_status: {status}")
            continue
        status_counts[status] += 1

        # JSON parsing validation
        try:
            steps = json.loads(steps_str)
        except Exception as e:
            violations.append(f"[{case_id}] Malformed JSON: {e}")
            continue

        if not isinstance(steps, list):
            violations.append(f"[{case_id}] steps_json is not an array")
            continue

        # NOT_APPLICABLE invariant
        if status == "NOT_APPLICABLE":
            if steps_str != "[]" or len(steps) != 0:
                violations.append(f"[{case_id}] NOT_APPLICABLE must have steps_json == '[]', got {steps_str}")
            continue

        total_steps += len(steps)
        last_phase_rank = -1

        # COMPLETE cases only have verification steps with non-empty evidence_id
        if status == "COMPLETE":
            for step in steps:
                if step.get("phase") != "VERIFICATION":
                    violations.append(f"[{case_id}] COMPLETE case has non-VERIFICATION step: {step}")
                if not step.get("evidence_id"):
                    violations.append(f"[{case_id}] COMPLETE case verification step missing evidence_id: {step}")

        # Step-level invariants
        for s_idx, step in enumerate(steps, start=1):
            # 1-based consecutive numbering
            if step.get("step_no") != s_idx:
                violations.append(f"[{case_id}] step_no expected {s_idx}, got {step.get('step_no')}")

            # Phase ordering
            phase = step.get("phase")
            if phase not in PHASE_RANK:
                violations.append(f"[{case_id}] Unknown phase: {phase}")
                continue

            rank = PHASE_RANK[phase]
            if rank < last_phase_rank:
                violations.append(f"[{case_id}] Phase order violation: {phase} followed rank {last_phase_rank}")
            last_phase_rank = rank

            # Allowed operations and states
            op = step.get("operation")
            st = step.get("state")
            if op not in ALLOWED_OPS[phase]:
                violations.append(f"[{case_id}] Invalid operation '{op}' for phase '{phase}'")
            elif ALLOWED_OPS[phase][op] != st:
                violations.append(f"[{case_id}] State '{st}' does not match operation '{op}' (expected '{ALLOWED_OPS[phase][op]}')")

            # Evidence ID rules
            ev_id = step.get("evidence_id", "")
            if status == "INCOMPLETE":
                if phase in ("REMEDIATION", "VERIFICATION") and ev_id != "":
                    violations.append(f"[{case_id}] INCOMPLETE {phase} step must have empty evidence_id, got '{ev_id}'")
                elif phase == "FINDING" and ev_id == "":
                    violations.append(f"[{case_id}] INCOMPLETE FINDING step must cite non-empty evidence_id")

    if violations:
        print(f"FAILED: Found {len(violations)} violations:")
        for v in violations[:30]:
            print("  -", v)
        if len(violations) > 30:
            print(f"  ... and {len(violations) - 30} more.")
        return False

    print("=======================================================")
    print("      COMPREHENSIVE OUTPUT.CSV VALIDATION: PASS")
    print("=======================================================")
    print(f"Total Rows:           {len(rows)} data rows (+ 1 header row)")
    print(f"Header:               {header}")
    print(f"Natural Sort Order:   CONFIRMED (matches deletion_requests.csv)")
    print(f"COMPLETE Cases:       {status_counts['COMPLETE']}")
    print(f"INCOMPLETE Cases:     {status_counts['INCOMPLETE']}")
    print(f"NOT_APPLICABLE Cases: {status_counts['NOT_APPLICABLE']}")
    print(f"Total Steps:          {total_steps}")
    print("=======================================================")
    return True


if __name__ == "__main__":
    success = validate_output()
    sys.exit(0 if success else 1)
