"""Adversarial stress testing and contract invariant verification for output.csv.

This module provides exhaustive, adversarial validation of the root output.csv
against all specifications in AGENTS.md §6, PROJECT.md, and dataset grounding rules.
"""

import csv
import json
import re
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_CSV = REPO_ROOT / "output.csv"
DATASET_DIR = REPO_ROOT / "dataset"
DELETION_REQUESTS = DATASET_DIR / "deletion_requests.csv"
EVIDENCE_FILES = DATASET_DIR / "evidence_files.csv"
SYSTEM_ACTIVITY = DATASET_DIR / "system_activity.csv"
USER_AUDIT_LOG = DATASET_DIR / "user_audit_log.csv"
CODE_ZIP = REPO_ROOT / "code.zip"

CANONICAL_MATRIX = {
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

PHASE_SEQUENCE = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}

REQUIRED_STEP_FIELDS = {
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
}


class TestOutputCsvAdversarialInvariants(unittest.TestCase):
    """Rigorous adversarial invariant validation suite for output.csv."""

    @classmethod
    def setUpClass(cls):
        if not OUTPUT_CSV.exists():
            raise unittest.SkipTest("output.csv does not exist yet; skipping output invariant tests.")

        # Load evidence timestamps
        cls.evidence_catalog = {}
        if EVIDENCE_FILES.exists():
            with open(EVIDENCE_FILES, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    cls.evidence_catalog[row["file_id"]] = row["captured_at"]

        if SYSTEM_ACTIVITY.exists():
            with open(SYSTEM_ACTIVITY, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    cls.evidence_catalog[row["activity_id"]] = row["event_time"]

        if USER_AUDIT_LOG.exists():
            with open(USER_AUDIT_LOG, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    cls.evidence_catalog[row["audit_id"]] = row["event_time"]

        # Load request metadata
        cls.requests_meta = {}
        if DELETION_REQUESTS.exists():
            with open(DELETION_REQUESTS, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    cls.requests_meta[row["case_id"]] = {
                        "audit_at": row["audit_at"],
                        "request_text": row["request_text"],
                        "email": row["email"],
                    }

        # Load parsed output.csv
        with open(OUTPUT_CSV, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            cls.header = next(reader)
            cls.rows = list(reader)

    def test_01_file_presence_and_byte_level_invariants(self):
        """Verify output.csv exists, has valid UTF-8 without BOM, exact line count and header."""
        self.assertTrue(OUTPUT_CSV.exists(), "output.csv must exist at repository root")
        raw_bytes = OUTPUT_CSV.read_bytes()
        self.assertFalse(raw_bytes.startswith(b"\xef\xbb\xbf"), "output.csv must NOT contain a UTF-8 BOM")

        # Check line count
        lines = raw_bytes.decode("utf-8").splitlines()
        self.assertEqual(len(lines), 519, f"output.csv must have exactly 519 lines (1 header + 518 cases), got {len(lines)}")
        self.assertEqual(lines[0].strip(), "case_id,deletion_status,steps_json")
        self.assertEqual(self.header, ["case_id", "deletion_status", "steps_json"])

        # Check for empty or whitespace-only lines
        for idx, line in enumerate(lines, start=1):
            self.assertTrue(line.strip(), f"Line {idx} in output.csv is blank or whitespace-only")

    def test_02_no_null_nan_or_undefined_tokens(self):
        """Verify no null, NaN, undefined, or None tokens exist in raw text or parsed data."""
        with open(OUTPUT_CSV, "r", encoding="utf-8") as f:
            text = f.read()

        # Adversarial token scan
        self.assertIsNone(re.search(r":\s*null\b", text), "Found literal unquoted JSON null in output.csv")
        self.assertIsNone(re.search(r":\s*NaN\b", text), "Found literal unquoted JSON NaN in output.csv")
        self.assertNotIn('"NaN"', text, 'Found string "NaN" in output.csv')
        self.assertNotIn('"undefined"', text, 'Found string "undefined" in output.csv')
        self.assertNotIn('"None"', text, 'Found string "None" in output.csv')

    def test_03_case_id_sequence_and_exact_match(self):
        """Verify 518 cases exactly match dataset/deletion_requests.csv in 1-to-1 natural sequence."""
        self.assertEqual(len(self.rows), 518, f"Expected exactly 518 rows, found {len(self.rows)}")

        expected_ids = list(self.requests_meta.keys())
        actual_ids = [r[0] for r in self.rows]

        self.assertEqual(actual_ids, expected_ids, "output.csv case_id sequence does not exactly match deletion_requests.csv")
        self.assertEqual(len(set(actual_ids)), 518, "Duplicate case_id found in output.csv")

        for cid in actual_ids:
            self.assertTrue(re.match(r"^case_\d+$", cid), f"Malformed case_id format: {cid}")

    def test_04_deletion_status_validity(self):
        """Verify deletion_status is strictly in {COMPLETE, INCOMPLETE, NOT_APPLICABLE}."""
        valid_statuses = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
        counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}

        for row in self.rows:
            status = row[1]
            self.assertIn(status, valid_statuses, f"Invalid status: '{status}' in row {row}")
            self.assertEqual(status, status.strip(), f"Status has leading/trailing whitespace: '{status}'")
            counts[status] += 1

        self.assertGreater(counts["COMPLETE"], 0, "Zero COMPLETE cases found")
        self.assertGreater(counts["INCOMPLETE"], 0, "Zero INCOMPLETE cases found")
        self.assertGreater(counts["NOT_APPLICABLE"], 0, "Zero NOT_APPLICABLE cases found")

    def test_05_not_applicable_invariants(self):
        """Verify all NOT_APPLICABLE cases have steps_json == '[]' and non-deletion intent."""
        explicit_deletion_pattern = re.compile(
            r'\b(?:permanent\s+account\s+deletion|requesting\s+deletion|deletion\s+process|account-deletion\s+request|delete\s+my\s+account)\b',
            re.I,
        )
        violations = []
        for row in self.rows:
            case_id, status, steps_str = row
            if status == "NOT_APPLICABLE":
                self.assertEqual(steps_str, "[]", f"NOT_APPLICABLE case {case_id} must have literal '[]', got {steps_str}")
                steps = json.loads(steps_str)
                self.assertEqual(steps, [], f"Parsed steps for {case_id} must be empty list")

                # Verify case text does not explicitly authorize deletion
                req_text = self.requests_meta.get(case_id, {}).get("request_text", "")
                if explicit_deletion_pattern.search(req_text):
                    violations.append(f"{case_id}: '{req_text}'")

        self.assertEqual(
            len(violations),
            0,
            f"Found {len(violations)} cases falsely classified as NOT_APPLICABLE that explicitly authorize deletion:\n"
            + "\n".join(f"  - {v}" for v in violations),
        )

    def test_06_json_parsing_and_field_exactness(self):
        """Verify all steps parse cleanly and have exactly the 7 required fields with correct types."""
        for row in self.rows:
            case_id, status, steps_str = row
            try:
                steps = json.loads(steps_str)
            except Exception as e:
                self.fail(f"Case {case_id} failed JSON parsing: {e}")

            self.assertIsInstance(steps, list, f"Case {case_id} steps_json is not a list")

            for s in steps:
                self.assertEqual(set(s.keys()), REQUIRED_STEP_FIELDS, f"Case {case_id} step {s} does not have exact 7 keys")
                self.assertIsInstance(s["step_no"], int, f"Case {case_id} step_no is not int: {s['step_no']}")
                for field in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                    self.assertIsInstance(s[field], str, f"Case {case_id} field {field} is not str: {s[field]}")
                self.assertTrue(s["system_id"].strip(), f"Case {case_id} step has empty system_id: {s}")
                self.assertTrue(s["resource_id"].strip(), f"Case {case_id} step has empty resource_id: {s}")

    def test_07_step_numbering_consecutive_1_based(self):
        """Verify step_no starts at 1 and increments by 1 consecutively for every case."""
        for row in self.rows:
            case_id, status, steps_str = row
            steps = json.loads(steps_str)
            for idx, s in enumerate(steps, start=1):
                self.assertEqual(s["step_no"], idx, f"Case {case_id} step_no mismatch: expected {idx}, got {s['step_no']}")

    def test_08_phase_progression_order(self):
        """Verify phase order is strictly FINDING -> REMEDIATION -> VERIFICATION without regression."""
        for row in self.rows:
            case_id, status, steps_str = row
            steps = json.loads(steps_str)
            last_rank = -1
            for s in steps:
                phase = s["phase"]
                self.assertIn(phase, PHASE_SEQUENCE, f"Unknown phase {phase} in case {case_id}")
                rank = PHASE_SEQUENCE[phase]
                self.assertGreaterEqual(rank, last_rank, f"Phase order violation in {case_id}: {phase} followed rank {last_rank}")
                last_rank = rank

    def test_09_operation_and_state_matrix_conformance(self):
        """Verify every operation and state strictly conforms to AGENTS.md §6.4 canonical matrix."""
        for row in self.rows:
            case_id, status, steps_str = row
            steps = json.loads(steps_str)
            for s in steps:
                phase = s["phase"]
                op = s["operation"]
                st = s["state"]
                self.assertIn(phase, CANONICAL_MATRIX, f"Invalid phase {phase} in {case_id}")
                self.assertIn(op, CANONICAL_MATRIX[phase], f"Invalid operation '{op}' for phase '{phase}' in {case_id}")
                expected_state = CANONICAL_MATRIX[phase][op]
                self.assertEqual(st, expected_state, f"Invalid state '{st}' for operation '{op}' in {case_id} (expected '{expected_state}')")

    def test_10_remediation_precedence_invariants(self):
        """Verify DISABLE_DATA_FLOW and BLOCK_RESTORE precede record changes in REMEDIATION."""
        for row in self.rows:
            case_id, status, steps_str = row
            steps = json.loads(steps_str)
            remediation_steps = [s for s in steps if s["phase"] == "REMEDIATION"]
            seen_record_op = False
            for s in remediation_steps:
                op = s["operation"]
                if op in ("DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"):
                    seen_record_op = True
                elif op in ("DISABLE_DATA_FLOW", "BLOCK_RESTORE"):
                    self.assertFalse(
                        seen_record_op,
                        f"Remediation order violation in {case_id}: '{op}' appeared after record deletion/redaction/anonymization",
                    )

    def test_11_complete_case_evidence_and_phases(self):
        """Verify COMPLETE cases only have VERIFICATION steps, all cite valid evidence captured <= audit_at."""
        for row in self.rows:
            case_id, status, steps_str = row
            if status != "COMPLETE":
                continue
            steps = json.loads(steps_str)
            self.assertGreater(len(steps), 0, f"COMPLETE case {case_id} has no steps")
            audit_at = self.requests_meta[case_id]["audit_at"]

            for s in steps:
                self.assertEqual(s["phase"], "VERIFICATION", f"COMPLETE case {case_id} has non-VERIFICATION step: {s}")
                ev_id = s.get("evidence_id", "")
                self.assertTrue(ev_id, f"COMPLETE case {case_id} step {s['step_no']} has empty evidence_id")
                self.assertIn(ev_id, self.evidence_catalog, f"COMPLETE case {case_id} cited unknown evidence_id '{ev_id}'")
                ev_time = self.evidence_catalog[ev_id]
                self.assertLessEqual(
                    ev_time,
                    audit_at,
                    f"COMPLETE case {case_id} cited evidence {ev_id} captured at {ev_time} after audit_at {audit_at}",
                )

    def test_12_incomplete_case_evidence_and_phases(self):
        """Verify INCOMPLETE cases have FINDING, REMEDIATION, VERIFICATION steps with proper evidence rules."""
        for row in self.rows:
            case_id, status, steps_str = row
            if status != "INCOMPLETE":
                continue
            steps = json.loads(steps_str)
            self.assertGreater(len(steps), 0, f"INCOMPLETE case {case_id} has no steps")
            audit_at = self.requests_meta[case_id]["audit_at"]

            findings = [s for s in steps if s["phase"] == "FINDING"]
            remediations = [s for s in steps if s["phase"] == "REMEDIATION"]
            verifications = [s for s in steps if s["phase"] == "VERIFICATION"]

            self.assertGreater(len(findings), 0, f"INCOMPLETE case {case_id} must have at least one FINDING step")
            self.assertGreater(len(remediations), 0, f"INCOMPLETE case {case_id} must have at least one REMEDIATION step")
            self.assertGreater(len(verifications), 0, f"INCOMPLETE case {case_id} must have at least one VERIFICATION step")

            for s in findings:
                ev_id = s.get("evidence_id", "")
                self.assertTrue(ev_id, f"INCOMPLETE case {case_id} FINDING step {s['step_no']} has empty evidence_id")
                self.assertIn(ev_id, self.evidence_catalog, f"INCOMPLETE case {case_id} cited unknown evidence_id '{ev_id}'")
                ev_time = self.evidence_catalog[ev_id]
                self.assertLessEqual(
                    ev_time,
                    audit_at,
                    f"INCOMPLETE case {case_id} cited evidence {ev_id} captured at {ev_time} after audit_at {audit_at}",
                )

            for s in remediations:
                self.assertEqual(
                    s.get("evidence_id"),
                    "",
                    f"INCOMPLETE case {case_id} REMEDIATION step {s['step_no']} must have empty evidence_id, got '{s.get('evidence_id')}'",
                )

            for s in verifications:
                self.assertEqual(
                    s.get("evidence_id"),
                    "",
                    f"INCOMPLETE case {case_id} VERIFICATION step {s['step_no']} must have empty evidence_id, got '{s.get('evidence_id')}'",
                )

    def test_13_submission_package_integrity(self):
        """Verify code.zip exists, is valid, and excludes prohibited files."""
        if not CODE_ZIP.exists():
            self.skipTest("code.zip not present at repo root; user handles packaging manually")
        self.assertGreater(CODE_ZIP.stat().st_size, 1000, "code.zip is unusually small")

        with zipfile.ZipFile(CODE_ZIP, "r") as z:
            names = z.namelist()
            self.assertIn("README.md", names, "code.zip missing README.md")
            self.assertTrue(any(n.startswith("code/") for n in names), "code.zip missing code/ directory")
            self.assertTrue(any(n.startswith("evaluation/") for n in names), "code.zip missing evaluation/ directory")
            self.assertTrue(any(n.startswith("tests/") for n in names), "code.zip missing tests/ directory")

            # Check prohibited files
            for n in names:
                parts = Path(n).parts
                self.assertNotIn("dataset", parts, f"code.zip contains dataset file: {n}")
                self.assertNotIn(".env", parts, f"code.zip contains .env file: {n}")
                self.assertNotIn("log.txt", parts, f"code.zip contains log.txt: {n}")
                self.assertNotIn("__pycache__", parts, f"code.zip contains __pycache__: {n}")
                self.assertNotIn(".git", parts, f"code.zip contains .git: {n}")
                self.assertFalse(n.endswith(".pyc"), f"code.zip contains .pyc: {n}")


if __name__ == "__main__":
    unittest.main()
