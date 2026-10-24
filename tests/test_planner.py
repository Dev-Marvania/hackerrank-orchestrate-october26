"""
Unit tests for planner step validator and sequencer.
Covers phase hierarchy (FINDING -> REMEDIATION -> VERIFICATION), remediation operation
precedence (DISABLE_DATA_FLOW and BLOCK_RESTORE before record mutations),
canonical state normalization, consecutive 1-based numbering,
evidence_id constraints, deduplication, tie-breaking, and invalid step filtering.
"""

from __future__ import annotations

import unittest
from typing import Any, Dict, List

from code.planner.validator import _step_sort_key, validate_and_order_steps


class TestPlannerStepOrdering(unittest.TestCase):
    """Test phase hierarchy, operation precedence, and tie-breaking order."""

    def test_phase_ordering(self) -> None:
        """Steps must be strictly sorted by phase: FINDING -> REMEDIATION -> VERIFICATION."""
        raw = [
            {
                "phase": "VERIFICATION", "operation": "VERIFY_RECORD_ABSENT",
                "system_id": "account_service", "resource_id": "account_01",
            },
            {
                "phase": "REMEDIATION", "operation": "DELETE_RECORD",
                "system_id": "account_service", "resource_id": "account_01",
            },
            {
                "phase": "FINDING", "operation": "REPORT_REMAINING_RECORD",
                "system_id": "account_service", "resource_id": "account_01", "evidence_id": "ev_01",
            },
        ]
        ordered = validate_and_order_steps(raw, "INCOMPLETE")
        phases = [s["phase"] for s in ordered]
        self.assertEqual(phases, ["FINDING", "REMEDIATION", "VERIFICATION"])

    def test_remediation_operation_precedence(self) -> None:
        """Remediation precedence: DISABLE_DATA_FLOW -> BLOCK_RESTORE -> DELETE -> REDACT -> ANONYMIZE."""
        raw = [
            {"phase": "REMEDIATION", "operation": "DELETE_RECORD", "system_id": "account_service", "resource_id": "res_del"},
            {"phase": "REMEDIATION", "operation": "ANONYMIZE_RECORD", "system_id": "analytics_platform", "resource_id": "res_anon"},
            {"phase": "REMEDIATION", "operation": "DISABLE_DATA_FLOW", "system_id": "integration_service", "resource_id": "res_flow"},
            {"phase": "REMEDIATION", "operation": "BLOCK_RESTORE", "system_id": "backup_service", "resource_id": "res_bk"},
            {"phase": "REMEDIATION", "operation": "REDACT_RECORD", "system_id": "support_platform", "resource_id": "res_red"},
        ]
        ordered = validate_and_order_steps(raw, "INCOMPLETE")
        ops = [s["operation"] for s in ordered]
        expected_order = [
            "DISABLE_DATA_FLOW",
            "BLOCK_RESTORE",
            "DELETE_RECORD",
            "REDACT_RECORD",
            "ANONYMIZE_RECORD",
        ]
        self.assertEqual(ops, expected_order)

    def test_tie_breaking_order(self) -> None:
        """Tie-breaking within same phase and operation: sort by system_id, then resource_id."""
        raw = [
            {"phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "support_platform", "resource_id": "res_b", "evidence_id": "ev_1"},
            {"phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "account_service", "resource_id": "res_b", "evidence_id": "ev_2"},
            {"phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "account_service", "resource_id": "res_a", "evidence_id": "ev_3"},
        ]
        ordered = validate_and_order_steps(raw, "INCOMPLETE")
        systems_and_resources = [(s["system_id"], s["resource_id"]) for s in ordered]
        expected = [
            ("account_service", "res_a"),
            ("account_service", "res_b"),
            ("support_platform", "res_b"),
        ]
        self.assertEqual(systems_and_resources, expected)


class TestPlannerNormalizationAndInvariants(unittest.TestCase):
    """Test canonical state normalization, consecutive numbering, and evidence_id invariants."""

    def test_canonical_state_normalization(self) -> None:
        """Validator normalizes arbitrary or invalid states to the official canonical state."""
        raw = [
            {"phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "s1", "resource_id": "r1", "state": "EXISTS", "evidence_id": "ev_1"},
            {"phase": "REMEDIATION", "operation": "DELETE_RECORD", "system_id": "s1", "resource_id": "r1", "state": "DELETED"},
            {"phase": "REMEDIATION", "operation": "DISABLE_DATA_FLOW", "system_id": "s2", "resource_id": "r2", "state": "STOPPED"},
            {"phase": "REMEDIATION", "operation": "BLOCK_RESTORE", "system_id": "s3", "resource_id": "r3", "state": "RESTORE_OFF"},
            {"phase": "REMEDIATION", "operation": "REDACT_RECORD", "system_id": "s4", "resource_id": "r4", "state": "MASKED"},
            {"phase": "REMEDIATION", "operation": "ANONYMIZE_RECORD", "system_id": "s5", "resource_id": "r5", "state": "HASHED"},
            {"phase": "VERIFICATION", "operation": "VERIFY_RECORD_ABSENT", "system_id": "s1", "resource_id": "r1", "state": "NOT_FOUND"},
            {"phase": "VERIFICATION", "operation": "VERIFY_RECORD_PRESENT", "system_id": "s6", "resource_id": "r6", "state": "FOUND", "evidence_id": "ev_6"},
        ]
        ordered = validate_and_order_steps(raw, "INCOMPLETE")
        state_map = {s["operation"]: s["state"] for s in ordered}

        self.assertEqual(state_map["REPORT_REMAINING_RECORD"], "PRESENT")
        self.assertEqual(state_map["DELETE_RECORD"], "ABSENT")
        self.assertEqual(state_map["DISABLE_DATA_FLOW"], "DISABLED")
        self.assertEqual(state_map["BLOCK_RESTORE"], "BLOCKED")
        self.assertEqual(state_map["REDACT_RECORD"], "REDACTED")
        self.assertEqual(state_map["ANONYMIZE_RECORD"], "ANONYMIZED")
        self.assertEqual(state_map["VERIFY_RECORD_ABSENT"], "ABSENT")
        self.assertEqual(state_map["VERIFY_RECORD_PRESENT"], "PRESENT")

    def test_consecutive_one_based_step_numbering(self) -> None:
        """Step numbers must be renumbered consecutively 1, 2, 3... regardless of input step_no."""
        raw = [
            {"step_no": 99, "phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "s1", "resource_id": "r1", "evidence_id": "ev_1"},
            {"step_no": 4, "phase": "REMEDIATION", "operation": "DELETE_RECORD", "system_id": "s1", "resource_id": "r1"},
            {"step_no": 500, "phase": "VERIFICATION", "operation": "VERIFY_RECORD_ABSENT", "system_id": "s1", "resource_id": "r1"},
        ]
        ordered = validate_and_order_steps(raw, "INCOMPLETE")
        step_nos = [s["step_no"] for s in ordered]
        self.assertEqual(step_nos, [1, 2, 3])

    def test_evidence_id_invariants_incomplete_case(self) -> None:
        """For INCOMPLETE cases, remediation and verification steps must have evidence_id=''."""
        raw = [
            {"phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "s1", "resource_id": "r1", "evidence_id": "ev_ground_truth"},
            {"phase": "REMEDIATION", "operation": "DELETE_RECORD", "system_id": "s1", "resource_id": "r1", "evidence_id": "ev_should_be_cleared"},
            {"phase": "VERIFICATION", "operation": "VERIFY_RECORD_ABSENT", "system_id": "s1", "resource_id": "r1", "evidence_id": "ev_should_be_cleared"},
        ]
        ordered = validate_and_order_steps(raw, "INCOMPLETE")
        self.assertEqual(ordered[0]["evidence_id"], "ev_ground_truth")
        self.assertEqual(ordered[1]["evidence_id"], "")
        self.assertEqual(ordered[2]["evidence_id"], "")

    def test_evidence_id_invariants_complete_case(self) -> None:
        """For COMPLETE cases, verification steps must retain their evidence_id."""
        raw = [
            {"phase": "VERIFICATION", "operation": "VERIFY_RECORD_ABSENT", "system_id": "s1", "resource_id": "r1", "evidence_id": "ev_proof_1"},
            {"phase": "VERIFICATION", "operation": "VERIFY_RESTORE_BLOCKED", "system_id": "s2", "resource_id": "r2", "evidence_id": "ev_proof_2"},
        ]
        ordered = validate_and_order_steps(raw, "COMPLETE")
        self.assertEqual(ordered[0]["evidence_id"], "ev_proof_1")
        self.assertEqual(ordered[1]["evidence_id"], "ev_proof_2")

    def test_deduplication_of_identical_steps(self) -> None:
        """Duplicate steps matching (phase, operation, system_id, resource_id) are deduplicated."""
        raw = [
            {"phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "account_service", "resource_id": "account_01", "evidence_id": "ev_1"},
            {"phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "account_service", "resource_id": "account_01", "evidence_id": "ev_1"},
            {"phase": "REMEDIATION", "operation": "DELETE_RECORD", "system_id": "account_service", "resource_id": "account_01"},
            {"phase": "REMEDIATION", "operation": "DELETE_RECORD", "system_id": "account_service", "resource_id": "account_01"},
        ]
        ordered = validate_and_order_steps(raw, "INCOMPLETE")
        self.assertEqual(len(ordered), 2)
        self.assertEqual(ordered[0]["step_no"], 1)
        self.assertEqual(ordered[1]["step_no"], 2)

    def test_invalid_step_filtering(self) -> None:
        """Steps with unrecognized phases, operations, or missing resource identifiers are filtered out."""
        raw = [
            {"phase": "UNKNOWN_PHASE", "operation": "REPORT_REMAINING_RECORD", "system_id": "s1", "resource_id": "r1"},
            {"phase": "FINDING", "operation": "INVALID_OPERATION", "system_id": "s1", "resource_id": "r1"},
            {"phase": "FINDING", "operation": "DELETE_RECORD", "system_id": "s1", "resource_id": "r1"},  # DELETE is REMEDIATION op
            {"phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "", "resource_id": "r1"},
            {"phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "s1", "resource_id": ""},
            {"phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "s1", "resource_id": "r1", "evidence_id": "ev_valid"},
        ]
        ordered = validate_and_order_steps(raw, "INCOMPLETE")
        self.assertEqual(len(ordered), 1)
        self.assertEqual(ordered[0]["resource_id"], "r1")
        self.assertEqual(ordered[0]["evidence_id"], "ev_valid")


if __name__ == "__main__":
    unittest.main()
