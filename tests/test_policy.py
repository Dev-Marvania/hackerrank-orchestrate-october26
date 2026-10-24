"""
Unit tests for policy rules specification and deterministic solver audit reasoning.
Covers all 15 deletion policy rules, canonical state bindings, phase/op rankings,
tombstone compliance, restore risk blocking, active data flows, and non-applicable cases.
"""

from __future__ import annotations

import json
import unittest
from typing import Any, Dict, List

from code.evidence.models import EvidenceRecord
from code.policy.deterministic_solver import evaluate_case_deterministically
from code.policy.rules import (
    CANONICAL_STATES,
    FINDING_OP_RANK,
    OP_RANK_MAP,
    PHASE_RANK,
    REMEDIATION_OP_RANK,
    VALID_OPS,
    VERIFICATION_OP_RANK,
)


class TestPolicyRulesSpecification(unittest.TestCase):
    """Test policy rules invariants, canonical states, and phase hierarchy."""

    def test_canonical_states_match_contract(self) -> None:
        """Every allowed operation must map to its canonical state from AGENTS.md §6.4."""
        expected_states = {
            "REPORT_REMAINING_RECORD": "PRESENT",
            "REPORT_EXPOSED_PII": "PRESENT",
            "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
            "REPORT_RESTORE_RISK": "ACTIVE",
            "DISABLE_DATA_FLOW": "DISABLED",
            "BLOCK_RESTORE": "BLOCKED",
            "DELETE_RECORD": "ABSENT",
            "REDACT_RECORD": "REDACTED",
            "ANONYMIZE_RECORD": "ANONYMIZED",
            "VERIFY_RECORD_ABSENT": "ABSENT",
            "VERIFY_RECORD_PRESENT": "PRESENT",
            "VERIFY_RECORD_REDACTED": "REDACTED",
            "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
            "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
            "VERIFY_RESTORE_BLOCKED": "BLOCKED",
        }
        for op, expected_state in expected_states.items():
            with self.subTest(operation=op):
                self.assertIn(op, CANONICAL_STATES, f"Missing canonical state for operation: {op}")
                self.assertEqual(
                    CANONICAL_STATES[op],
                    expected_state,
                    f"Wrong canonical state for {op}: got {CANONICAL_STATES[op]}, expected {expected_state}",
                )

    def test_phase_rank_hierarchy(self) -> None:
        """Phase hierarchy must strictly be FINDING (0) -> REMEDIATION (1) -> VERIFICATION (2)."""
        self.assertLess(PHASE_RANK["FINDING"], PHASE_RANK["REMEDIATION"])
        self.assertLess(PHASE_RANK["REMEDIATION"], PHASE_RANK["VERIFICATION"])

    def test_remediation_operation_precedence(self) -> None:
        """Remediation must disable data flows and block restores before record mutations."""
        self.assertLess(REMEDIATION_OP_RANK["DISABLE_DATA_FLOW"], REMEDIATION_OP_RANK["DELETE_RECORD"])
        self.assertLess(REMEDIATION_OP_RANK["DISABLE_DATA_FLOW"], REMEDIATION_OP_RANK["REDACT_RECORD"])
        self.assertLess(REMEDIATION_OP_RANK["DISABLE_DATA_FLOW"], REMEDIATION_OP_RANK["ANONYMIZE_RECORD"])

        self.assertLess(REMEDIATION_OP_RANK["BLOCK_RESTORE"], REMEDIATION_OP_RANK["DELETE_RECORD"])
        self.assertLess(REMEDIATION_OP_RANK["BLOCK_RESTORE"], REMEDIATION_OP_RANK["REDACT_RECORD"])
        self.assertLess(REMEDIATION_OP_RANK["BLOCK_RESTORE"], REMEDIATION_OP_RANK["ANONYMIZE_RECORD"])


class TestPolicySolverRules(unittest.TestCase):
    """Test policy solver rule execution against synthetic evidence records."""

    def _eval(
        self,
        records: List[EvidenceRecord],
        request_text: str = "Please delete my account and all data.",
        case_id: str = "test_case_01",
    ) -> Dict[str, Any]:
        case = {
            "case_id": case_id,
            "request_text": request_text,
            "audit_at": "2026-10-01T00:00:00Z",
            "email": "user@example.com",
        }
        user = {
            "user_id": "user_01",
            "name": "Test User",
            "current_email": "user@example.com",
            "all_emails": {"user@example.com"},
        }
        res = evaluate_case_deterministically(case, user, records, [])
        res["steps"] = json.loads(res["steps_json"])
        return res

    def test_rule_01_user_profile_present(self) -> None:
        """Rule 01: Present USER_PROFILE must trigger REPORT_REMAINING_RECORD -> DELETE_RECORD -> VERIFY_RECORD_ABSENT."""
        rec = EvidenceRecord(
            file_id="ev_01", captured_at="2026-09-01T00:00:00Z",
            system_id="account_service", resource_id="account_001",
            record_type="USER_PROFILE", state="PRESENT",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "INCOMPLETE")
        ops = [s["operation"] for s in res["steps"]]
        self.assertIn("REPORT_REMAINING_RECORD", ops)
        self.assertIn("DELETE_RECORD", ops)
        self.assertIn("VERIFY_RECORD_ABSENT", ops)

    def test_rule_01_user_profile_absent(self) -> None:
        """Rule 01: Absent USER_PROFILE must produce VERIFY_RECORD_ABSENT with evidence ID."""
        rec = EvidenceRecord(
            file_id="ev_01", captured_at="2026-09-01T00:00:00Z",
            system_id="account_service", resource_id="account_001",
            record_type="USER_PROFILE", state="ABSENT",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "COMPLETE")
        self.assertEqual(len(res["steps"]), 1)
        step = res["steps"][0]
        self.assertEqual(step["phase"], "VERIFICATION")
        self.assertEqual(step["operation"], "VERIFY_RECORD_ABSENT")
        self.assertEqual(step["state"], "ABSENT")
        self.assertEqual(step["evidence_id"], "ev_01")

    def test_rule_03_search_index_entry(self) -> None:
        """Rule 03: Present SEARCH_INDEX_ENTRY must trigger deletion."""
        rec = EvidenceRecord(
            file_id="ev_02", captured_at="2026-09-01T00:00:00Z",
            system_id="search_service", resource_id="search_001",
            record_type="SEARCH_INDEX_ENTRY", state="PRESENT",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "INCOMPLETE")
        ops = [s["operation"] for s in res["steps"]]
        self.assertIn("REPORT_REMAINING_RECORD", ops)
        self.assertIn("DELETE_RECORD", ops)
        self.assertIn("VERIFY_RECORD_ABSENT", ops)

    def test_rule_04_cache_entry(self) -> None:
        """Rule 04: Present CACHE_ENTRY in cache_service must trigger deletion."""
        rec = EvidenceRecord(
            file_id="ev_03", captured_at="2026-09-01T00:00:00Z",
            system_id="cache_service", resource_id="cache_001",
            record_type="CACHE_ENTRY", state="PRESENT",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "INCOMPLETE")
        ops = [s["operation"] for s in res["steps"]]
        self.assertIn("REPORT_REMAINING_RECORD", ops)
        self.assertIn("DELETE_RECORD", ops)
        self.assertIn("VERIFY_RECORD_ABSENT", ops)

    def test_rule_05_support_message_shared_context(self) -> None:
        """Rule 05: Shared support conversation message requires REDACT_RECORD."""
        rec = EvidenceRecord(
            file_id="ev_04", captured_at="2026-09-01T00:00:00Z",
            system_id="support_platform", resource_id="ticket_msg_001",
            record_type="SUPPORT_MESSAGE", state="IDENTIFIABLE",
            raw_payload="conversation between user and agent",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "INCOMPLETE")
        ops = [s["operation"] for s in res["steps"]]
        self.assertIn("REPORT_EXPOSED_PII", ops)
        self.assertIn("REDACT_RECORD", ops)
        self.assertIn("VERIFY_RECORD_REDACTED", ops)

    def test_rule_06_support_attachment(self) -> None:
        """Rule 06: Support attachment belonging to subject requires DELETE_RECORD."""
        rec = EvidenceRecord(
            file_id="ev_05", captured_at="2026-09-01T00:00:00Z",
            system_id="support_platform", resource_id="attachment_505",
            record_type="SUPPORT_ATTACHMENT", state="PRESENT",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "INCOMPLETE")
        ops = [s["operation"] for s in res["steps"]]
        self.assertIn("REPORT_REMAINING_RECORD", ops)
        self.assertIn("DELETE_RECORD", ops)
        self.assertIn("VERIFY_RECORD_ABSENT", ops)

    def test_rule_07_analytics_profile_anonymization(self) -> None:
        """Rule 07: Analytics profile identifiable to user requires ANONYMIZE_RECORD."""
        rec = EvidenceRecord(
            file_id="ev_06", captured_at="2026-09-01T00:00:00Z",
            system_id="analytics_platform", resource_id="analytics_001",
            record_type="ANALYTICS_PROFILE", state="IDENTIFIABLE",
            raw_payload="event_stream_tracking",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "INCOMPLETE")
        ops = [s["operation"] for s in res["steps"]]
        self.assertIn("REPORT_EXPOSED_PII", ops)
        self.assertIn("ANONYMIZE_RECORD", ops)
        self.assertIn("VERIFY_RECORD_ANONYMIZED", ops)

    def test_rule_09_user_export(self) -> None:
        """Rule 09: User export archive must be deleted."""
        rec = EvidenceRecord(
            file_id="ev_07", captured_at="2026-09-01T00:00:00Z",
            system_id="export_service", resource_id="export_001",
            record_type="USER_EXPORT", state="PRESENT",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "INCOMPLETE")
        ops = [s["operation"] for s in res["steps"]]
        self.assertIn("REPORT_REMAINING_RECORD", ops)
        self.assertIn("DELETE_RECORD", ops)
        self.assertIn("VERIFY_RECORD_ABSENT", ops)

    def test_rule_10_marketing_profile_present(self) -> None:
        """Rule 10: Present marketing profile requires REPORT_REMAINING_RECORD -> DELETE_RECORD."""
        rec = EvidenceRecord(
            file_id="ev_08", captured_at="2026-09-01T00:00:00Z",
            system_id="analytics_platform", resource_id="marketing_001",
            record_type="MARKETING_PROFILE", state="PRESENT",
            raw_payload="email_opt_in=true;campaign=october",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "INCOMPLETE")
        ops = [s["operation"] for s in res["steps"]]
        self.assertIn("REPORT_REMAINING_RECORD", ops)
        self.assertIn("DELETE_RECORD", ops)
        self.assertIn("VERIFY_RECORD_ABSENT", ops)

    def test_rule_10_marketing_profile_absent(self) -> None:
        """Rule 10: Absent marketing profile should produce VERIFY_RECORD_ABSENT, NOT a finding."""
        rec = EvidenceRecord(
            file_id="ev_08", captured_at="2026-09-01T00:00:00Z",
            system_id="analytics_platform", resource_id="marketing_001",
            record_type="MARKETING_PROFILE", state="ABSENT",
            raw_payload="email_opt_in=false;deleted=true",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "COMPLETE")
        ops = [s["operation"] for s in res["steps"]]
        self.assertNotIn("REPORT_REMAINING_RECORD", ops)
        self.assertIn("VERIFY_RECORD_ABSENT", ops)

    def test_rule_12_security_audit_preservation(self) -> None:
        """Rule 12: Security audit records within retention must be retained (VERIFY_RECORD_PRESENT)."""
        rec = EvidenceRecord(
            file_id="ev_09", captured_at="2026-09-01T00:00:00Z",
            system_id="security_service", resource_id="audit_log_001",
            record_type="SECURITY_AUDIT_LOG", state="PRESENT",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "COMPLETE")
        ops = [s["operation"] for s in res["steps"]]
        self.assertIn("VERIFY_RECORD_PRESENT", ops)
        self.assertNotIn("DELETE_RECORD", ops)
        self.assertNotIn("REDACT_RECORD", ops)

    def test_rule_14_backup_restore_risk(self) -> None:
        """Rule 14: Active backup restore risk triggers REPORT_RESTORE_RISK -> BLOCK_RESTORE -> VERIFY_RESTORE_BLOCKED."""
        rec = EvidenceRecord(
            file_id="ev_10", captured_at="2026-09-01T00:00:00Z",
            system_id="backup_service", resource_id="backup_001",
            record_type="BACKUP_ARCHIVE", state="ACTIVE",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "INCOMPLETE")
        ops = [s["operation"] for s in res["steps"]]
        self.assertIn("REPORT_RESTORE_RISK", ops)
        self.assertIn("BLOCK_RESTORE", ops)
        self.assertIn("VERIFY_RESTORE_BLOCKED", ops)

    def test_rule_14_backup_restore_blocked(self) -> None:
        """Rule 14: Already blocked backup yields VERIFY_RESTORE_BLOCKED with evidence ID."""
        rec = EvidenceRecord(
            file_id="ev_10", captured_at="2026-09-01T00:00:00Z",
            system_id="backup_service", resource_id="backup_001",
            record_type="BACKUP_ARCHIVE", state="BLOCKED",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "COMPLETE")
        backup_step = next((s for s in res["steps"] if s["resource_id"] == "backup_001"), None)
        self.assertIsNotNone(backup_step, "backup_001 verification step missing")
        self.assertEqual(backup_step["phase"], "VERIFICATION")
        self.assertEqual(backup_step["operation"], "VERIFY_RESTORE_BLOCKED")
        self.assertEqual(backup_step["state"], "BLOCKED")
        self.assertEqual(backup_step["evidence_id"], "ev_10")

    def test_rule_15_compliant_tombstone(self) -> None:
        """Rule 15: Compliant tombstone (state=REDACTED) generates VERIFY_RECORD_REDACTED with evidence ID."""
        rec = EvidenceRecord(
            file_id="ev_11", captured_at="2026-09-01T00:00:00Z",
            system_id="identity_service", resource_id="tombstone_440",
            record_type="ACCOUNT_TOMBSTONE", state="REDACTED",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "COMPLETE")
        tomb_step = next((s for s in res["steps"] if s["resource_id"] == "tombstone_440"), None)
        self.assertIsNotNone(tomb_step, "tombstone_440 verification step missing")
        self.assertEqual(tomb_step["phase"], "VERIFICATION")
        self.assertEqual(tomb_step["operation"], "VERIFY_RECORD_REDACTED")
        self.assertEqual(tomb_step["state"], "REDACTED")
        self.assertEqual(tomb_step["evidence_id"], "ev_11")

    def test_rule_15_non_compliant_tombstone(self) -> None:
        """Rule 15: Non-compliant tombstone with residual PII generates REPORT_EXPOSED_PII -> REDACT_RECORD -> VERIFY."""
        rec = EvidenceRecord(
            file_id="ev_11", captured_at="2026-09-01T00:00:00Z",
            system_id="identity_service", resource_id="tombstone_9178",
            record_type="ACCOUNT_TOMBSTONE", state="IDENTIFIABLE",
            raw_payload="name=Kofi Addo;email=addo.kofi@gmail.com",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "INCOMPLETE")
        ops = [s["operation"] for s in res["steps"]]
        self.assertIn("REPORT_EXPOSED_PII", ops)
        self.assertIn("REDACT_RECORD", ops)
        self.assertIn("VERIFY_RECORD_REDACTED", ops)

    def test_active_sync_data_flow(self) -> None:
        """Active sync integration connector generates REPORT_ACTIVE_DATA_FLOW -> DISABLE_DATA_FLOW -> VERIFY."""
        rec = EvidenceRecord(
            file_id="ev_12", captured_at="2026-09-01T00:00:00Z",
            system_id="integration_service", resource_id="data_flow_8165",
            record_type="DATA_FLOW", state="ACTIVE",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "INCOMPLETE")
        ops = [s["operation"] for s in res["steps"]]
        self.assertIn("REPORT_ACTIVE_DATA_FLOW", ops)
        self.assertIn("DISABLE_DATA_FLOW", ops)
        self.assertIn("VERIFY_DATA_FLOW_DISABLED", ops)

    def test_disabled_sync_data_flow(self) -> None:
        """Disabled integration connector generates VERIFY_DATA_FLOW_DISABLED with evidence ID."""
        rec = EvidenceRecord(
            file_id="ev_12", captured_at="2026-09-01T00:00:00Z",
            system_id="integration_service", resource_id="data_flow_8165",
            record_type="DATA_FLOW", state="DISABLED",
        )
        res = self._eval([rec])
        self.assertEqual(res["deletion_status"], "COMPLETE")
        df_step = next((s for s in res["steps"] if s["resource_id"] == "data_flow_8165"), None)
        self.assertIsNotNone(df_step, "data_flow_8165 verification step missing")
        self.assertEqual(df_step["operation"], "VERIFY_DATA_FLOW_DISABLED")
        self.assertEqual(df_step["state"], "DISABLED")
        self.assertEqual(df_step["evidence_id"], "ev_12")

    def test_non_applicable_access_request(self) -> None:
        """Non-deletion requests must return deletion_status=NOT_APPLICABLE and steps_json='[]'."""
        rec = EvidenceRecord(
            file_id="ev_01", captured_at="2026-09-01T00:00:00Z",
            system_id="account_service", resource_id="account_001",
            record_type="USER_PROFILE", state="PRESENT",
        )
        res = self._eval([rec], request_text="Please send me a copy of all my data.")
        self.assertEqual(res["deletion_status"], "NOT_APPLICABLE")
        self.assertEqual(res["steps_json"], "[]")
        self.assertEqual(res["steps"], [])


class TestLLMClientConfiguration(unittest.TestCase):
    """Test LLM client initialization, .env loading, and Gemini provider prioritization."""

    def test_load_env_file_populates_environ(self) -> None:
        """load_env_file must safely parse repo root .env into os.environ."""
        import os
        from code.main import load_env_file
        load_env_file()
        self.assertTrue(
            "GOOGLE_API_KEY" in os.environ or "GEMINI_API_KEY" in os.environ,
            "Expected GOOGLE_API_KEY or GEMINI_API_KEY to be loaded into os.environ from .env"
        )

    def test_gemini_primary_provider_initialization(self) -> None:
        """get_llm_client must prioritize Gemini as primary provider with gemini-2.5-pro."""
        import os
        from unittest.mock import patch
        from code.main import get_llm_client

        with patch.dict(os.environ, {"GOOGLE_API_KEY": "test_fake_key_123", "ANTHROPIC_API_KEY": "test_claude_key"}):
            client, provider, model = get_llm_client()
            self.assertEqual(provider, "google", "Google Gemini must be prioritized as primary provider")
            self.assertEqual(model, "gemini-2.5-pro", "Default model should be gemini-2.5-pro")
            self.assertIsNotNone(client)
            if isinstance(client, dict):
                self.assertEqual(client.get("type"), "rest")
                self.assertEqual(client.get("api_key"), "test_fake_key_123")

    def test_fallback_to_deterministic_when_no_keys(self) -> None:
        """get_llm_client must fallback to deterministic solver when keys are cleared."""
        import os
        from unittest.mock import patch
        from code.main import get_llm_client

        with patch.dict(os.environ, {"GOOGLE_API_KEY": "", "GEMINI_API_KEY": "", "ANTHROPIC_API_KEY": ""}, clear=True):
            # Also mock load_env_file so it doesn't re-read .env
            with patch("code.main.load_env_file"):
                client, provider, model = get_llm_client()
                self.assertIsNone(client)
                self.assertEqual(provider, "deterministic")
                self.assertEqual(model, "symbolic-rule-solver")


if __name__ == "__main__":
    unittest.main()
