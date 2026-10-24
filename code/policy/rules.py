"""Deletion rules, operations, canonical states, and phase hierarchy."""

from __future__ import annotations

from typing import Dict, Set

# Full 15-rule policy specification
DELETION_RULES_TEXT = """DELETION POLICY SPECIFICATION:

rule_01  USER_PROFILE           Always                                              DELETE
rule_02  SECONDARY_IDENTIFIER   Always                                              DELETE
rule_03  SEARCH_INDEX_ENTRY     Always                                              DELETE
rule_04  CACHE_ENTRY            Always                                              DELETE
rule_05  SUPPORT_MESSAGE        Shared customer/agent/order context exists          REDACT
rule_05  SUPPORT_MESSAGE        Belongs only to the deletion subject                DELETE
rule_06  SUPPORT_ATTACHMENT     Belongs only to the deletion subject                DELETE
rule_07  ANALYTICS_PROFILE      Still attributable to user                          ANONYMIZE
rule_08  PRODUCT_TELEMETRY      Still attributable to user                          ANONYMIZE
rule_09  USER_EXPORT            Always                                              DELETE
rule_10  MARKETING_PROFILE      Always                                              DELETE
rule_11  EMAIL_DELIVERY_LOG     Contains user email address                         REDACT
rule_12  SECURITY_AUDIT_LOG     Within retention period                             RETAIN
rule_13  LEGAL_HOLD_RECORD      Active legal hold                                   RETAIN
rule_14  BACKUP_ARCHIVE         Restore access can be blocked                       RETAIN + BLOCK_RESTORE
rule_15  ACCOUNT_TOMBSTONE      Account deleted, only user_id needed for references REDACT (keep user_id, strip PII)"""

# Execution hierarchy across phases
PHASE_RANK = {
    "FINDING": 0,
    "REMEDIATION": 1,
    "VERIFICATION": 2,
}

# Strictly scored operation ranking within each phase
FINDING_OP_RANK = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
}

REMEDIATION_OP_RANK = {
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
}

VERIFICATION_OP_RANK = {
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}

OP_RANK_MAP: Dict[str, int] = {
    **FINDING_OP_RANK,
    **REMEDIATION_OP_RANK,
    **VERIFICATION_OP_RANK,
}

# Invariant operation-to-state pairing
CANONICAL_STATES: Dict[str, str] = {
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

VALID_OPS: Dict[str, Set[str]] = {
    "FINDING": set(FINDING_OP_RANK.keys()),
    "REMEDIATION": set(REMEDIATION_OP_RANK.keys()),
    "VERIFICATION": set(VERIFICATION_OP_RANK.keys()),
}
