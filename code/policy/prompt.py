"""Prompt construction, formatting, and LLM response parsing."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .rules import DELETION_RULES_TEXT
from ..evidence.models import EvidenceRecord

SYSTEM_PROMPT = """\
You are an expert deletion-audit AI agent for Northstar Shop.
Your goal is to inspect a data subject's deletion request against ground-truth evidence at audit_at.
Determine if the deletion is COMPLETE, INCOMPLETE, or NOT_APPLICABLE.
Produce only a valid JSON object without surrounding markdown codeblocks or conversational text.
"""

USER_PROMPT_TEMPLATE = """\
## CASE TO AUDIT
case_id:         {case_id}
email:           {email}
requested_at:    {requested_at}
reported_status: {reported_status}  (Claim from existing workflow, not proof)
audit_at:        {audit_at}
request_text:    {request_text}

## USER PROFILE (Current + Historical Aliases)
user_id:         {user_id}
all_emails:      {all_emails}
all_phones:      {all_phones}
all_names:       {all_names}

## MATCHED EVIDENCE (Captured <= audit_at)
{evidence_block}

## RELEVANT OPERATIONAL ACTIVITY
{activity_block}

## POLICY RULES
{deletion_rules}

## OUTPUT JSON SCHEMA
{{
  "deletion_status": "COMPLETE|INCOMPLETE|NOT_APPLICABLE",
  "reasoning": "Concise 1-2 sentence rationale",
  "steps": [
    {{
      "phase": "FINDING|REMEDIATION|VERIFICATION",
      "system_id": "exact system identifier",
      "resource_id": "exact resource identifier from evidence",
      "operation": "exact operation name",
      "state": "exact canonical state",
      "evidence_id": "file_id or activity_id or empty string"
    }}
  ]
}}

## CONSTRAINTS
1. Non-deletion requests (access, export, opt-out) -> NOT_APPLICABLE with steps: [].
2. COMPLETE -> Only VERIFICATION steps citing real evidence_ids proving the compliant state.
3. INCOMPLETE -> FINDING (citing real evidence_id) + REMEDIATION (evidence_id: "") + VERIFICATION (evidence_id: "").
4. Always verify that security_service audit records are RETAINED (VERIFY_RECORD_PRESENT).
5. Always verify account_service profile absence if deleted.
6. DISABLE_DATA_FLOW must precede any record deletion or redaction.
7. Use ONLY resource_ids that appear in the evidence block above. Do not invent identifiers.
"""


def format_evidence_block(records: List[EvidenceRecord]) -> str:
    """Format structured evidence records into an unambiguous prompt block."""
    if not records:
        return "  (No matching records found in evidence captured <= audit_at)"

    lines = []
    seen = set()
    for rec in records:
        key = (rec.file_id, rec.resource_id)
        if key in seen:
            continue
        seen.add(key)
        lines.append(
            f"  file_id={rec.file_id} | captured={rec.captured_at} | "
            f"system_id={rec.system_id} | resource_id={rec.resource_id} | "
            f"type={rec.record_type} | state={rec.state}"
        )
        if rec.raw_payload:
            lines.append(f"    payload: {rec.raw_payload[:300]}")
    return "\n".join(lines)


def format_activity_block(activity: List[Dict[str, str]]) -> str:
    """Format system activity logs for context."""
    if not activity:
        return "  (No relevant activity logged before audit_at)"
    lines = []
    for row in activity[:30]:
        lines.append(
            f"  [{row.get('activity_id', '')}] {row.get('event_time', '')} | "
            f"{row.get('event_type', '')} | {row.get('source_system', '')} -> {row.get('target_system', '')} | "
            f"resource={row.get('resource_id', '')} | result={row.get('reported_result', '')} | "
            f"{row.get('details', '')[:100]}"
        )
    return "\n".join(lines)


def build_analysis_prompt(case: Dict[str, str], user: Dict[str, Any],
                          evidence: List[EvidenceRecord], activity: List[Dict[str, str]]) -> str:
    """Construct the complete prompt for LLM evaluation."""
    return USER_PROMPT_TEMPLATE.format(
        case_id=case["case_id"],
        email=case["email"],
        requested_at=case["requested_at"],
        reported_status=case.get("reported_status", "UNKNOWN"),
        audit_at=case["audit_at"],
        request_text=case.get("request_text", ""),
        user_id=user["user_id"] if user else "UNKNOWN",
        all_emails=", ".join(sorted(user["all_emails"])) if user else case["email"],
        all_phones=", ".join(sorted(user["all_phones"])) if user else "",
        all_names=", ".join(sorted(user["all_names"])) if user else "",
        evidence_block=format_evidence_block(evidence),
        activity_block=format_activity_block(activity),
        deletion_rules=DELETION_RULES_TEXT,
    )


def parse_llm_json(raw_text: str) -> Dict[str, Any]:
    """Robustly extract and decode JSON payload from LLM responses."""
    text = raw_text.strip()
    text = re.sub(r'^```(?:json)?\s*', '', text)
    text = re.sub(r'\s*```$', '', text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r'\{[\s\S]*\}', text)
        if m:
            try:
                return json.loads(m.group())
            except Exception:
                pass
    return {"deletion_status": "INCOMPLETE", "steps": [], "reasoning": "JSON decode failed"}
