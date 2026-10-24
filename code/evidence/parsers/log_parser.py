"""Log stream parser for structured key-value log lines with trace-id correlation."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ..models import EvidenceRecord
from ...config import get_logger

log = get_logger(__name__)

RID_PATTERN = re.compile(r'(?:resource_id=|\"resource_id\":\s*)(?:\\*")?([^"\\\s,}]+)(?:\\*")?')
SVC_PATTERN = re.compile(r'(?:service=|\"service\":\s*)(?:\\*")?([^"\\\s,}]+)(?:\\*")?')

TRACE_PATTERNS = [
    re.compile(r'(?:(?:trace_id|requestId)=(?:\\*")?|"(?:trace_id|requestId)":\s*(?:\\*")?)([^"\\\s,}]+)'),
    re.compile(r'\[(tr-[^\]\s]+)\]'),
    re.compile(r'\|\s*(tr-[^\|\s]+)\s*\|'),
    re.compile(r'<\d+>1\s+\S+\s+\S+\s+([^"\\\s]+)'),
    re.compile(r'\b(tr-[a-zA-Z0-9_-]+|rb-[a-zA-Z0-9_-]+)\b'),
]


class _TracePatternWrapper:
    def search(self, line: str):
        for rx in TRACE_PATTERNS:
            m = rx.search(line)
            if m:
                val = m.group(1).strip('"\\').strip()
                if val:
                    return _MatchResult(val)
        return None


class _MatchResult:
    __slots__ = ("_val",)

    def __init__(self, val: str):
        self._val = val

    def group(self, idx: int = 1) -> str:
        return self._val


TRACE_PATTERN = _TracePatternWrapper()
EVENT_PATTERN = re.compile(r'(?:event|result)=(?:\\*")?([^"\\\s,]+)(?:\\*")?')
CORR_PATTERN = re.compile(
    r'(?:correlation_key|lookup_key|match_key|subject_key|subject_ref|'
    r'scan_key|matched_value|subject_reference)(?:=|\":\s*)(?:\\*")?([^"\\\s,}]+)(?:\\*")?'
)
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')

SERVICE_MAP = {
    "support_replica": "support_platform",
    "search_index_service": "search_service",
    "attachment_preview": "support_platform",
    "customer_account_service": "account_service",
}


def _extract_line_json(line: str) -> Optional[Dict[str, Any]]:
    idx = line.find('{')
    if idx != -1 and '}' in line:
        try:
            return json.loads(line[idx:])
        except Exception:
            return None
    return None


def parse_log_evidence(path: Path, file_id: str, captured_at: str) -> List[EvidenceRecord]:
    """Extract discrete resource events from structured log streams with trace correlation."""
    records: List[EvidenceRecord] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        log.warning(f"Failed to read log evidence {path.name}: {e}")
        return records

    lines = content.splitlines()

    # Pass 1: Build trace_id correlation tables
    trace_to_ids: Dict[str, Set[str]] = defaultdict(set)
    trace_to_rids: Dict[str, Set[str]] = defaultdict(set)
    for line in lines:
        json_obj = _extract_line_json(line)
        tr = None
        if json_obj:
            tr = json_obj.get("trace_id") or json_obj.get("requestId")
        if not tr:
            tr_m = TRACE_PATTERN.search(line)
            if tr_m:
                tr = tr_m.group(1).strip('"')
        if not tr:
            continue

        if json_obj:
            for k in ("correlation_key", "lookup_key", "match_key", "subject_key", "subject_ref",
                      "scan_key", "matched_value", "subject_reference"):
                val = json_obj.get(k)
                if val:
                    trace_to_ids[tr].add(str(val).strip().lower())
            for val in json_obj.values():
                if isinstance(val, str):
                    for m in EMAIL_PATTERN.finditer(val):
                        trace_to_ids[tr].add(m.group(0).lower())
            rid = json_obj.get("resource_id")
            if rid:
                rid_clean = str(rid).strip().strip('"\\')
                if rid_clean and rid_clean not in {'\\', '/'}:
                    trace_to_rids[tr].add(rid_clean)
        else:
            for m in CORR_PATTERN.finditer(line):
                val = m.group(1).strip('"\\').strip().lower()
                if val:
                    trace_to_ids[tr].add(val)
            for m in EMAIL_PATTERN.finditer(line):
                val = m.group(0).strip().lower()
                if val:
                    trace_to_ids[tr].add(val)
            rid_m = RID_PATTERN.search(line)
            if rid_m:
                rid = rid_m.group(1).strip('"\\').strip()
                if rid and rid not in {'\\', '/'}:
                    trace_to_rids[tr].add(rid)

    # Pass 2: Extract evidence records
    for line in lines:
        json_obj = _extract_line_json(line)
        tr = None
        if json_obj:
            tr = json_obj.get("trace_id") or json_obj.get("requestId")
        if not tr:
            tr_m = TRACE_PATTERN.search(line)
            if tr_m:
                tr = tr_m.group(1).strip('"')

        rid = ""
        if json_obj and json_obj.get("resource_id"):
            rid = str(json_obj["resource_id"]).strip().strip('"\\')
        if not rid:
            rid_m = RID_PATTERN.search(line)
            if rid_m:
                rid = rid_m.group(1).strip('"\\').strip()

        if not rid or rid in {'\\', '/'}:
            continue

        svc = ""
        if json_obj and json_obj.get("service"):
            raw_svc = str(json_obj["service"]).strip().strip('"\\')
            svc = SERVICE_MAP.get(raw_svc, raw_svc)
        if not svc:
            svc_m = SVC_PATTERN.search(line)
            raw_svc = svc_m.group(1).strip('"\\').strip() if svc_m else ""
            svc = SERVICE_MAP.get(raw_svc, raw_svc)

        # Infer service from resource prefix if unknown
        if not svc or svc not in {"account_service", "search_service", "analytics_platform",
                                  "support_platform", "integration_service", "backup_service",
                                  "identity_service", "security_service", "export_service", "cache_service"}:
            if rid.startswith("account_"):
                svc = "account_service"
            elif rid.startswith("search_"):
                svc = "search_service"
            elif rid.startswith("analytics_"):
                svc = "analytics_platform"
            elif rid.startswith("support_"):
                svc = "support_platform"
            elif rid.startswith("data_flow_"):
                svc = "integration_service"
            elif rid.startswith("backup_"):
                svc = "backup_service"
            elif rid.startswith("audit_record_"):
                svc = "security_service"
            elif rid.startswith("export_"):
                svc = "export_service"
            elif rid.startswith("tombstone_"):
                svc = "identity_service"
            elif rid.startswith("cache_"):
                svc = "cache_service"

        # Determine semantic state
        state = "PRESENT"
        if json_obj:
            res_val = str(json_obj.get("result", "")).lower()
            rows_val = str(json_obj.get("rows", "")).lower()
            status_val = str(json_obj.get("http_status", "")).lower()
            enabled_val = json_obj.get("enabled")
            restore_val = json_obj.get("restore_allowed")

            if res_val == "hit" or rows_val == "1" or status_val == "200":
                state = "PRESENT"
            elif res_val == "miss" or rows_val == "0" or status_val == "404":
                state = "ABSENT"
            elif enabled_val is True or str(enabled_val).lower() == "true":
                state = "ACTIVE"
            elif enabled_val is False or str(enabled_val).lower() == "false":
                state = "DISABLED"
            elif restore_val is False or str(restore_val).lower() == "false":
                state = "BLOCKED"
            elif restore_val is True or str(restore_val).lower() == "true":
                state = "ACTIVE"
            else:
                ev_val = str(json_obj.get("event", ""))
                if ev_val.lower() == "hit":
                    state = "PRESENT"
                elif ev_val.lower() == "miss":
                    state = "ABSENT"
                elif ev_val in {"profile_lookup_completed", "index_query_completed"}:
                    state = "PRESENT"
                elif ev_val:
                    state = ev_val
        else:
            if re.search(r'\b(?:result=[\"\']?hit[\"\']?|rows=[\"\']?1[\"\']?|http_status=[\"\']?200[\"\']?)\b', line, re.I):
                state = "PRESENT"
            elif re.search(r'\b(?:result=[\"\']?miss[\"\']?|rows=[\"\']?0[\"\']?|http_status=[\"\']?404[\"\']?)\b', line, re.I):
                state = "ABSENT"
            elif re.search(r'\b(?:enabled=[\"\']?true[\"\']?|restore_allowed=[\"\']?true[\"\']?|deletion_block=[\"\']?false[\"\']?)\b', line, re.I):
                state = "ACTIVE"
            elif re.search(r'\b(?:enabled=[\"\']?false[\"\']?)\b', line, re.I):
                state = "DISABLED"
            elif re.search(r'\b(?:restore_allowed=[\"\']?false[\"\']?|deletion_block=[\"\']?true[\"\']?)\b', line, re.I):
                state = "BLOCKED"
            elif "requester_email=null" in line and "requester_phone=null" in line:
                state = "REDACTED"
            elif "email=null" in line and "phone=null" in line and "email_hash=null" in line:
                state = "ANONYMIZED"
            elif ("requester_email=" in line and "requester_email=null" not in line) or \
                 ("email=" in line and "email=null" not in line and "email_hash" not in line):
                state = "IDENTIFIABLE"
            elif "message_pii_scan" in line or "attachment_pii_scan" in line or "matched_value=" in line:
                state = "IDENTIFIABLE"
            elif rid.startswith("audit_record_") or "audit_record_" in line:
                state = "PRESENT"
            elif "marker_found=false" in line:
                state = "PRESENT"
            else:
                ev_m = EVENT_PATTERN.search(line)
                if ev_m:
                    ev_val = ev_m.group(1).strip('"')
                    if ev_val.lower() == "hit":
                        state = "PRESENT"
                    elif ev_val.lower() == "miss":
                        state = "ABSENT"
                    elif ev_val in {"profile_lookup_completed", "index_query_completed"}:
                        state = "PRESENT"
                    else:
                        state = ev_val

        # Collect embedded and correlated identifiers
        emb_ids: Set[str] = set()
        if tr:
            emb_ids.update(trace_to_ids.get(tr, set()))
        if json_obj:
            for k in ("correlation_key", "lookup_key", "match_key", "subject_key", "subject_ref",
                      "scan_key", "matched_value", "subject_reference"):
                val = json_obj.get(k)
                if val:
                    emb_ids.add(str(val).strip().lower())
            for val in json_obj.values():
                if isinstance(val, str):
                    for m in EMAIL_PATTERN.finditer(val):
                        emb_ids.add(m.group(0).lower())
        else:
            for m in CORR_PATTERN.finditer(line):
                val = m.group(1).strip('"\\').strip().lower()
                if val:
                    emb_ids.add(val)
            for m in EMAIL_PATTERN.finditer(line):
                val = m.group(0).strip().lower()
                if val:
                    emb_ids.add(val)

        records.append(EvidenceRecord(
            file_id=file_id,
            captured_at=captured_at,
            system_id=svc,
            resource_id=rid,
            record_type="",
            state=state,
            raw_payload=line[:400],
            identifiers_found=emb_ids,
        ))

    return records
