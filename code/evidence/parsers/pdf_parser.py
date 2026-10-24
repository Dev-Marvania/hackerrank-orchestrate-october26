"""PDF document evidence parser using PyMuPDF (fitz)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Set

from ..models import EvidenceRecord
from ...config import get_logger

log = get_logger(__name__)

RID_PATTERN = re.compile(r'\b(support_\d+|account_\d+|audit_record_\d+|ORD-\d+)\b', re.I)
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
PHONE_PATTERN = re.compile(r'\+\d{1,3}\s+\d{2,4}\s+\d{3,5}\s?\d{0,4}')
USER_PATTERN = re.compile(r'\b(user_\d+)\b', re.I)


def parse_pdf_evidence(path: Path, file_id: str, captured_at: str) -> List[EvidenceRecord]:
    """Extract discrete resource events and identifiers from PDF evidence documents."""
    records: List[EvidenceRecord] = []
    try:
        import fitz
    except ImportError:
        log.warning("fitz (PyMuPDF) not available; skipping PDF evidence parsing.")
        return records

    try:
        doc = fitz.open(path)
        full_text = "\n".join(page.get_text() for page in doc)
    except Exception as e:
        log.warning(f"Failed to read PDF evidence {path.name}: {e}")
        return records

    # Extract all identifiers in text
    emb_ids: Set[str] = set()
    for m in EMAIL_PATTERN.finditer(full_text):
        emb_ids.add(m.group(0).lower())
    for m in PHONE_PATTERN.finditer(full_text):
        emb_ids.add(m.group(0).lower())
    for m in USER_PATTERN.finditer(full_text):
        emb_ids.add(m.group(0).lower())

    # Check for customer names in structured PDF headers
    for line in full_text.splitlines():
        line_clean = line.strip()
        if line_clean.startswith("Customer ") and len(line_clean) > 9:
            emb_ids.add(line_clean[9:].strip().lower())
        m_hdr = re.match(r'^(?:Customer|Client|Name|Subject|Account Holder)(?:\s*:\s*|\s+)([A-Za-z]+(?:\s+[A-Za-z]+)+)$', line_clean, re.I)
        if m_hdr:
            emb_ids.add(m_hdr.group(1).strip().lower())

    # Determine system and record type
    lower_text = full_text.lower()
    lower_name = path.name.lower()

    if "delivery" in lower_name or "support" in lower_text or "ticket cs-" in lower_text:
        sys_id = "support_platform"
        rtype = "ATTACHMENT"
    elif "compliance" in lower_text or "security" in lower_name or "audit_record_" in lower_text:
        sys_id = "security_service"
        rtype = "AUDIT_LOG"
    elif "legal" in lower_name or "disputed" in lower_text:
        sys_id = "security_service"
        rtype = "LEGAL_HOLD"
    else:
        sys_id = "account_service"
        rtype = "STATEMENT"

    # Line by line extraction for multi-record registers
    line_records: List[tuple[str, Set[str], str]] = []
    for line in full_text.splitlines():
        line_clean = line.strip()
        m = RID_PATTERN.search(line_clean)
        if m:
            l_rid = m.group(1).replace("statement ", "").strip()
            l_ids: Set[str] = set()
            for em in EMAIL_PATTERN.finditer(line_clean):
                l_ids.add(em.group(0).lower())
            for ph in PHONE_PATTERN.finditer(line_clean):
                l_ids.add(ph.group(0).lower())
            for u in USER_PATTERN.finditer(line_clean):
                l_ids.add(u.group(0).lower())
            line_records.append((l_rid, l_ids, line_clean))

    if not line_records:
        for m in RID_PATTERN.finditer(full_text):
            val = m.group(1).replace("statement ", "").strip()
            line_records.append((val, emb_ids, full_text[:600]))

    for rid, ids, payload in line_records:
        effective_ids = ids if ids else emb_ids
        cur_sys = sys_id
        cur_type = rtype
        if rid.startswith("account_"):
            cur_sys = "account_service"
            cur_type = "USER_PROFILE"
        elif rid.startswith("audit_record_"):
            cur_sys = "security_service"
            cur_type = "SECURITY_AUDIT_LOG"
        elif rid.startswith("ORD-"):
            if "legal" in lower_name or "disputed" in lower_text or "register" in lower_text:
                cur_sys = "security_service"
                cur_type = "LEGAL_HOLD"
            else:
                continue
        elif rid.startswith("support_"):
            cur_sys = "support_platform"
            cur_type = "SUPPORT_ATTACHMENT" if ("attachment" in lower_text or "delivery" in lower_name) else "SUPPORT_MESSAGE"

        records.append(EvidenceRecord(
            file_id=file_id,
            captured_at=captured_at,
            system_id=cur_sys,
            resource_id=rid,
            record_type=cur_type,
            state="PRESENT",
            raw_payload=payload[:600] if payload else full_text[:600],
            identifiers_found=effective_ids,
        ))

    return records
