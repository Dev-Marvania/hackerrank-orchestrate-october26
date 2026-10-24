"""Image / screenshot evidence parser with graceful OCR fallback."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Set

from ..models import EvidenceRecord
from ...config import get_logger

log = get_logger(__name__)

RID_PATTERN = re.compile(r'\b(account_\d+|search_\d+|analytics_\d+|support_\d+|data_flow_\d+|backup_\d+|audit_record_\d+|export_\d+|tombstone_\d+)\b', re.I)
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
PHONE_PATTERN = re.compile(r'\+\d{1,3}\s+\d{2,4}\s+\d{3,5}\s?\d{0,4}')
USER_PATTERN = re.compile(r'\b(user_\d+)\b', re.I)


def parse_image_evidence(path: Path, file_id: str, captured_at: str) -> List[EvidenceRecord]:
    """
    Extract discrete resource events and identifiers from PNG screenshots.
    Gracefully falls back to an empty list if pytesseract / OCR binaries are unavailable.
    """
    records: List[EvidenceRecord] = []
    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        log.debug(f"pytesseract/PIL not available; skipping OCR for {path.name}")
        return records

    try:
        img = Image.open(path)
        full_text = pytesseract.image_to_string(img)
    except Exception as e:
        log.debug(f"OCR execution skipped or failed for {path.name}: {e}")
        return records

    if not full_text or not full_text.strip():
        return records

    emb_ids: Set[str] = set()
    for m in EMAIL_PATTERN.finditer(full_text):
        emb_ids.add(m.group(0).lower())
    for m in PHONE_PATTERN.finditer(full_text):
        emb_ids.add(m.group(0).lower())
    for m in USER_PATTERN.finditer(full_text):
        emb_ids.add(m.group(0).lower())

    text_lower = full_text.lower()
    for m in RID_PATTERN.finditer(full_text):
        rid = m.group(1)
        sys_id = ""
        if rid.startswith("account_"):
            sys_id = "account_service"
        elif rid.startswith("search_"):
            sys_id = "search_service"
        elif rid.startswith("analytics_"):
            sys_id = "analytics_platform"
        elif rid.startswith("support_"):
            sys_id = "support_platform"
        elif rid.startswith("data_flow_"):
            sys_id = "integration_service"
        elif rid.startswith("backup_"):
            sys_id = "backup_service"
        elif rid.startswith("audit_record_"):
            sys_id = "security_service"
        elif rid.startswith("export_"):
            sys_id = "export_service"
        elif rid.startswith("tombstone_"):
            sys_id = "identity_service"

        state = "PRESENT"
        if "404" in text_lower or "not found" in text_lower or "deleted" in text_lower:
            state = "ABSENT"
        elif "anonymized" in text_lower or "redacted" in text_lower:
            state = "ANONYMIZED" if sys_id == "analytics_platform" else "REDACTED"
        elif "blocked" in text_lower or "disabled" in text_lower:
            state = "BLOCKED" if sys_id == "backup_service" else "DISABLED"

        records.append(EvidenceRecord(
            file_id=file_id,
            captured_at=captured_at,
            system_id=sys_id,
            resource_id=rid,
            record_type="SCREENSHOT_CAPTURE",
            state=state,
            raw_payload=full_text[:600],
            identifiers_found=emb_ids,
        ))

    return records
