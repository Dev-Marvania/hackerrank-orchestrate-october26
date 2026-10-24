"""Text handover parser for tabular shift report artifacts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from ..models import EvidenceRecord
from ...config import get_logger

log = get_logger(__name__)

LINE_RE = re.compile(
    r'\d{4}-\d{2}-\d{2}T[^\|]+\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(.+)'
)


def parse_text_evidence(path: Path, file_id: str, captured_at: str) -> List[EvidenceRecord]:
    """Parse pipe-delimited handover text summaries into structured EvidenceRecords."""
    records: List[EvidenceRecord] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        log.warning(f"Failed to read text handover {path.name}: {e}")
        return records

    for line in content.splitlines():
        m = LINE_RE.search(line)
        if not m:
            continue
        sys_id, rid, rec_type, state, subj = (m.group(i).strip() for i in range(1, 6))
        emb_ids = {subj.strip().lower()} if subj else set()

        records.append(EvidenceRecord(
            file_id=file_id,
            captured_at=captured_at,
            system_id=sys_id,
            resource_id=rid,
            record_type=rec_type,
            state=state,
            raw_payload=line[:400],
            identifiers_found=emb_ids,
        ))

    return records
