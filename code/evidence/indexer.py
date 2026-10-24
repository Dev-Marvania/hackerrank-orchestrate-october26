"""Global evidence indexer and temporal query engine."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Set

from .models import EvidenceRecord
from .parsers import (
    parse_sql_evidence,
    parse_json_evidence,
    parse_log_evidence,
    parse_text_evidence,
    parse_pdf_evidence,
    parse_image_evidence,
)
from ..config import before_or_equal, get_logger

log = get_logger(__name__)


class EvidenceIndex:
    """
    Maintains an in-memory index of all pre-parsed evidence files.
    Allows rapid O(1) file-level filtering and temporal scoping per case.
    """

    def __init__(self, manifest: List[Dict[str, str]], dataset_dir: Path):
        self._index: Dict[str, List[EvidenceRecord]] = {}
        self._file_captured_at: Dict[str, str] = {}
        self._build_index(manifest, dataset_dir)

    def _build_index(self, manifest: List[Dict[str, str]], dataset_dir: Path) -> None:
        log.info(f"Indexing {len(manifest)} evidence files across dataset...")
        for item in manifest:
            fid = item["file_id"]
            rel_path = item["file_path"]
            captured_at = item["captured_at"]
            self._file_captured_at[fid] = captured_at
            full_path = dataset_dir / rel_path

            if not full_path.exists():
                log.warning(f"Manifest path missing on disk: {full_path}")
                continue

            suffix = full_path.suffix.lower()
            records: List[EvidenceRecord] = []

            if suffix == ".sql":
                records = parse_sql_evidence(full_path, fid, captured_at)
            elif suffix == ".json":
                records = parse_json_evidence(full_path, fid, captured_at)
            elif suffix == ".log":
                records = parse_log_evidence(full_path, fid, captured_at)
            elif suffix == ".txt":
                records = parse_text_evidence(full_path, fid, captured_at)
            elif suffix == ".pdf":
                records = parse_pdf_evidence(full_path, fid, captured_at)
            elif suffix == ".png":
                records = parse_image_evidence(full_path, fid, captured_at)

            self._index[fid] = records


        # Propagate resource ownership across multi-snapshot occurrences
        from collections import defaultdict
        rid_to_tokens = defaultdict(set)
        for fid, recs in self._index.items():
            for r in recs:
                if r.resource_id and r.identifiers_found:
                    rid_to_tokens[r.resource_id].update(r.identifiers_found)

        propagated = 0
        for fid, recs in self._index.items():
            for r in recs:
                if r.resource_id in rid_to_tokens:
                    before = len(r.identifiers_found)
                    r.identifiers_found.update(rid_to_tokens[r.resource_id])
                    if len(r.identifiers_found) > before:
                        propagated += 1

        total_records = sum(len(recs) for recs in self._index.values())
        log.info(f"Evidence index ready: {len(self._index)} files indexed, {total_records} records extracted (propagated {propagated} links).")

    def query_for_user(self, user_tokens: Set[str], audit_cutoff: str) -> List[EvidenceRecord]:
        """
        Return all records matching any user identifier token,
        strictly respecting the temporal boundary captured_at <= audit_cutoff.
        """
        matched: List[EvidenceRecord] = []
        for fid, records in self._index.items():
            file_cap = self._file_captured_at.get(fid, "")
            if file_cap and not before_or_equal(file_cap, audit_cutoff):
                continue
            for record in records:
                if before_or_equal(record.captured_at, audit_cutoff):
                    if record.matches_tokens(user_tokens):
                        matched.append(record)
        return matched
