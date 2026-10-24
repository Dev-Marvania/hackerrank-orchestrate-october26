"""Data models for structured evidence records."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Set


@dataclass(slots=True)
class EvidenceRecord:
    """Represents a discrete record extracted from an evidence file."""
    file_id: str
    captured_at: str
    system_id: str
    resource_id: str
    record_type: str
    state: str
    raw_payload: str = ""
    identifiers_found: Set[str] = field(default_factory=set)

    def matches_tokens(self, tokens: Set[str]) -> bool:
        """Return True if any of the target user tokens match this record's identifiers."""
        return bool(self.identifiers_found & tokens)
