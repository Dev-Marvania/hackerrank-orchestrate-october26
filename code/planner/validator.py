"""Deterministic step ordering, deduplication, canonical state normalization, and validation."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from ..policy.rules import (
    CANONICAL_STATES,
    OP_RANK_MAP,
    PHASE_RANK,
    VALID_OPS,
)


def _step_sort_key(step: Dict[str, Any]) -> Tuple[int, int, str, str]:
    """Sort key tuple enforcing: Phase rank -> Operation rank -> system_id -> resource_id."""
    ph = step.get("phase", "")
    op = step.get("operation", "")
    return (
        PHASE_RANK.get(ph, 99),
        OP_RANK_MAP.get(op, 99),
        step.get("system_id", ""),
        step.get("resource_id", ""),
    )


def validate_and_order_steps(raw_steps: List[Dict[str, Any]], deletion_status: str) -> List[Dict[str, Any]]:
    """
    Apply post-inference deterministic guarantees:
    1. Filter out invalid phases or operations.
    2. Enforce canonical state for each operation.
    3. Enforce evidence_id constraints (empty for future remediation & incomplete verification).
    4. Deduplicate redundant step entries.
    5. Sort by official phase and operation precedence.
    6. Renumber step_no consecutively from 1.
    """
    valid: List[Dict[str, Any]] = []
    seen = set()

    for s in raw_steps:
        phase = s.get("phase", "").strip()
        op = s.get("operation", "").strip()
        sys_id = s.get("system_id", "").strip()
        res_id = s.get("resource_id", "").strip()
        ev_id = s.get("evidence_id", "").strip() if s.get("evidence_id") else ""

        if phase not in PHASE_RANK:
            continue
        if op not in VALID_OPS.get(phase, set()):
            continue
        if not sys_id or not res_id:
            continue

        dedup_key = (phase, op, sys_id, res_id)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        # Enforce canonical state mapping
        state = CANONICAL_STATES.get(op, s.get("state", "PRESENT"))

        # Enforce evidence_id presence rule
        if phase == "REMEDIATION":
            ev_id = ""
        elif phase == "VERIFICATION":
            if deletion_status == "INCOMPLETE":
                ev_id = ""

        valid.append({
            "phase": phase,
            "system_id": sys_id,
            "resource_id": res_id,
            "operation": op,
            "state": state,
            "evidence_id": ev_id,
        })

    # Sort strictly by the specification
    valid.sort(key=_step_sort_key)

    # Re-number consecutively from 1
    finalized: List[Dict[str, Any]] = []
    for idx, s in enumerate(valid, 1):
        finalized.append({
            "step_no": idx,
            "phase": s["phase"],
            "system_id": s["system_id"],
            "resource_id": s["resource_id"],
            "operation": s["operation"],
            "state": s["state"],
            "evidence_id": s["evidence_id"],
        })

    return finalized
