"""Recursive parser for JSON snapshot bundles and export jobs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Set

from ..models import EvidenceRecord
from ...config import get_logger

log = get_logger(__name__)


def parse_json_evidence(path: Path, file_id: str, captured_at: str) -> List[EvidenceRecord]:
    """Parse JSON snapshot bundles or export records into flat EvidenceRecord objects."""
    records: List[EvidenceRecord] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
    except Exception as e:
        log.warning(f"Failed to read/parse JSON evidence {path.name}: {e}")
        return records

    candidates: List[Dict[str, Any]] = []
    if isinstance(data, dict) and "service_exports" in data:
        for svc_name, svc_data in data["service_exports"].items():
            if isinstance(svc_data, dict):
                for subkey, items in svc_data.items():
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict):
                                item_copy = dict(item)
                                item_copy["system"] = svc_name
                                item_copy["record_type"] = subkey

                                # State determination based on service type
                                if svc_name == "account_service":
                                    sc = item.get("status_code")
                                    item_copy["state"] = "ABSENT" if sc == 404 else "PRESENT"
                                elif svc_name == "backup_service":
                                    allowed = item.get("restore_allowed", False)
                                    item_copy["state"] = "ACTIVE" if allowed else "BLOCKED"
                                elif svc_name == "integration_service":
                                    en = item.get("enabled", False)
                                    item_copy["state"] = "ACTIVE" if en else "DISABLED"
                                elif svc_name == "search_service":
                                    hits = item.get("hits", {})
                                    tot = hits.get("total", 0) if isinstance(hits, dict) else 0
                                    item_copy["state"] = "PRESENT" if tot > 0 else "ABSENT"
                                elif svc_name == "security_service":
                                    item_copy["state"] = "PRESENT"
                                elif svc_name == "analytics_platform":
                                    has_pii = bool(item.get("email") or item.get("phone") or item.get("email_hash"))
                                    item_copy["state"] = "IDENTIFIABLE" if has_pii else "ANONYMIZED"
                                elif svc_name == "support_platform":
                                    has_pii = bool(item.get("requester_email") or item.get("requester_name") or item.get("requester_phone"))
                                    item_copy["state"] = "IDENTIFIABLE" if has_pii else "REDACTED"

                                candidates.append(item_copy)
    elif isinstance(data, list):
        candidates = data
    elif isinstance(data, dict):
        if "snapshots" in data and isinstance(data["snapshots"], list):
            for snap in data["snapshots"]:
                if isinstance(snap, dict):
                    ds = snap.get("data_store", "")
                    col = snap.get("collection", "")
                    snap_ts = snap.get("captured_at") or snap.get("timestamp") or captured_at
                    snap_recs = snap.get("records", [])
                    if isinstance(snap_recs, list):
                        for sr in snap_recs:
                            if isinstance(sr, dict):
                                sr_copy = dict(sr)
                                sr_copy.setdefault("data_store", ds)
                                sr_copy.setdefault("system", ds)
                                sr_copy.setdefault("collection", col)
                                sr_copy.setdefault("record_type", col)
                                sr_copy.setdefault("captured_at", snap_ts)
                                if ds == "identity_service":
                                    has_pii = bool(sr.get("name") or sr.get("email") or sr.get("phone") or sr.get("email_hash"))
                                    sr_copy["state"] = "IDENTIFIABLE" if has_pii else "REDACTED"
                                elif ds == "security_service":
                                    sr_copy["state"] = "PRESENT"
                                candidates.append(sr_copy)
        else:
            col = data.get("collection", "")
            for key in ("records", "entries", "data", "items"):
                val = data.get(key)
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            item_copy = dict(item)
                            item_copy.setdefault("collection", col)
                            candidates.append(item_copy)
                    break
            else:
                candidates = [data]

    for rec in candidates:
        if not isinstance(rec, dict):
            continue
        rid = rec.get("resource_id", "")
        if not rid:
            continue

        sys_id = (rec.get("system") or rec.get("origin_system") or
                  rec.get("data_store") or "")
        rec_type = rec.get("record_type") or rec.get("collection") or ""
        state = rec.get("result") or rec.get("state") or "PRESENT"

        # Infer system_id and state from resource_id prefix or attributes
        if not sys_id:
            if rid.startswith("export_"):
                sys_id = "export_service"
                rec_type = rec_type or "USER_EXPORT"
                da = rec.get("download_available")
                state = "PRESENT" if da is not False else "ABSENT"
            elif rid.startswith("account_"):
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
            elif rid.startswith("tombstone_"):
                sys_id = "identity_service"

        if sys_id == "analytics_platform" or rid.startswith("analytics_") or "analytics" in rec_type.lower():
            sys_id = "analytics_platform"
            has_pii = bool(rec.get("email") or rec.get("phone") or rec.get("email_hash") or rec.get("user_id"))
            if not has_pii:
                state = "ANONYMIZED"
            elif "state" not in rec and "result" not in rec:
                state = "IDENTIFIABLE"

        emb_ids: Set[str] = set()
        for field in ("email", "user_id", "phone", "email_hash",
                      "customer_reference", "subject_reference",
                      "owner_email", "owner_reference", "customer_email",
                      "query", "requester_email"):
            v = rec.get(field)
            if v:
                emb_ids.add(str(v).strip().lower())

        # Check nested profile
        prof = rec.get("profile")
        if isinstance(prof, dict):
            for k in ("email", "phone", "customer_reference", "email_hash"):
                pv = prof.get(k)
                if pv:
                    emb_ids.add(str(pv).strip().lower())

        # Check nested documents under hits
        hits = rec.get("hits")
        if isinstance(hits, dict):
            docs = hits.get("documents", [])
            if isinstance(docs, list):
                for doc in docs:
                    if isinstance(doc, dict):
                        for k in ("email", "phone", "customer_reference", "email_hash"):
                            dv = doc.get(k)
                            if dv:
                                emb_ids.add(str(dv).strip().lower())

        rec_captured_at = rec.get("captured_at") or rec.get("timestamp") or captured_at
        records.append(EvidenceRecord(
            file_id=file_id,
            captured_at=rec_captured_at,
            system_id=sys_id,
            resource_id=rid,
            record_type=rec_type,
            state=state,
            raw_payload=json.dumps(rec, default=str)[:600],
            identifiers_found=emb_ids,
        ))

    return records
