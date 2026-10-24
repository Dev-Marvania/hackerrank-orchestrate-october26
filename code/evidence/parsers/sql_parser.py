"""SQLite-backed parser for SQL database snapshot evidence."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import List, Set

from ..models import EvidenceRecord
from ...config import get_logger

log = get_logger(__name__)


def parse_sql_evidence(path: Path, file_id: str, captured_at: str) -> List[EvidenceRecord]:
    """Execute SQL dump inside an ephemeral SQLite database and extract all records."""
    records: List[EvidenceRecord] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        log.warning(f"Failed to read SQL file {path}: {e}")
        return records

    tmp_path = None
    conn = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name

        conn = sqlite3.connect(tmp_path)
        conn.executescript(content)
        conn.commit()

        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

        for tbl in tables:
            try:
                cols = [c[1] for c in conn.execute(f"PRAGMA table_info({tbl})").fetchall()]
                rows = conn.execute(f"SELECT * FROM {tbl}").fetchall()

                tbl_lower = tbl.lower()
                for row in rows:
                    row_dict = dict(zip(cols, row))
                    rid = row_dict.get("resource_id", "")
                    if not rid:
                        continue

                    sys_id = row_dict.get("origin_system", row_dict.get("system", ""))
                    rec_type = row_dict.get("record_type", row_dict.get("collection_name", ""))
                    state = row_dict.get("result", "PRESENT")

                    # Handle domain tables
                    if "connector_subscriptions" in tbl_lower or "connector" in tbl_lower:
                        sys_id = "integration_service"
                        rec_type = rec_type or "DATA_FLOW"
                        en = row_dict.get("enabled")
                        state = "ACTIVE" if en in (1, "1", True, "true") else "DISABLED"
                    elif "backup_restore_entries" in tbl_lower or "backup" in tbl_lower:
                        sys_id = "backup_service"
                        rec_type = rec_type or "BACKUP_ENTRY"
                        ra = row_dict.get("restore_allowed")
                        state = "ACTIVE" if ra in (1, "1", True, "true") else "BLOCKED"
                    elif "customer_exports" in tbl_lower or "export" in tbl_lower:
                        sys_id = "export_service"
                        rec_type = rec_type or "USER_EXPORT"
                        state = "PRESENT"
                    elif "customer_profiles" in tbl_lower or "account" in tbl_lower:
                        sys_id = "account_service"
                        rec_type = rec_type or "USER_PROFILE"
                        status = str(row_dict.get("account_status", "")).upper()
                        state = "PRESENT" if status in {"ACTIVE", "PENDING", "OPEN"} else "PRESENT"
                    elif "customer_search" in tbl_lower or "search" in tbl_lower:
                        sys_id = "search_service"
                        rec_type = rec_type or "SEARCH_INDEX_ENTRY"
                        state = "PRESENT"
                    elif "analytics" in tbl_lower:
                        sys_id = "analytics_platform"
                        rec_type = rec_type or "ANALYTICS_PROFILE"
                        has_pii = bool(row_dict.get("email") or row_dict.get("phone") or row_dict.get("email_hash"))
                        state = "IDENTIFIABLE" if has_pii else "ANONYMIZED"
                    elif "support" in tbl_lower:
                        sys_id = "support_platform"
                        rec_type = rec_type or "SUPPORT_MESSAGE"
                        has_pii = bool(row_dict.get("requester_email") or row_dict.get("requester_name") or row_dict.get("requester_phone"))
                        state = "IDENTIFIABLE" if has_pii else "REDACTED"
                    elif "audit" in tbl_lower or "security" in tbl_lower:
                        sys_id = "security_service"
                        rec_type = rec_type or "SECURITY_AUDIT_LOG"
                        state = "PRESENT"

                    raw = json.dumps(row_dict, default=str)

                    emb_ids: Set[str] = set()
                    rj = row_dict.get("record_json", "")
                    if rj:
                        try:
                            inner = json.loads(rj)
                            raw = json.dumps(inner, default=str)
                            sys_id = sys_id or inner.get("origin_system", "")

                            # Generic tables state inference from record_json attributes
                            if "enabled" in inner:
                                en = inner.get("enabled")
                                state = "ACTIVE" if en in (1, "1", True, "true") else "DISABLED"
                            elif "restore_allowed" in inner:
                                ra = inner.get("restore_allowed")
                                state = "ACTIVE" if ra in (1, "1", True, "true") else "BLOCKED"
                            elif sys_id == "analytics_platform" or "analytics" in rec_type.lower():
                                has_pii = bool(inner.get("email") or inner.get("phone") or inner.get("email_hash") or inner.get("user_id"))
                                state = "IDENTIFIABLE" if has_pii else "ANONYMIZED"
                            elif sys_id == "support_platform" or "support" in rec_type.lower():
                                has_pii = bool(inner.get("requester_email") or inner.get("requester_name") or inner.get("requester_phone"))
                                state = "IDENTIFIABLE" if has_pii else "REDACTED"

                            for field in ("email", "user_id", "phone", "email_hash", "full_name", "name",
                                          "customer_reference", "subject_reference", "customer_email",
                                          "requester_email", "owner_email", "owner_reference",
                                          "subject_selector", "uploaded_by"):
                                v = inner.get(field)
                                if v:
                                    emb_ids.add(str(v).strip().lower())

                            # Traverse nested document dictionary in search documents
                            doc = inner.get("document")
                            if isinstance(doc, dict):
                                for field in ("email", "user_id", "phone", "email_hash", "full_name", "name",
                                              "customer_reference", "subject_reference", "customer_email",
                                              "requester_email", "owner_email", "owner_reference",
                                              "subject_selector", "uploaded_by"):
                                    v = doc.get(field)
                                    if v:
                                        emb_ids.add(str(v).strip().lower())
                        except Exception:
                            pass

                    for field in ("subject_reference", "owner_email", "owner_reference",
                                  "customer_reference", "customer_email", "requester_email",
                                  "user_id", "email", "phone", "full_name", "name",
                                  "subject_selector", "uploaded_by"):
                        v = row_dict.get(field)
                        if v:
                            emb_ids.add(str(v).strip().lower())

                    if not sys_id:
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

                    records.append(EvidenceRecord(
                        file_id=file_id,
                        captured_at=captured_at,
                        system_id=sys_id,
                        resource_id=rid,
                        record_type=rec_type,
                        state=state,
                        raw_payload=raw[:600],
                        identifiers_found=emb_ids,
                    ))
            except Exception as e:
                log.debug(f"Error reading table {tbl} in {path.name}: {e}")

    except Exception as e:
        log.warning(f"Error parsing SQL snapshot {path.name}: {e}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    return records
