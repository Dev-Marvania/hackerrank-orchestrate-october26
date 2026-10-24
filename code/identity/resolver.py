"""Bidirectional user identity resolution and audit log replay."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Set


class IdentityIndex:
    """
    Maintains a bidirectional index of user identities.
    Replays user_audit_log to resolve current AND historical identifiers
    (emails, phone numbers, email hashes, and names).
    """

    def __init__(self, identities: List[Dict[str, str]], audit_log: List[Dict[str, str]]):
        self.by_uid: Dict[str, Dict[str, Any]] = {}
        self._email_to_uid: Dict[str, str] = {}

        # 1. Ingest current snapshot
        for row in identities:
            uid = row["user_id"]
            email_val = row.get("email", "")
            email_norm = email_val.strip().lower() if email_val and email_val.strip() else ""

            phone_val = row.get("phone", "")
            phone_norm = phone_val.strip() if phone_val and phone_val.strip() else ""

            hash_val = row.get("email_hash", "")
            hash_norm = hash_val.strip().lower() if hash_val and hash_val.strip() else ""

            name_val = row.get("name", "")
            name_norm = name_val.strip() if name_val and name_val.strip() else ""

            all_emails: Set[str] = {email_norm} if email_norm else set()
            all_phones: Set[str] = {phone_norm} if phone_norm else set()
            all_hashes: Set[str] = {hash_norm} if hash_norm else set()
            all_names: Set[str] = {name_norm} if name_norm else set()

            if email_norm:
                derived_h = hashlib.sha256(email_norm.encode("utf-8")).hexdigest()
                all_hashes.add(derived_h)

            rec: Dict[str, Any] = {
                "user_id": uid,
                "name": row.get("name", ""),
                "current_email": row.get("email", ""),
                "current_phone": row.get("phone", ""),
                "current_email_hash": row.get("email_hash", ""),
                "all_emails": all_emails,
                "all_phones": all_phones,
                "all_hashes": all_hashes,
                "all_names": all_names,
            }
            self.by_uid[uid] = rec
            if email_norm:
                self._email_to_uid[email_norm] = uid

        # 2. Replay historical identity changes from audit log
        for row in audit_log:
            uid = row.get("user_id", "")
            if uid not in self.by_uid:
                continue
            rec = self.by_uid[uid]
            field = row.get("field_name", "")
            old_val = row.get("old_value", "")
            new_val = row.get("new_value", "")

            if field == "email":
                for val in (old_val, new_val):
                    if val and val.strip():
                        norm = val.strip().lower()
                        rec["all_emails"].add(norm)
                        self._email_to_uid.setdefault(norm, uid)
                        derived_h = hashlib.sha256(norm.encode("utf-8")).hexdigest()
                        rec["all_hashes"].add(derived_h)
            elif field == "phone":
                for val in (old_val, new_val):
                    if val and val.strip():
                        rec["all_phones"].add(val.strip())
            elif field == "email_hash":
                for val in (old_val, new_val):
                    if val and val.strip():
                        rec["all_hashes"].add(val.strip().lower())
            elif field == "name":
                for val in (old_val, new_val):
                    if val and val.strip():
                        rec["all_names"].add(val.strip())

    def resolve(self, email: str) -> Optional[Dict[str, Any]]:
        """Resolve any current or historical email to the full user profile dict."""
        if not email:
            return None
        uid = self._email_to_uid.get(email.strip().lower())
        if uid and uid in self.by_uid:
            return self.by_uid[uid]
        return None

    def get_search_tokens(self, user: Dict[str, Any]) -> Set[str]:
        """Return all searchable lowercase string tokens for a user."""
        tokens: Set[str] = set()
        tokens.add(user["user_id"].lower())
        tokens.update(e for e in user["all_emails"] if e)
        tokens.update(p.lower() for p in user["all_phones"] if p)
        tokens.update(h.lower() for h in user["all_hashes"] if h)
        tokens.update(n.lower() for n in user["all_names"] if n)
        return tokens
