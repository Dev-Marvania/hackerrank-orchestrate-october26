"""
Unit tests for bidirectional identity resolution, multi-hop audit trail traversal,
search token extraction, and cross-subject token hygiene.
"""

from __future__ import annotations

import hashlib
import unittest
from typing import Any, Dict, List

from code.identity.resolver import IdentityIndex


class TestIdentityResolution(unittest.TestCase):
    """Test resolution of current and historical email identifiers."""

    def setUp(self) -> None:
        self.identities: List[Dict[str, str]] = [
            {
                "user_id": "user_101",
                "name": "Jane Doe",
                "email": "jane.current@example.com",
                "phone": "+1 (555) 0199",
                "email_hash": hashlib.sha256(b"jane.current@example.com").hexdigest(),
                "updated_at": "2026-05-01T12:00:00Z",
            },
            {
                "user_id": "user_102",
                "name": "Carlos Gomez",
                "email": "carlos.final@example.com",
                "phone": "+34 600 000 000",
                "email_hash": hashlib.sha256(b"carlos.final@example.com").hexdigest(),
                "updated_at": "2026-06-01T10:00:00Z",
            },
            {
                "user_id": "user_103",
                "name": "Whitespace User",
                "email": "  space.user@example.com  ",
                "phone": "   ",
                "email_hash": "   ",
                "updated_at": "2026-01-01T00:00:00Z",
            },
            {
                "user_id": "user_104",
                "name": "Cycle User",
                "email": "cycle.a@example.com",
                "phone": "+44 20 7946 0991",
                "email_hash": hashlib.sha256(b"cycle.a@example.com").hexdigest(),
                "updated_at": "2026-07-01T00:00:00Z",
            },
        ]

        self.audit_log: List[Dict[str, str]] = [
            # user_101 single-hop email update
            {
                "audit_id": "aud_01",
                "user_id": "user_101",
                "event_time": "2025-01-15T08:00:00Z",
                "field_name": "email",
                "old_value": "jane.old@example.com",
                "new_value": "jane.current@example.com",
            },
            # user_102 two-hop multi-migration: initial -> middle -> final
            {
                "audit_id": "aud_02",
                "user_id": "user_102",
                "event_time": "2024-03-01T09:00:00Z",
                "field_name": "email",
                "old_value": "carlos.initial@example.com",
                "new_value": "carlos.middle@example.com",
            },
            {
                "audit_id": "aud_03",
                "user_id": "user_102",
                "event_time": "2025-04-10T11:00:00Z",
                "field_name": "email",
                "old_value": "carlos.middle@example.com",
                "new_value": "carlos.final@example.com",
            },
            # user_101 phone update
            {
                "audit_id": "aud_04",
                "user_id": "user_101",
                "event_time": "2025-02-01T10:00:00Z",
                "field_name": "phone",
                "old_value": "+1 (555) 0100",
                "new_value": "+1 (555) 0199",
            },
            # user_104 email reversion cycle: A -> B -> A
            {
                "audit_id": "aud_05",
                "user_id": "user_104",
                "event_time": "2025-03-01T00:00:00Z",
                "field_name": "email",
                "old_value": "cycle.a@example.com",
                "new_value": "cycle.b@example.com",
            },
            {
                "audit_id": "aud_06",
                "user_id": "user_104",
                "event_time": "2025-06-01T00:00:00Z",
                "field_name": "email",
                "old_value": "cycle.b@example.com",
                "new_value": "cycle.a@example.com",
            },
            # Unknown / ghost user audit event
            {
                "audit_id": "aud_07",
                "user_id": "user_999",
                "event_time": "2025-01-01T00:00:00Z",
                "field_name": "email",
                "old_value": "ghost@example.com",
                "new_value": "ghost2@example.com",
            },
            # Unrecognized field in audit log
            {
                "audit_id": "aud_08",
                "user_id": "user_101",
                "event_time": "2025-01-01T00:00:00Z",
                "field_name": "preferences",
                "old_value": "opt_in",
                "new_value": "opt_out",
            },
            # Empty / whitespace-only audit values
            {
                "audit_id": "aud_09",
                "user_id": "user_101",
                "event_time": "2025-01-02T00:00:00Z",
                "field_name": "email",
                "old_value": "   ",
                "new_value": "",
            },
        ]

        self.index = IdentityIndex(self.identities, self.audit_log)

    def test_resolve_current_email(self) -> None:
        """Current email resolves to the primary profile."""
        profile = self.index.resolve("jane.current@example.com")
        self.assertIsNotNone(profile)
        self.assertEqual(profile["user_id"], "user_101")
        self.assertEqual(profile["name"], "Jane Doe")

    def test_resolve_historical_single_hop(self) -> None:
        """Previous email from audit log resolves to the same user."""
        profile = self.index.resolve("jane.old@example.com")
        self.assertIsNotNone(profile)
        self.assertEqual(profile["user_id"], "user_101")

    def test_resolve_multi_hop_traversal(self) -> None:
        """All intermediate email hops in a multi-hop chain resolve correctly."""
        p_initial = self.index.resolve("carlos.initial@example.com")
        p_middle = self.index.resolve("carlos.middle@example.com")
        p_final = self.index.resolve("carlos.final@example.com")

        self.assertIsNotNone(p_initial)
        self.assertIsNotNone(p_middle)
        self.assertIsNotNone(p_final)
        self.assertEqual(p_initial["user_id"], "user_102")
        self.assertEqual(p_middle["user_id"], "user_102")
        self.assertEqual(p_final["user_id"], "user_102")

    def test_resolve_alias_reversion_cycle(self) -> None:
        """Email cycle A -> B -> A allows both A and B to resolve to the user."""
        p_a = self.index.resolve("cycle.a@example.com")
        p_b = self.index.resolve("cycle.b@example.com")
        self.assertIsNotNone(p_a)
        self.assertIsNotNone(p_b)
        self.assertEqual(p_a["user_id"], "user_104")
        self.assertEqual(p_b["user_id"], "user_104")

    def test_resolve_case_insensitivity(self) -> None:
        """Resolution ignores case variation in the query email."""
        profile = self.index.resolve("JANE.CURRENT@EXAMPLE.COM")
        self.assertIsNotNone(profile)
        self.assertEqual(profile["user_id"], "user_101")

        p_hist = self.index.resolve("CaRlOs.InItIaL@ExAmPlE.cOm")
        self.assertIsNotNone(p_hist)
        self.assertEqual(p_hist["user_id"], "user_102")

    def test_resolve_whitespace_trimming(self) -> None:
        """Resolution strips leading and trailing whitespace."""
        profile = self.index.resolve("   jane.current@example.com \t \n")
        self.assertIsNotNone(profile)
        self.assertEqual(profile["user_id"], "user_101")

        p_space = self.index.resolve("space.user@example.com")
        self.assertIsNotNone(p_space)
        self.assertEqual(p_space["user_id"], "user_103")

    def test_resolve_empty_and_none(self) -> None:
        """Empty, whitespace-only, and None emails return None gracefully."""
        self.assertIsNone(self.index.resolve(""))
        self.assertIsNone(self.index.resolve("     "))
        self.assertIsNone(self.index.resolve(None))  # type: ignore

    def test_resolve_unregistered_email(self) -> None:
        """Unregistered email returns None without error."""
        self.assertIsNone(self.index.resolve("unknown.person@nowhere.com"))

    def test_audit_ghost_user_skipped(self) -> None:
        """Audit events for users not in identities snapshot are ignored."""
        self.assertIsNone(self.index.resolve("ghost@example.com"))
        self.assertIsNone(self.index.resolve("ghost2@example.com"))

    def test_audit_empty_values_skipped(self) -> None:
        """Empty or whitespace values in audit log do not pollute profile aliases."""
        user = self.index.by_uid["user_101"]
        self.assertNotIn("", user["all_emails"])
        self.assertNotIn(" ", user["all_emails"])

    def test_out_of_order_audit_events(self) -> None:
        """Reversed or shuffled audit events still aggregate all aliases into profile sets."""
        identities = [
            {
                "user_id": "user_200",
                "name": "Order Test",
                "email": "three@example.com",
                "phone": "+1 000 000 0000",
                "email_hash": "hash3",
                "updated_at": "2026-06-01T00:00:00Z",
            }
        ]
        # Chronologically out-of-order audit events
        audit_shuffled = [
            {
                "audit_id": "aud_s2",
                "user_id": "user_200",
                "event_time": "2025-06-01T00:00:00Z",
                "field_name": "email",
                "old_value": "two@example.com",
                "new_value": "three@example.com",
            },
            {
                "audit_id": "aud_s1",
                "user_id": "user_200",
                "event_time": "2025-01-01T00:00:00Z",
                "field_name": "email",
                "old_value": "one@example.com",
                "new_value": "two@example.com",
            },
        ]
        shuffled_index = IdentityIndex(identities, audit_shuffled)
        self.assertEqual(shuffled_index.resolve("one@example.com")["user_id"], "user_200")
        self.assertEqual(shuffled_index.resolve("two@example.com")["user_id"], "user_200")
        self.assertEqual(shuffled_index.resolve("three@example.com")["user_id"], "user_200")


class TestSearchTokensAndHygiene(unittest.TestCase):
    """Test search token extraction, token normalization, and cross-subject token isolation."""

    def setUp(self) -> None:
        self.identities: List[Dict[str, str]] = [
            {
                "user_id": "user_301",
                "name": "Mateo Ríos",
                "email": "mateo.rios@example.com",
                "phone": "+34 612 847 593",
                "email_hash": hashlib.sha256(b"mateo.rios@example.com").hexdigest(),
                "updated_at": "2026-01-01T00:00:00Z",
            },
            {
                "user_id": "user_302",
                "name": "Mateo Ríos",
                "email": "mateo.rios.second@example.com",
                "phone": "+54 11 4321 8765",
                "email_hash": hashlib.sha256(b"mateo.rios.second@example.com").hexdigest(),
                "updated_at": "2026-01-01T00:00:00Z",
            },
            {
                "user_id": "user_303",
                "name": "   ",
                "email": "whitespace.profile@example.com",
                "phone": "   ",
                "email_hash": "   ",
                "updated_at": "2026-01-01T00:00:00Z",
            },
        ]

        self.audit_log: List[Dict[str, str]] = [
            {
                "audit_id": "aud_30",
                "user_id": "user_301",
                "event_time": "2025-01-01T00:00:00Z",
                "field_name": "phone",
                "old_value": "+34 699 999 999",
                "new_value": "+34 612 847 593",
            },
            {
                "audit_id": "aud_31",
                "user_id": "user_301",
                "event_time": "2025-01-01T00:00:00Z",
                "field_name": "email",
                "old_value": "m.rios.old@example.com",
                "new_value": "mateo.rios@example.com",
            },
        ]

        self.index = IdentityIndex(self.identities, self.audit_log)

    def test_search_tokens_normalization(self) -> None:
        """All search tokens emitted by get_search_tokens are lowercased strings."""
        user = self.index.by_uid["user_301"]
        tokens = self.index.get_search_tokens(user)
        for tok in tokens:
            self.assertEqual(tok, tok.lower(), f"Search token not lowercased: {tok}")

    def test_search_tokens_contains_all_identities(self) -> None:
        """Search tokens include user_id, current/historical emails, phones, and hashes."""
        user = self.index.by_uid["user_301"]
        tokens = self.index.get_search_tokens(user)

        self.assertIn("user_301", tokens)
        self.assertIn("mateo.rios@example.com", tokens)
        self.assertIn("m.rios.old@example.com", tokens)
        self.assertIn("+34 612 847 593", tokens)
        self.assertIn("+34 699 999 999", tokens)
        self.assertIn(hashlib.sha256(b"mateo.rios@example.com").hexdigest(), tokens)

    def test_whitespace_profile_fields_no_empty_token(self) -> None:
        """Profile with whitespace strings in phone, email_hash, or name must NOT emit empty string tokens."""
        user = self.index.by_uid["user_303"]
        self.assertNotIn("", user["all_phones"])
        self.assertNotIn("", user["all_hashes"])
        self.assertNotIn("", user["all_names"])

        tokens = self.index.get_search_tokens(user)
        self.assertNotIn("", tokens, "Empty string found in search tokens!")

    def test_dynamic_sha256_hash_coverage(self) -> None:
        """Historical email aliases should have their SHA-256 hash covered in search tokens."""
        user = self.index.by_uid["user_301"]
        hist_email = "m.rios.old@example.com"
        expected_hash = hashlib.sha256(hist_email.encode("utf-8")).hexdigest()

        tokens = self.index.get_search_tokens(user)
        self.assertIn(expected_hash, tokens, f"Expected SHA-256 hash for historical email {hist_email} to be present in search tokens")

    def test_cross_subject_token_isolation(self) -> None:
        """Two distinct users must have strictly disjoint identifiers except for non-unique names."""
        user1 = self.index.by_uid["user_301"]
        user2 = self.index.by_uid["user_302"]

        tokens1 = self.index.get_search_tokens(user1)
        tokens2 = self.index.get_search_tokens(user2)

        # Name is shared
        shared_tokens = tokens1 & tokens2
        self.assertEqual(shared_tokens, {"mateo ríos"})

        # Crucial direct identifiers must be strictly disjoint
        self.assertTrue(user1["all_emails"].isdisjoint(user2["all_emails"]))
        self.assertTrue(user1["all_phones"].isdisjoint(user2["all_phones"]))
        self.assertTrue(user1["all_hashes"].isdisjoint(user2["all_hashes"]))
        self.assertNotEqual(user1["user_id"], user2["user_id"])


if __name__ == "__main__":
    unittest.main()
