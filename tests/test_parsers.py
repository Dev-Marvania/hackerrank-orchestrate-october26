"""
Unit tests for evidence parsers and EvidenceIndex temporal engine.
Covers SQL snapshots, log streams, JSON bundles, text handovers, PDF documents,
replication drift, escaped quotes, JSON-lines, trace correlation, and temporal boundaries.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from code.evidence.indexer import EvidenceIndex
from code.evidence.models import EvidenceRecord
from code.evidence.parsers.json_parser import parse_json_evidence
from code.evidence.parsers.log_parser import parse_log_evidence
from code.evidence.parsers.pdf_parser import parse_pdf_evidence
from code.evidence.parsers.sql_parser import parse_sql_evidence
from code.evidence.parsers.text_parser import parse_text_evidence


class TestLogParser(unittest.TestCase):
    """Test suite for structured log stream parsing and trace correlation."""

    def test_log_parser_escaped_quotes_no_backslash(self) -> None:
        """EC-01: Ensure resource_id inside escaped quotes does not extract backslash."""
        content = (
            '2026-06-08T06:52:09Z requestId=tr-1108860 level=INFO '
            'message="instance=\\"search-3\\" resource_id=\\"search_1234\\""\n'
        )
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write(content)
            p = Path(f.name)
        try:
            recs = parse_log_evidence(p, "ev_log", "2026-10-01T00:00:00Z")
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0].resource_id, "search_1234")
            self.assertNotEqual(recs[0].resource_id, "\\", "Corrupted backslash extracted as resource_id!")
        finally:
            if p.exists():
                os.unlink(p)

    def test_log_parser_json_lines(self) -> None:
        """EC-02: Ensure JSON-lines logs are parsed with correct service, RID, and trace correlation."""
        content = (
            '2026-04-19T06:51:13Z {"service":"search_service","trace_id":"tr-7722221",'
            '"event":"index_query_started","match_key":"dubois.ines94@icloud.com"}\n'
            '2026-04-19T06:51:21Z {"service":"search_service","trace_id":"tr-7722221",'
            '"resource_id":"search_9365","event":"index_query_completed","result":"hit"}\n'
        )
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write(content)
            p = Path(f.name)
        try:
            recs = parse_log_evidence(p, "ev_json_log", "2026-10-01T00:00:00Z")
            self.assertGreaterEqual(len(recs), 1, "Failed to parse any records from JSON-lines log")
            search_rec = next((r for r in recs if r.resource_id == "search_9365"), None)
            self.assertIsNotNone(search_rec, "Record search_9365 not found in parsed JSON-lines log")
            self.assertEqual(search_rec.system_id, "search_service")
            self.assertEqual(search_rec.state, "PRESENT")
            self.assertIn("dubois.ines94@icloud.com", search_rec.identifiers_found)
        finally:
            if p.exists():
                os.unlink(p)

    def test_log_parser_bracketed_trace_correlation(self) -> None:
        """EC-03: Ensure [tr-XXXX] bracketed trace correlation links email to RID."""
        content = (
            '2026-07-28T05:51:18Z [DEBUG] [account_service] [tr-6074163] '
            'profile_lookup_started: lookup_key="l.nascimento40@gmail.com"\n'
            '2026-07-28T05:51:21Z [INFO] [account_service] [tr-6074163] '
            'profile_lookup_completed: resource_id="account_7947" rows="0" http_status="404"\n'
        )
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write(content)
            p = Path(f.name)
        try:
            recs = parse_log_evidence(p, "ev_bracket", "2026-10-01T00:00:00Z")
            acct_rec = next((r for r in recs if r.resource_id == "account_7947"), None)
            self.assertIsNotNone(acct_rec, "account_7947 not found in bracketed log parse")
            self.assertEqual(acct_rec.state, "ABSENT")
            self.assertIn("l.nascimento40@gmail.com", acct_rec.identifiers_found)
        finally:
            if p.exists():
                os.unlink(p)

    def test_log_parser_pipe_trace_correlation(self) -> None:
        """EC-04: Ensure | tr-XXXX | pipe trace correlation links email to data flow."""
        content = (
            '2026-02-03T05:52:43Z | DEBUG | integration_service | tr-6648486 | '
            'connector_config_read_started | subject_key="yetunde.a3014@zoho.com"\n'
            '2026-02-03T05:52:51Z | WARN | integration_service | tr-6648486 | '
            'connector_heartbeat | resource_id="data_flow_8165" enabled="true"\n'
        )
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write(content)
            p = Path(f.name)
        try:
            recs = parse_log_evidence(p, "ev_pipe", "2026-10-01T00:00:00Z")
            df_rec = next((r for r in recs if r.resource_id == "data_flow_8165"), None)
            self.assertIsNotNone(df_rec, "data_flow_8165 not found in pipe-delimited log parse")
            self.assertEqual(df_rec.state, "ACTIVE")
            self.assertIn("yetunde.a3014@zoho.com", df_rec.identifiers_found)
        finally:
            if p.exists():
                os.unlink(p)

    def test_log_parser_syslog_trace_correlation(self) -> None:
        """EC-05: Ensure RFC 5424 syslog header trace correlation links email to RID."""
        content = (
            '2026-08-22T10:51:11Z <15>1 node-1 account_service tr-4973247 - - '
            'level=DEBUG event="profile_lookup_started" lookup_key="nana.b9576@outlook.com"\n'
            '2026-08-22T10:51:17Z <15>1 node-1 account_service tr-4973247 - - '
            'level=DEBUG resource_id="account_1785" event="profile_lookup_completed" rows="1" http_status="200"\n'
        )
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write(content)
            p = Path(f.name)
        try:
            recs = parse_log_evidence(p, "ev_syslog", "2026-10-01T00:00:00Z")
            acct_rec = next((r for r in recs if r.resource_id == "account_1785"), None)
            self.assertIsNotNone(acct_rec, "account_1785 not found in syslog parse")
            self.assertEqual(acct_rec.state, "PRESENT")
            self.assertIn("nana.b9576@outlook.com", acct_rec.identifiers_found)
        finally:
            if p.exists():
                os.unlink(p)


class TestSQLParser(unittest.TestCase):
    """Test suite for SQLite-backed SQL snapshot parsing."""

    def test_sql_parser_generic_tables_state_inference(self) -> None:
        """EC-06: Ensure generic customer_data_* tables correctly infer DISABLED/BLOCKED/ANONYMIZED states."""
        sql = (
            "CREATE TABLE customer_data_primary (resource_id TEXT PRIMARY KEY, origin_system TEXT, "
            "collection_name TEXT, record_json TEXT, updated_at TEXT);\n"
            "INSERT INTO customer_data_primary VALUES ('data_flow_01', 'integration_service', 'connector_configurations', "
            "'{\"resource_id\":\"data_flow_01\",\"enabled\":false,\"subject_selector\":\"alice@test.com\"}', '2026-09-01T00:00:00Z');\n"
            "INSERT INTO customer_data_primary VALUES ('backup_01', 'backup_service', 'backup_catalog', "
            "'{\"resource_id\":\"backup_01\",\"restore_allowed\":false,\"subject_reference\":\"alice@test.com\"}', '2026-09-01T00:00:00Z');\n"
            "INSERT INTO customer_data_primary VALUES ('analytics_01', 'analytics_platform', 'customer_analytics_reports', "
            "'{\"resource_id\":\"analytics_01\",\"user_id\":null,\"email\":null,\"phone\":null}', '2026-09-01T00:00:00Z');\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False, encoding="utf-8") as f:
            f.write(sql)
            p = Path(f.name)
        try:
            recs = parse_sql_evidence(p, "ev_sql_generic", "2026-10-01T00:00:00Z")
            by_rid = {r.resource_id: r for r in recs}
            self.assertIn("data_flow_01", by_rid)
            self.assertEqual(by_rid["data_flow_01"].state, "DISABLED")
            self.assertIn("backup_01", by_rid)
            self.assertEqual(by_rid["backup_01"].state, "BLOCKED")
            self.assertIn("analytics_01", by_rid)
            self.assertEqual(by_rid["analytics_01"].state, "ANONYMIZED")
            self.assertIn("alice@test.com", by_rid["data_flow_01"].identifiers_found)
        finally:
            if p.exists():
                os.unlink(p)

    def test_sql_parser_nested_search_document_extraction(self) -> None:
        """EC-07: Ensure nested document dictionary in search documents extracts identifiers."""
        sql = (
            "CREATE TABLE customer_data_read_replica (resource_id TEXT PRIMARY KEY, origin_system TEXT, "
            "collection_name TEXT, record_json TEXT, updated_at TEXT);\n"
            "INSERT INTO customer_data_read_replica VALUES ('search_99', 'search_service', 'customer_search_documents', "
            "'{\"resource_id\":\"search_99\",\"document\":{\"email\":\"bob@test.com\",\"customer_reference\":\"user_99\"}}', '2026-09-01T00:00:00Z');\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False, encoding="utf-8") as f:
            f.write(sql)
            p = Path(f.name)
        try:
            recs = parse_sql_evidence(p, "ev_sql_nested", "2026-10-01T00:00:00Z")
            self.assertEqual(len(recs), 1)
            self.assertIn("bob@test.com", recs[0].identifiers_found)
            self.assertIn("user_99", recs[0].identifiers_found)
        finally:
            if p.exists():
                os.unlink(p)

    def test_sql_parser_replication_drift(self) -> None:
        """EC-08: Ensure records in replica but absent in primary are successfully extracted."""
        sql = (
            "CREATE TABLE customer_profiles_primary (resource_id TEXT PRIMARY KEY, user_id TEXT, email TEXT);\n"
            "CREATE TABLE customer_profiles_failover_replica (resource_id TEXT PRIMARY KEY, user_id TEXT, email TEXT);\n"
            "INSERT INTO customer_profiles_failover_replica VALUES ('account_005', 'user_05', 'leila.haddad@yahoo.com');\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False, encoding="utf-8") as f:
            f.write(sql)
            p = Path(f.name)
        try:
            recs = parse_sql_evidence(p, "ev_drift", "2026-10-01T00:00:00Z")
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0].resource_id, "account_005")
            self.assertEqual(recs[0].state, "PRESENT")
            self.assertIn("leila.haddad@yahoo.com", recs[0].identifiers_found)
        finally:
            if p.exists():
                os.unlink(p)


class TestJSONParser(unittest.TestCase):
    """Test suite for JSON snapshot bundles and export reports."""

    def test_json_parser_analytics_report_anonymized(self) -> None:
        """EC-10: Ensure analytics record with null PII fields receives state=ANONYMIZED."""
        data = {
            "captured_at": "2026-09-07T09:45:00Z",
            "collection": "customer_analytics_reports",
            "records": [
                {
                    "resource_id": "analytics_901",
                    "user_id": None,
                    "email": None,
                    "phone": None,
                    "email_hash": None,
                }
            ],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(data, f)
            p = Path(f.name)
        try:
            recs = parse_json_evidence(p, "ev_json_anon", "2026-09-07T09:45:00Z")
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0].resource_id, "analytics_901")
            self.assertEqual(recs[0].state, "ANONYMIZED")
        finally:
            if p.exists():
                os.unlink(p)

    def test_json_parser_service_exports_hierarchy(self) -> None:
        """EC-11: Ensure service_exports 404 maps to ABSENT and blocked backup maps to BLOCKED."""
        data = {
            "service_exports": {
                "account_service": {
                    "profile_lookups": [
                        {"resource_id": "account_3136", "status_code": 404, "profile": None}
                    ]
                },
                "backup_service": {
                    "entries": [
                        {"resource_id": "backup_123", "restore_allowed": False}
                    ]
                },
            }
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(data, f)
            p = Path(f.name)
        try:
            recs = parse_json_evidence(p, "ev_svc_exp", "2026-09-15T11:44:55Z")
            by_rid = {r.resource_id: r for r in recs}
            self.assertIn("account_3136", by_rid)
            self.assertEqual(by_rid["account_3136"].state, "ABSENT")
            self.assertIn("backup_123", by_rid)
            self.assertEqual(by_rid["backup_123"].state, "BLOCKED")
        finally:
            if p.exists():
                os.unlink(p)


class TestTextParser(unittest.TestCase):
    """Test suite for handover notes and plain text parser."""

    def test_text_parser_pipe_format(self) -> None:
        """Ensure shift handover notes in pipe-delimited format are parsed into EvidenceRecord."""
        content = (
            "2026-10-01T04:00:00Z | account_service | account_001 | USER_PROFILE | ABSENT | user_01@example.com\n"
            "2026-10-01T04:00:00Z | backup_service | backup_002 | BACKUP_ARCHIVE | BLOCKED | user_01@example.com\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(content)
            p = Path(f.name)
        try:
            recs = parse_text_evidence(p, "ev_text", "2026-10-01T04:00:00Z")
            self.assertEqual(len(recs), 2)
            self.assertEqual(recs[0].resource_id, "account_001")
            self.assertEqual(recs[0].state, "ABSENT")
            self.assertIn("user_01@example.com", recs[0].identifiers_found)
        finally:
            if p.exists():
                os.unlink(p)


class TestPDFParser(unittest.TestCase):
    """Test suite for PDF evidence extraction using PyMuPDF and fallback behavior."""

    def test_pdf_parser_order_retention_matching(self) -> None:
        """EC-12: Ensure ORD-XXXX disputed order entries in legal registers are extracted."""
        try:
            import fitz
        except ImportError:
            self.skipTest("PyMuPDF (fitz) not available in environment")

        doc = fitz.open()
        page = doc.new_page()
        page.insert_text(
            (50, 50),
            "DISPUTED ORDERS AND TAX RECORDS REGISTER\n"
            "ORD-20264118 | user_08 | Card dispute | 04 May 2026 | Retain until 2033\n"
        )
        with tempfile.NamedTemporaryFile("wb", suffix=".pdf", delete=False) as f:
            pdf_path = Path(f.name)
        doc.save(str(pdf_path))
        doc.close()
        try:
            recs = parse_pdf_evidence(pdf_path, "ev_pdf_legal", "2026-05-29T08:00:00Z")
            self.assertGreaterEqual(len(recs), 1, "Failed to extract ORD-20264118 from PDF")
            ord_rec = next((r for r in recs if r.resource_id == "ORD-20264118"), None)
            self.assertIsNotNone(ord_rec, "ORD-20264118 not identified in PDF records")
            self.assertIn("user_08", ord_rec.identifiers_found)
        finally:
            if pdf_path.exists():
                os.unlink(pdf_path)

    def test_pdf_parser_missing_fitz_fallback(self) -> None:
        """EC-13: Ensure graceful handling and empty record return when fitz is unavailable."""
        with patch.dict("sys.modules", {"fitz": None}):
            p = Path("nonexistent.pdf")
            recs = parse_pdf_evidence(p, "ev_pdf_none", "2026-05-29T08:00:00Z")
            self.assertEqual(recs, [], "Expected empty record list on missing fitz fallback")


class TestEvidenceIndexTemporalFilter(unittest.TestCase):
    """Test suite for EvidenceIndex temporal scoping and token isolation."""

    def test_evidence_index_strict_temporal_filtering(self) -> None:
        """EC-14: Ensure evidence captured after audit_at is strictly excluded."""
        with tempfile.TemporaryDirectory() as tmpdir:
            td = Path(tmpdir)
            p_past = td / "past.txt"
            p_future = td / "future.txt"

            p_past.write_text(
                "2026-08-01T00:00:00Z | account_service | account_01 | USER_PROFILE | PRESENT | alice@test.com\n",
                encoding="utf-8",
            )
            p_future.write_text(
                "2026-09-15T00:00:00Z | account_service | account_01 | USER_PROFILE | PRESENT | alice@test.com\n",
                encoding="utf-8",
            )

            manifest = [
                {"file_id": "ev_past", "file_path": "past.txt", "captured_at": "2026-08-01T00:00:00Z"},
                {"file_id": "ev_future", "file_path": "future.txt", "captured_at": "2026-09-15T00:00:00Z"},
            ]

            index = EvidenceIndex(manifest, td)
            # Query with cutoff strictly between past and future files
            results = index.query_for_user({"alice@test.com"}, "2026-08-15T00:00:00Z")
            self.assertEqual(len(results), 1, "Expected exactly 1 record from past evidence")
            self.assertEqual(results[0].file_id, "ev_past")

    def test_evidence_index_no_bogus_token_pollution(self) -> None:
        """EC-15: Ensure corrupt single-character resource IDs (like \\) do not cross-pollinate tokens."""
        with tempfile.TemporaryDirectory() as tmpdir:
            td = Path(tmpdir)
            p_log = td / "cloud.log"
            p_log.write_text(
                '2026-08-01T00:00:00Z message="resource_id=\\"search_123\\" correlation_key=\\"user_1@test.com\\""\n',
                encoding="utf-8",
            )
            manifest = [
                {"file_id": "ev_cloud", "file_path": "cloud.log", "captured_at": "2026-08-01T00:00:00Z"},
            ]
            index = EvidenceIndex(manifest, td)
            # Query for an unrelated user should yield zero records
            results = index.query_for_user({"user_2@test.com"}, "2026-09-01T00:00:00Z")
            self.assertEqual(len(results), 0, "Unrelated user matched cross-pollinated tokens!")


if __name__ == "__main__":
    unittest.main()
