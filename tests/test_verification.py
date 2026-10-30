"""
Phase 7 Auditor Dashboard & Verification Engine Tests:
- Server-side access control (403 for ordinary users, login redirect for anonymous, 200 for auditor)
- Dashboard filtering (by user, action, status) and pagination
- Verification engine classification:
  * Intact records -> VERIFIED
  * Modified off-chain SQL records -> TAMPERED
  * Deleted off-chain SQL rows -> MISSING_SQL
  * Unanchored SQL records -> UNANCHORED
  * Offline blockchain node -> BLOCKCHAIN_UNAVAILABLE (NOT classified as tampering)
- POST /audit/verify route and POST /api/audit/verify JSON API execution
"""
from unittest.mock import MagicMock
import pytest
from app.extensions import db
from app.models.user import User
from app.models.audit_log import AuditLog
from app.services.audit_service import record_audit_event
from app.services.hashing_service import hash_audit_fields
from app.audit.verification import (
    verify_audit_trail,
    STATUS_VERIFIED,
    STATUS_TAMPERED,
    STATUS_MISSING_SQL,
    STATUS_UNANCHORED,
    STATUS_BLOCKCHAIN_UNAVAILABLE,
)
from app.blockchain.client import BlockchainClient


# ---------------------------------------------------------------------------
# Section 1: Server-Side Access Control & Security Tests
# ---------------------------------------------------------------------------

def test_auditor_dashboard_access_control(client, app):
    """
    Verify server-side authorization:
    - Anonymous users are redirected to login.
    - Ordinary users (role='user') receive HTTP 403 Forbidden.
    - Auditors (role='auditor') are granted access (HTTP 200 OK).
    """
    with app.app_context():
        # Setup ordinary user
        user = User(username="regular_viewer", role="user")
        user.set_password("ViewerPass123!")
        # Setup auditor
        auditor = User(username="official_auditor", role="auditor")
        auditor.set_password("AuditorPass123!")
        db.session.add_all([user, auditor])
        db.session.commit()

    # 1. Anonymous access
    anon_resp = client.get("/audit/dashboard")
    assert anon_resp.status_code == 302
    assert "/auth/login" in anon_resp.headers["Location"]

    # 2. Ordinary user access blocked
    client.post("/auth/login", data={"username": "regular_viewer", "password": "ViewerPass123!"})
    user_resp = client.get("/audit/dashboard")
    assert user_resp.status_code == 403

    # 3. Auditor access granted
    client.get("/auth/logout")
    client.post("/auth/login", data={"username": "official_auditor", "password": "AuditorPass123!"})
    auditor_resp = client.get("/audit/dashboard")
    assert auditor_resp.status_code == 200
    assert b"Auditor Verification Dashboard" in auditor_resp.data


def test_auditor_dashboard_filters_and_pagination(client, app):
    """Verify table filtering by user, action, and pagination controls."""
    with app.app_context():
        # Provision auditor account
        auditor = User(username="filter_auditor", role="auditor")
        auditor.set_password("FilterPass123!")
        db.session.add(auditor)
        db.session.commit()

        # Seed 20 diverse audit records
        for i in range(12):
            record_audit_event("alice_corp", "UPLOAD", f"file_a_{i}.pdf", auto_anchor=False)
        for i in range(8):
            record_audit_event("bob_corp", "DOWNLOAD", f"file_b_{i}.csv", auto_anchor=False)

    client.post("/auth/login", data={"username": "filter_auditor", "password": "FilterPass123!"})

    # 1. Pagination: page 1 with per_page=10
    resp_p1 = client.get("/audit/dashboard?page=1&per_page=10")
    assert resp_p1.status_code == 200
    assert b"Showing page 1 of" in resp_p1.data

    # 2. Filter by user: alice_corp
    resp_user = client.get("/audit/dashboard?user=alice_corp")
    assert resp_user.status_code == 200
    assert b"alice_corp" in resp_user.data

    # 3. Filter by action: DOWNLOAD
    resp_act = client.get("/audit/dashboard?action=DOWNLOAD")
    assert resp_act.status_code == 200
    assert b"DOWNLOAD" in resp_act.data


# ---------------------------------------------------------------------------
# Section 2: Verification Engine Cryptographic Logic Tests
# ---------------------------------------------------------------------------

def test_verification_blockchain_offline_handling(app):
    """
    CRITICAL RULE:
    When the blockchain is unreachable, records are marked BLOCKCHAIN_UNAVAILABLE.
    An unreachable blockchain must NEVER be classified as evidence of tampering.
    """
    with app.app_context():
        record_audit_event("offline_user", "UPLOAD", "doc.txt", auto_anchor=False)

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = False
        mock_client.get_contract.return_value = None

        report = verify_audit_trail(client=mock_client)
        assert report["blockchain_status"] == "OFFLINE"
        assert report["summary"]["tampered"] == 0
        assert report["summary"]["blockchain_unavailable"] >= 1
        for r in report["records"]:
            assert r["verification_status"] == STATUS_BLOCKCHAIN_UNAVAILABLE


def test_verification_intact_records_verified(app):
    """Verify that records with matching on-chain hashes are classified as VERIFIED."""
    with app.app_context():
        rec = record_audit_event("intact_actor", "UPLOAD", "financials.xlsx", auto_anchor=False)
        canonical_str, expected_hash = hash_audit_fields(
            rec.log_id, rec.user_id, rec.action_type, rec.file_name, rec.timestamp
        )

        raw_hash_bytes = bytes.fromhex(expected_hash[2:])

        mock_contract = MagicMock()
        mock_contract.functions.getAllLogIds.return_value.call.return_value = [rec.log_id]
        mock_contract.functions.getLogRecord.return_value.call.return_value = (
            rec.log_id, raw_hash_bytes, 1793361600, True
        )

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = True
        mock_client.get_contract.return_value = mock_contract

        report = verify_audit_trail(client=mock_client)
        assert report["blockchain_status"] == "ONLINE"
        matching_record = next(r for r in report["records"] if r["log_id"] == rec.log_id)
        assert matching_record["verification_status"] == STATUS_VERIFIED
        assert matching_record["recalculated_hash"].lower() == expected_hash.lower()


def test_verification_tampered_record_detected(app):
    """
    Verify tamper detection:
    When an off-chain SQL row is modified, recomputed hash diverges from contract hash -> TAMPERED.
    """
    with app.app_context():
        rec = record_audit_event("victim_user", "UPLOAD", "payroll.csv", auto_anchor=False)
        # Calculate genuine original hash
        _, original_hash = hash_audit_fields(
            rec.log_id, rec.user_id, rec.action_type, rec.file_name, rec.timestamp
        )
        original_bytes = bytes.fromhex(original_hash[2:])

        # Rogue insider modifies the SQL row action to DELETE
        rec.action_type = "DELETE"
        db.session.commit()

        # Contract stores the legitimate original hash
        mock_contract = MagicMock()
        mock_contract.functions.getAllLogIds.return_value.call.return_value = [rec.log_id]
        mock_contract.functions.getLogRecord.return_value.call.return_value = (
            rec.log_id, original_bytes, 1793361600, True
        )

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = True
        mock_client.get_contract.return_value = mock_contract

        report = verify_audit_trail(client=mock_client)
        matching_record = next(r for r in report["records"] if r["log_id"] == rec.log_id)
        assert matching_record["verification_status"] == STATUS_TAMPERED
        assert report["summary"]["tampered"] >= 1
        assert "TAMPER DETECTED" in matching_record["details"]


def test_verification_missing_sql_record_detected(app):
    """
    Verify deleted SQL detection:
    When a log ID is anchored on-chain but absent from SQLite -> MISSING_SQL.
    """
    with app.app_context():
        deleted_log_id = "LOG-20261030-DELETED99"
        dummy_hash_bytes = bytes.fromhex("f" * 64)

        mock_contract = MagicMock()
        mock_contract.functions.getAllLogIds.return_value.call.return_value = [deleted_log_id]
        mock_contract.functions.getLogRecord.return_value.call.return_value = (
            deleted_log_id, dummy_hash_bytes, 1793361600, True
        )

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = True
        mock_client.get_contract.return_value = mock_contract

        report = verify_audit_trail(client=mock_client)
        assert report["summary"]["missing_sql"] >= 1
        missing_entry = next(r for r in report["records"] if r["log_id"] == deleted_log_id)
        assert missing_entry["verification_status"] == STATUS_MISSING_SQL
        assert "DELETED RECORD DETECTED" in missing_entry["details"]


def test_verification_unanchored_record_detected(app):
    """
    Verify unanchored detection:
    When an SQL row has not yet been committed to blockchain -> UNANCHORED.
    """
    with app.app_context():
        rec = record_audit_event("new_actor", "LOGIN", "SESSION", auto_anchor=False)

        mock_contract = MagicMock()
        mock_contract.functions.getAllLogIds.return_value.call.return_value = []
        mock_contract.functions.isLogAnchored.return_value.call.return_value = False

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = True
        mock_client.get_contract.return_value = mock_contract

        report = verify_audit_trail(client=mock_client)
        matching_record = next(r for r in report["records"] if r["log_id"] == rec.log_id)
        assert matching_record["verification_status"] == STATUS_UNANCHORED


# ---------------------------------------------------------------------------
# Section 3: Verification Endpoints & API Tests
# ---------------------------------------------------------------------------

def test_run_verification_route_and_api(client, app):
    """Test POST /audit/verify route and POST /api/audit/verify API endpoint."""
    with app.app_context():
        auditor = User(username="exec_auditor", role="auditor")
        auditor.set_password("ExecPass123!")
        db.session.add(auditor)
        db.session.commit()

    client.post("/auth/login", data={"username": "exec_auditor", "password": "ExecPass123!"})

    # 1. Form POST /audit/verify
    post_resp = client.post("/audit/verify", follow_redirects=True)
    assert post_resp.status_code == 200
    assert b"Verification" in post_resp.data

    # 2. JSON API POST /api/verify
    api_resp = client.post("/audit/api/verify")
    assert api_resp.status_code == 200
    json_data = api_resp.get_json()
    assert "summary" in json_data
    assert "records" in json_data
    assert "blockchain_status" in json_data
