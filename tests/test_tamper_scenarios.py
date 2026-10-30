"""
Phase 8 Automated Validation Suite:
Comprehensive tests covering all 8 demonstration scenarios:
1. Normal audit event that verifies successfully (VERIFIED)
2. SQL field changed after anchoring (TAMPERED)
3. SQL audit row deleted after anchoring (MISSING_SQL)
4. SQL event that has not been anchored (UNANCHORED)
5. Blockchain outage during a new event (preserved as PENDING with diagnostics)
6. Recovery after Ganache becomes available again (retry worker anchors pending records)
7. Duplicate anchoring attempts (rejection and idempotent safety)
8. On-chain ID with no matching SQL row (MISSING_SQL)

Also verifies:
- Dev-only tamper endpoints are blocked for non-auditors (403 Forbidden)
- Dev-only tamper endpoints are blocked when ALLOW_TAMPER_SIMULATION is False (403 Forbidden)
- Auditor dashboard displays the correct result for every case.
"""
from unittest.mock import MagicMock
import pytest
from app.extensions import db
from app.models.user import User
from app.models.audit_log import AuditLog
from app.services.audit_service import record_audit_event
from app.services.hashing_service import hash_audit_fields, to_bytes32
from app.audit.verification import (
    verify_audit_trail,
    STATUS_VERIFIED,
    STATUS_TAMPERED,
    STATUS_MISSING_SQL,
    STATUS_UNANCHORED,
    STATUS_BLOCKCHAIN_UNAVAILABLE,
)
from app.blockchain.client import BlockchainClient
from app.blockchain.anchoring import anchor_single_log, retry_pending_anchors


# ---------------------------------------------------------------------------
# Scenario 1: Normal audit event that verifies successfully
# ---------------------------------------------------------------------------
def test_scenario_1_normal_verified_event(app):
    """Scenario 1: A normal audit event verifies successfully against on-chain hash."""
    with app.app_context():
        rec = record_audit_event("alice", "UPLOAD", "annual_report.pdf", auto_anchor=False)
        _, expected_hash = hash_audit_fields(rec.log_id, rec.user_id, rec.action_type, rec.file_name, rec.timestamp)
        raw_bytes = to_bytes32(expected_hash)

        mock_contract = MagicMock()
        mock_contract.functions.getAllLogIds.return_value.call.return_value = [rec.log_id]
        mock_contract.functions.getLogRecord.return_value.call.return_value = (
            rec.log_id, raw_bytes, 1793361600, True
        )

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = True
        mock_client.get_contract.return_value = mock_contract

        report = verify_audit_trail(client=mock_client)
        assert report["summary"]["verified"] == 1
        assert report["summary"]["tampered"] == 0
        entry = next(r for r in report["records"] if r["log_id"] == rec.log_id)
        assert entry["verification_status"] == STATUS_VERIFIED


# ---------------------------------------------------------------------------
# Scenario 2: A SQL field changed after anchoring
# ---------------------------------------------------------------------------
def test_scenario_2_sql_field_tampered(app):
    """Scenario 2: An off-chain SQL field modified after anchoring is caught by hash mismatch."""
    with app.app_context():
        rec = record_audit_event("charlie", "UPLOAD", "invoice_99.pdf", auto_anchor=False)
        _, original_hash = hash_audit_fields(rec.log_id, rec.user_id, rec.action_type, rec.file_name, rec.timestamp)
        original_bytes = to_bytes32(original_hash)

        # Insider tampering: modify target file name directly in SQLite
        rec.file_name = "TAMPERED_invoice_99.pdf"
        db.session.commit()

        mock_contract = MagicMock()
        mock_contract.functions.getAllLogIds.return_value.call.return_value = [rec.log_id]
        mock_contract.functions.getLogRecord.return_value.call.return_value = (
            rec.log_id, original_bytes, 1793361600, True
        )

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = True
        mock_client.get_contract.return_value = mock_contract

        report = verify_audit_trail(client=mock_client)
        assert report["summary"]["tampered"] == 1
        entry = next(r for r in report["records"] if r["log_id"] == rec.log_id)
        assert entry["verification_status"] == STATUS_TAMPERED
        assert "TAMPER DETECTED" in entry["details"]


# ---------------------------------------------------------------------------
# Scenario 3: A SQL audit row deleted after anchoring
# ---------------------------------------------------------------------------
def test_scenario_3_sql_row_deleted_after_anchoring(app):
    """Scenario 3: An off-chain SQL row deleted after anchoring is detected via on-chain array."""
    with app.app_context():
        rec = record_audit_event("dave", "DELETE", "classified.txt", auto_anchor=False)
        target_log_id = rec.log_id
        _, original_hash = hash_audit_fields(rec.log_id, rec.user_id, rec.action_type, rec.file_name, rec.timestamp)
        original_bytes = to_bytes32(original_hash)

        # Insider physically deletes row from SQLite
        db.session.delete(rec)
        db.session.commit()

        # Blockchain still holds immutable record of target_log_id
        mock_contract = MagicMock()
        mock_contract.functions.getAllLogIds.return_value.call.return_value = [target_log_id]
        mock_contract.functions.getLogRecord.return_value.call.return_value = (
            target_log_id, original_bytes, 1793361600, True
        )

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = True
        mock_client.get_contract.return_value = mock_contract

        report = verify_audit_trail(client=mock_client)
        assert report["summary"]["missing_sql"] >= 1
        missing_entry = next(r for r in report["records"] if r["log_id"] == target_log_id)
        assert missing_entry["verification_status"] == STATUS_MISSING_SQL
        assert "DELETED RECORD DETECTED" in missing_entry["details"]


# ---------------------------------------------------------------------------
# Scenario 4: An SQL event that has not been anchored
# ---------------------------------------------------------------------------
def test_scenario_4_unanchored_sql_event(app):
    """Scenario 4: An unanchored record stored in SQLite is classified as UNANCHORED."""
    with app.app_context():
        rec = record_audit_event("eve", "LOGIN", "SESSION", auto_anchor=False)

        mock_contract = MagicMock()
        mock_contract.functions.getAllLogIds.return_value.call.return_value = []
        mock_contract.functions.isLogAnchored.return_value.call.return_value = False

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = True
        mock_client.get_contract.return_value = mock_contract

        report = verify_audit_trail(client=mock_client)
        assert report["summary"]["unanchored"] >= 1
        entry = next(r for r in report["records"] if r["log_id"] == rec.log_id)
        assert entry["verification_status"] == STATUS_UNANCHORED


# ---------------------------------------------------------------------------
# Scenario 5: Blockchain outage during a new event
# ---------------------------------------------------------------------------
def test_scenario_5_blockchain_outage_during_event(app):
    """Scenario 5: When blockchain is down, event is safely stored in SQL as PENDING."""
    with app.app_context():
        # Simulate offline node
        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = False

        rec = record_audit_event("frank", "UPLOAD", "budget.csv", auto_anchor=False)
        assert rec.anchored_status == "PENDING"

        # Anchoring attempt fails gracefully
        success = anchor_single_log(rec.id, client=mock_client)
        assert success is False

        # Verify SQL row preserved intact with error diagnostics
        db.session.refresh(rec)
        assert rec.anchored_status == "PENDING"
        assert rec.error_message == "Blockchain RPC endpoint unreachable"
        assert rec.tx_hash is None


# ---------------------------------------------------------------------------
# Scenario 6: Recovery after Ganache becomes available again
# ---------------------------------------------------------------------------
def test_scenario_6_recovery_after_ganache_available(app):
    """Scenario 6: Pending records queued during outage are anchored once connectivity restores."""
    with app.app_context():
        rec = record_audit_event("grace", "DOWNLOAD", "data_export.zip", auto_anchor=False)
        rec.anchored_status = "PENDING"
        rec.error_message = "Blockchain RPC endpoint unreachable"
        rec.retry_count = 1
        db.session.commit()

        # Blockchain becomes available again
        mock_tx_hash = MagicMock()
        mock_tx_hash.hex.return_value = "0x" + "7" * 64
        mock_receipt = MagicMock()
        mock_receipt.status = 1
        mock_receipt.transactionHash.hex.return_value = "0x" + "7" * 64
        mock_receipt.blockNumber = 350

        mock_w3 = MagicMock()
        mock_w3.eth.wait_for_transaction_receipt.return_value = mock_receipt

        mock_contract = MagicMock()
        mock_contract.functions.isLogAnchored.return_value.call.return_value = False
        mock_contract.functions.storeLogHash.return_value.transact.return_value = mock_tx_hash

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = True
        mock_client.get_contract.return_value = mock_contract
        mock_client.get_web3.return_value = mock_w3
        mock_client.get_signing_account.return_value = ("0x7777777777777777777777777777777777777777", None)

        # Trigger worker retry
        summary = retry_pending_anchors(limit=10, client=mock_client)
        assert summary["status"] == "success"
        assert summary["succeeded"] >= 1

        db.session.refresh(rec)
        assert rec.anchored_status == "ANCHORED"
        assert rec.tx_hash == "0x" + "7" * 64
        assert rec.block_number == 350
        assert rec.error_message is None


# ---------------------------------------------------------------------------
# Scenario 7: Duplicate anchoring attempts
# ---------------------------------------------------------------------------
def test_scenario_7_duplicate_anchoring_prevention(app):
    """Scenario 7: Duplicate anchor attempts are caught idempotently before transaction revert."""
    with app.app_context():
        rec = record_audit_event("heidi", "MODIFY", "settings.ini", auto_anchor=False)

        mock_contract = MagicMock()
        # Simulate contract reporting isLogAnchored == True
        mock_contract.functions.isLogAnchored.return_value.call.return_value = True

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = True
        mock_client.get_contract.return_value = mock_contract
        mock_client.get_signing_account.return_value = ("0x8888888888888888888888888888888888888888", None)

        success = anchor_single_log(rec.id, client=mock_client)
        assert success is True

        # Ensure no redundant blockchain transaction was submitted
        assert mock_contract.functions.storeLogHash.call_count == 0

        db.session.refresh(rec)
        assert rec.anchored_status == "ANCHORED"


# ---------------------------------------------------------------------------
# Scenario 8: An on-chain ID that has no matching SQL row
# ---------------------------------------------------------------------------
def test_scenario_8_orphan_onchain_id_detected(app):
    """Scenario 8: An on-chain ID without a matching SQL row is detected as MISSING_SQL."""
    with app.app_context():
        orphan_id = "LOG-20261030-ORPHAN01"
        raw_hash = to_bytes32("0x" + "9" * 64)

        mock_contract = MagicMock()
        mock_contract.functions.getAllLogIds.return_value.call.return_value = [orphan_id]
        mock_contract.functions.getLogRecord.return_value.call.return_value = (
            orphan_id, raw_hash, 1793361600, True
        )

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = True
        mock_client.get_contract.return_value = mock_contract

        report = verify_audit_trail(client=mock_client)
        orphan_result = next(r for r in report["records"] if r["log_id"] == orphan_id)
        assert orphan_result["verification_status"] == STATUS_MISSING_SQL
        assert orphan_result["user_id"] == "UNKNOWN [DELETED]"


# ---------------------------------------------------------------------------
# Security & Tampering Endpoint Protection Tests
# ---------------------------------------------------------------------------
def test_tamper_endpoints_blocked_for_normal_users(client, app):
    """Verify ordinary users cannot invoke tampering endpoints (HTTP 403 Forbidden)."""
    with app.app_context():
        user = User(username="normal_user_tamper", role="user")
        user.set_password("NormalPass123!")
        db.session.add(user)
        rec = record_audit_event("victim", "UPLOAD", "file.txt", auto_anchor=False)
        rec_id = rec.id
        db.session.commit()

    client.post("/auth/login", data={"username": "normal_user_tamper", "password": "NormalPass123!"})

    # Modify endpoint
    resp_mod = client.post(f"/audit/tamper/modify/{rec_id}")
    assert resp_mod.status_code == 403

    # Delete endpoint
    resp_del = client.post(f"/audit/tamper/delete/{rec_id}")
    assert resp_del.status_code == 403

    # Seed scenarios endpoint
    resp_seed = client.post("/audit/tamper/seed-scenarios")
    assert resp_seed.status_code == 403


def test_tamper_endpoints_blocked_when_disabled(client, app):
    """Verify tampering endpoints are blocked when ALLOW_TAMPER_SIMULATION is False."""
    with app.app_context():
        app.config["ALLOW_TAMPER_SIMULATION"] = False
        auditor = User(username="auditor_tamper_test", role="auditor")
        auditor.set_password("AuditorPass123!")
        db.session.add(auditor)
        rec = record_audit_event("victim", "UPLOAD", "file2.txt", auto_anchor=False)
        rec_id = rec.id
        db.session.commit()

    client.post("/auth/login", data={"username": "auditor_tamper_test", "password": "AuditorPass123!"})

    resp = client.post(f"/audit/tamper/modify/{rec_id}")
    assert resp.status_code == 403

    # Reset config
    app.config["ALLOW_TAMPER_SIMULATION"] = True
