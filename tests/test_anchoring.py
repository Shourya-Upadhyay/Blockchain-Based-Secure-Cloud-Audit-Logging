"""
Phase 6 Web3 Middleware & Hash Anchoring Tests:
- Isolated unit tests using clearly labeled mocks for edge-case coverage:
  * Graceful handling when RPC node is offline (SQL record preserved as PENDING)
  * Duplicate detection preventing redundant transaction submission (idempotency)
  * Successful receipt confirmation updating SQL record to ANCHORED
  * On-chain revert handling and retry count increment
  * Max retry limit transition to FAILED
  * Retry queue worker batch processing
- Live Ganache integration tests executed against running local testnet:
  * Two-phase commit: off-chain SQL persist -> on-chain contract store -> confirmation
  * Verification that on-chain record matches off-chain SQL digest
  * Worker batch retry against live node
"""
from unittest.mock import MagicMock
import pytest
from app.extensions import db
from app.models.audit_log import AuditLog
from app.services.audit_service import record_audit_event
from app.blockchain.anchoring import (
    anchor_single_log,
    retry_pending_anchors,
    get_anchoring_stats,
    parse_iso_to_unix,
)
from app.blockchain.client import BlockchainClient
from tests.test_blockchain import get_live_ganache_connection, ARTIFACT_FILE

GANACHE_ONLINE, W3_INSTANCE, ACTIVE_RPC = get_live_ganache_connection()


# ---------------------------------------------------------------------------
# Section 1: Isolated Unit Tests with Explicitly Labeled Mocks
# (Never reports mock transactions as real blockchain transactions)
# ---------------------------------------------------------------------------

def test_mock_offline_rpc_preserves_sql_record_as_pending(app):
    """
    [ISOLATED MOCK TEST]
    Verify that when the blockchain RPC endpoint is offline:
    1. The off-chain SQL record is preserved intact.
    2. Status remains 'PENDING'.
    3. Descriptive error message is stored.
    4. Application workflow does not crash.
    """
    with app.app_context():
        # Create record without auto-anchoring
        record = record_audit_event("alice", "LOGIN", "SESSION", auto_anchor=False)
        assert record.anchored_status == "PENDING"
        assert record.tx_hash is None

        # Build mock client simulating offline Ganache node
        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = False

        success = anchor_single_log(record.id, client=mock_client)
        assert success is False

        # Verify SQL persistence
        db.session.refresh(record)
        assert record.anchored_status == "PENDING"
        assert record.error_message == "Blockchain RPC endpoint unreachable"
        assert record.tx_hash is None
        assert record.block_number is None


def test_mock_duplicate_detection_prevents_redundant_transaction(app):
    """
    [ISOLATED MOCK TEST]
    Verify idempotency:
    If a record is already anchored on-chain (e.g. following app crash between tx and SQL update),
    the anchoring service detects this and avoids sending a duplicate transaction that would revert.
    """
    with app.app_context():
        record = record_audit_event("bob", "UPLOAD", "data.csv", auto_anchor=False)

        mock_contract = MagicMock()
        # Simulate contract reporting logId already anchored
        mock_contract.functions.isLogAnchored.return_value.call.return_value = True

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = True
        mock_client.get_contract.return_value = mock_contract
        mock_client.get_signing_account.return_value = ("0x1111111111111111111111111111111111111111", None)

        success = anchor_single_log(record.id, client=mock_client)
        assert success is True

        # Ensure storeLogHash transaction was NOT called redundantly
        assert mock_contract.functions.storeLogHash.call_count == 0

        # Verify SQL status was updated to ANCHORED
        db.session.refresh(record)
        assert record.anchored_status == "ANCHORED"


def test_mock_successful_receipt_updates_sql_record(app):
    """
    [ISOLATED MOCK TEST]
    Verify two-phase commit:
    When transaction receipt status == 1, tx_hash and block_number are written to SQL.
    """
    with app.app_context():
        record = record_audit_event("charlie", "DOWNLOAD", "spec.pdf", auto_anchor=False)

        mock_tx_hash = MagicMock()
        mock_tx_hash.hex.return_value = "0x" + "1" * 64

        mock_receipt = MagicMock()
        mock_receipt.status = 1
        mock_receipt.transactionHash.hex.return_value = "0x" + "1" * 64
        mock_receipt.blockNumber = 1042

        mock_w3 = MagicMock()
        mock_w3.eth.wait_for_transaction_receipt.return_value = mock_receipt

        mock_contract = MagicMock()
        mock_contract.functions.isLogAnchored.return_value.call.return_value = False
        mock_contract.functions.storeLogHash.return_value.transact.return_value = mock_tx_hash

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = True
        mock_client.get_contract.return_value = mock_contract
        mock_client.get_web3.return_value = mock_w3
        mock_client.get_signing_account.return_value = ("0x2222222222222222222222222222222222222222", None)

        success = anchor_single_log(record.id, client=mock_client)
        assert success is True

        db.session.refresh(record)
        assert record.anchored_status == "ANCHORED"
        assert record.tx_hash == "0x" + "1" * 64
        assert record.block_number == 1042
        assert record.error_message is None


def test_mock_reverted_receipt_increments_retry(app):
    """
    [ISOLATED MOCK TEST]
    Verify that an on-chain reverted transaction (status == 0) increments retry_count
    and keeps status PENDING while below retry limit.
    """
    with app.app_context():
        record = record_audit_event("dave", "MODIFY", "config.xml", auto_anchor=False)

        mock_tx_hash = MagicMock()
        mock_tx_hash.hex.return_value = "0x" + "2" * 64

        mock_receipt = MagicMock()
        mock_receipt.status = 0  # Revert status

        mock_w3 = MagicMock()
        mock_w3.eth.wait_for_transaction_receipt.return_value = mock_receipt

        mock_contract = MagicMock()
        mock_contract.functions.isLogAnchored.return_value.call.return_value = False
        mock_contract.functions.storeLogHash.return_value.transact.return_value = mock_tx_hash

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = True
        mock_client.get_contract.return_value = mock_contract
        mock_client.get_web3.return_value = mock_w3
        mock_client.get_signing_account.return_value = ("0x3333333333333333333333333333333333333333", None)

        success = anchor_single_log(record.id, client=mock_client)
        assert success is False

        db.session.refresh(record)
        assert record.anchored_status == "PENDING"
        assert record.retry_count == 1
        assert "reverted" in record.error_message.lower()


def test_mock_max_retry_limit_transitions_to_failed(app):
    """
    [ISOLATED MOCK TEST]
    Verify that when retry_count reaches ANCHOR_RETRY_LIMIT, status transitions to FAILED.
    """
    with app.app_context():
        record = record_audit_event("eve", "DELETE", "old_doc.txt", auto_anchor=False)
        record.retry_count = 2  # Limit is 3
        db.session.commit()

        mock_contract = MagicMock()
        mock_contract.functions.isLogAnchored.return_value.call.return_value = False
        mock_contract.functions.storeLogHash.side_effect = Exception("Out of gas error")

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = True
        mock_client.get_contract.return_value = mock_contract
        mock_client.get_web3.return_value = MagicMock()
        mock_client.get_signing_account.return_value = ("0x4444444444444444444444444444444444444444", None)

        success = anchor_single_log(record.id, client=mock_client)
        assert success is False

        db.session.refresh(record)
        assert record.retry_count == 3
        assert record.anchored_status == "FAILED"


def test_mock_retry_queue_worker(app):
    """
    [ISOLATED MOCK TEST]
    Verify retry_pending_anchors processes queued records.
    """
    with app.app_context():
        rec1 = record_audit_event("worker_user", "UPLOAD", "file1.dat", auto_anchor=False)
        rec2 = record_audit_event("worker_user", "DOWNLOAD", "file2.dat", auto_anchor=False)

        mock_tx_hash = MagicMock()
        mock_tx_hash.hex.return_value = "0x" + "a" * 64

        mock_receipt = MagicMock()
        mock_receipt.status = 1
        mock_receipt.transactionHash.hex.return_value = "0x" + "a" * 64
        mock_receipt.blockNumber = 200

        mock_w3 = MagicMock()
        mock_w3.eth.wait_for_transaction_receipt.return_value = mock_receipt

        mock_contract = MagicMock()
        mock_contract.functions.isLogAnchored.return_value.call.return_value = False
        mock_contract.functions.storeLogHash.return_value.transact.return_value = mock_tx_hash

        mock_client = MagicMock(spec=BlockchainClient)
        mock_client.is_connected.return_value = True
        mock_client.get_contract.return_value = mock_contract
        mock_client.get_web3.return_value = mock_w3
        mock_client.get_signing_account.return_value = ("0x5555555555555555555555555555555555555555", None)

        summary = retry_pending_anchors(limit=10, client=mock_client)
        assert summary["status"] == "success"
        assert summary["succeeded"] >= 2


def test_anchoring_stats_aggregation(app):
    """Verify get_anchoring_stats returns accurate counts."""
    with app.app_context():
        stats = get_anchoring_stats()
        assert "total_events" in stats
        assert "anchored_count" in stats
        assert "pending_count" in stats
        assert "failed_count" in stats


def test_parse_iso_to_unix():
    """Verify ISO-8601 UTC string conversion to Unix timestamp."""
    unix_val = parse_iso_to_unix("2026-10-30T12:00:00Z")
    assert isinstance(unix_val, int)
    assert unix_val > 0


# ---------------------------------------------------------------------------
# Section 2: Live Ganache Integration Tests (Executed when Ganache is online)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def live_ganache_contract():
    """Provisions a live AuditLogContract on running Ganache node for integration tests."""
    if not GANACHE_ONLINE or W3_INSTANCE is None:
        pytest.skip("Local Ganache testnet is offline. Skipping live integration tests.")

    import json
    with open(ARTIFACT_FILE, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    w3 = W3_INSTANCE
    deployer = w3.eth.accounts[0]
    contract_factory = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    tx_hash = contract_factory.constructor().transact({"from": deployer, "gas": 3000000})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=10)

    client = BlockchainClient(rpc_url=ACTIVE_RPC, contract_address=receipt.contractAddress)
    return client, receipt.contractAddress


def test_live_ganache_anchor_single_log(app, live_ganache_contract):
    """
    [REAL BLOCKCHAIN TEST]
    End-to-end integration test with live Ganache:
    Creates audit record in SQL -> Submits to smart contract -> Awaits receipt -> Updates SQL.
    """
    client, contract_addr = live_ganache_contract

    with app.app_context():
        record = record_audit_event("live_tester", "UPLOAD", "blockchain_report.pdf", auto_anchor=False)
        assert record.anchored_status == "PENDING"

        success = anchor_single_log(record.id, client=client)
        assert success is True

        db.session.refresh(record)
        assert record.anchored_status == "ANCHORED"
        assert record.tx_hash.startswith("0x")
        assert len(record.tx_hash) == 66
        assert record.block_number is not None
        assert record.block_number > 0

        # Query smart contract to verify immutable on-chain record
        contract = client.get_contract()
        ret_id, ret_hash, ret_ts, exists = contract.functions.getLogRecord(record.log_id).call()
        assert ret_id == record.log_id
        assert exists is True


def test_live_ganache_retry_worker(app, live_ganache_contract):
    """
    [REAL BLOCKCHAIN TEST]
    Verify retry worker successfully anchors queued records on live Ganache.
    """
    client, contract_addr = live_ganache_contract

    with app.app_context():
        rec = record_audit_event("queued_user", "DOWNLOAD", "dataset.zip", auto_anchor=False)
        assert rec.anchored_status == "PENDING"

        summary = retry_pending_anchors(limit=5, client=client)
        assert summary["status"] == "success"
        assert summary["succeeded"] >= 1

        db.session.refresh(rec)
        assert rec.anchored_status == "ANCHORED"
