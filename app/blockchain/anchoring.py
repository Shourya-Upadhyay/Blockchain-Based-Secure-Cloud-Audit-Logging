"""
Hash Anchoring Service & Two-Phase Commit Logic.
Manages immutable hash submission to AuditLogContract on Ethereum/Ganache,
handles network timeouts, duplicate-transaction prevention, retry queue,
and guarantees database transactions are not held open during Web3 RPC wait.
"""
import logging
from datetime import datetime
from flask import current_app, has_app_context
from app.extensions import db
from app.models.audit_log import AuditLog
from app.services.hashing_service import to_bytes32
from app.blockchain.client import get_blockchain_client, BlockchainClient

logger = logging.getLogger(__name__)


def parse_iso_to_unix(iso_str: str) -> int:
    """Convert strict ISO-8601 UTC timestamp string to integer Unix seconds."""
    try:
        clean_str = iso_str.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        return int(dt.timestamp())
    except Exception:
        return int(datetime.utcnow().timestamp())


def anchor_single_log(audit_log_id: int, client: BlockchainClient | None = None) -> bool:
    """
    Anchor a single SQL audit record to the smart contract.
    
    Architectural Guarantees:
    1. SQL record is already committed before this function is called.
    2. Database transactions are NOT held open while awaiting blockchain mining.
    3. Idempotent: Verifies if log_id is already anchored on-chain before sending tx.
    4. On network / RPC failure, preserves SQL record with status 'PENDING' and records error.
    5. On successful receipt confirmation (status == 1), records tx_hash and block_number in SQL.
    
    Returns True if successfully anchored (or already anchored), False otherwise.
    """
    bclient = client or get_blockchain_client()

    # Phase 1: Retrieve immutable record fields from SQL and detach/commit
    audit_entry = db.session.get(AuditLog, audit_log_id)
    if not audit_entry:
        logger.warning(f"Audit log ID {audit_log_id} not found for anchoring.")
        return False

    log_id = audit_entry.log_id
    log_hash_hex = audit_entry.log_hash
    timestamp_str = audit_entry.timestamp

    # Commit and end current DB transaction so no locks are held during Web3 RPC calls
    db.session.commit()

    # Phase 2: Check blockchain connection and contract availability
    if not bclient.is_connected():
        logger.info(f"Ganache RPC offline. Record {log_id} remains safely stored as PENDING.")
        _update_status_safely(audit_log_id, "PENDING", error="Blockchain RPC endpoint unreachable")
        return False

    contract = bclient.get_contract()
    if not contract:
        logger.info(f"Smart contract not available or not deployed. Record {log_id} remains PENDING.")
        _update_status_safely(audit_log_id, "PENDING", error="Contract not deployed or address missing")
        return False

    w3 = bclient.get_web3()
    deployer, private_key = bclient.get_signing_account()

    if not deployer:
        logger.error("No deployer or signing account available for blockchain transaction.")
        _update_status_safely(audit_log_id, "PENDING", error="No signing account available")
        return False

    # Phase 3: Idempotent pre-flight check - Has this logId already been anchored on-chain?
    try:
        already_anchored = contract.functions.isLogAnchored(log_id).call()
        if already_anchored:
            logger.info(f"Log ID {log_id} is already anchored on-chain. Syncing SQL record to ANCHORED.")
            _update_status_safely(audit_log_id, "ANCHORED", error=None)
            return True
    except Exception as e:
        logger.warning(f"Error checking isLogAnchored for {log_id}: {e}")

    # Phase 4: Submit transaction
    try:
        raw_hash = to_bytes32(log_hash_hex)
        unix_ts = parse_iso_to_unix(timestamp_str)

        if private_key:
            nonce = w3.eth.get_transaction_count(deployer)
            tx = contract.functions.storeLogHash(log_id, raw_hash, unix_ts).build_transaction({
                "from": deployer,
                "nonce": nonce,
                "gas": 300000,
                "gasPrice": w3.eth.gas_price,
            })
            signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)
            tx_hash_bytes = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            tx_hash_hex = tx_hash_bytes.hex()
        else:
            tx_hash = contract.functions.storeLogHash(log_id, raw_hash, unix_ts).transact({
                "from": deployer,
                "gas": 300000,
            })
            tx_hash_hex = tx_hash.hex()

        logger.info(f"Submitted anchor transaction {tx_hash_hex} for {log_id}. Awaiting receipt...")

        # Phase 5: Await receipt and verify confirmation
        timeout = 15
        if has_app_context() and "WEB3_TIMEOUT_SECONDS" in current_app.config:
            timeout = int(current_app.config["WEB3_TIMEOUT_SECONDS"])

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash_hex, timeout=timeout)

        if receipt.status == 1:
            logger.info(f"Record {log_id} confirmed in block {receipt.blockNumber} (tx: {tx_hash_hex}).")
            _update_status_safely(
                audit_log_id,
                status="ANCHORED",
                tx_hash=receipt.transactionHash.hex(),
                block_number=receipt.blockNumber,
                error=None,
            )
            return True
        else:
            logger.error(f"Transaction for {log_id} reverted on-chain. Status: {receipt.status}")
            _increment_retry_or_fail(audit_log_id, error="Transaction reverted on-chain")
            return False

    except Exception as e:
        err_msg = str(e)
        logger.warning(f"Blockchain submission error for {log_id}: {err_msg}")
        _increment_retry_or_fail(audit_log_id, error=err_msg[:255])
        return False


def _update_status_safely(
    audit_log_id: int,
    status: str,
    tx_hash: str | None = None,
    block_number: int | None = None,
    error: str | None = None,
) -> None:
    """Update SQL record status inside an isolated short-lived database transaction."""
    try:
        rec = db.session.get(AuditLog, audit_log_id)
        if rec:
            rec.anchored_status = status
            if tx_hash:
                rec.tx_hash = tx_hash
            if block_number is not None:
                rec.block_number = block_number
            rec.error_message = error
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Could not update status for audit log {audit_log_id}: {e}")


def _increment_retry_or_fail(audit_log_id: int, error: str) -> None:
    """Increment retry count and transition to FAILED if retry limit reached."""
    retry_limit = 3
    if has_app_context() and "ANCHOR_RETRY_LIMIT" in current_app.config:
        retry_limit = int(current_app.config["ANCHOR_RETRY_LIMIT"])

    try:
        rec = db.session.get(AuditLog, audit_log_id)
        if rec:
            rec.retry_count += 1
            rec.error_message = error
            if rec.retry_count >= retry_limit:
                rec.anchored_status = "FAILED"
            else:
                rec.anchored_status = "PENDING"
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating retry count for audit log {audit_log_id}: {e}")


def retry_pending_anchors(limit: int = 50, client: BlockchainClient | None = None) -> dict:
    """
    Worker task: Process queued PENDING audit records.
    Called on startup or via auditor retry action.
    """
    bclient = client or get_blockchain_client()
    if not bclient.is_connected() or not bclient.get_contract():
        return {
            "status": "offline",
            "message": "Blockchain RPC is unreachable or contract not deployed",
            "processed": 0,
            "succeeded": 0,
            "failed": 0,
        }

    retry_limit = 3
    if has_app_context() and "ANCHOR_RETRY_LIMIT" in current_app.config:
        retry_limit = int(current_app.config["ANCHOR_RETRY_LIMIT"])

    pending_records = (
        AuditLog.query.filter(
            AuditLog.anchored_status == "PENDING",
            AuditLog.retry_count < retry_limit,
        )
        .order_by(AuditLog.id.asc())
        .limit(limit)
        .all()
    )

    succeeded = 0
    failed = 0

    # Extract IDs to avoid keeping ORM references across transactions
    target_ids = [rec.id for rec in pending_records]

    for record_id in target_ids:
        success = anchor_single_log(record_id, client=bclient)
        if success:
            succeeded += 1
        else:
            failed += 1

    return {
        "status": "success",
        "processed": len(target_ids),
        "succeeded": succeeded,
        "failed": failed,
    }


def get_anchoring_stats() -> dict:
    """Return off-chain aggregation of anchoring statuses."""
    total = AuditLog.query.count()
    anchored = AuditLog.query.filter_by(anchored_status="ANCHORED").count()
    pending = AuditLog.query.filter_by(anchored_status="PENDING").count()
    failed = AuditLog.query.filter_by(anchored_status="FAILED").count()

    return {
        "total_events": total,
        "anchored_count": anchored,
        "pending_count": pending,
        "failed_count": failed,
    }
