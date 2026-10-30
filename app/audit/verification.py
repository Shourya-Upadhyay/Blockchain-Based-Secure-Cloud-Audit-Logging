"""
Auditor Verification Engine.
Performs dual-layer cryptographic verification and discrepancy detection:
1. Re-serializes off-chain SQLite audit records into canonical strings.
2. Recomputes SHA-256 digests.
3. Compares recomputed digests with immutable hashes anchored on the smart contract.
4. Cross-checks all on-chain log IDs to detect deleted SQL records (MISSING_SQL).
5. Categorizes distinct statuses: VERIFIED, TAMPERED, MISSING_SQL, UNANCHORED, BLOCKCHAIN_UNAVAILABLE.
Never classifies network unavailability as proof of tampering.
"""
import logging
from datetime import datetime, timezone
from app.extensions import db
from app.models.audit_log import AuditLog
from app.services.hashing_service import (
    canonical_serialize,
    compute_sha256_hash,
)
from app.blockchain.client import get_blockchain_client, BlockchainClient

logger = logging.getLogger(__name__)

# Verification status constants
STATUS_VERIFIED = "VERIFIED"
STATUS_TAMPERED = "TAMPERED"
STATUS_MISSING_SQL = "MISSING_SQL"
STATUS_UNANCHORED = "UNANCHORED"
STATUS_BLOCKCHAIN_UNAVAILABLE = "BLOCKCHAIN_UNAVAILABLE"


def verify_audit_trail(client: BlockchainClient | None = None) -> dict:
    """
    Execute full cryptographic verification of all audit records.
    
    Returns structured verification report:
    {
        "timestamp": "ISO-8601 UTC",
        "blockchain_status": "ONLINE" | "OFFLINE",
        "summary": {
            "total_sql_records": int,
            "total_chain_records": int,
            "verified": int,
            "tampered": int,
            "missing_sql": int,
            "unanchored": int,
            "blockchain_unavailable": int,
        },
        "records": [
            {
                "log_id": str,
                "user_id": str,
                "action_type": str,
                "file_name": str,
                "timestamp": str,
                "verification_status": str,
                "recalculated_hash": str | None,
                "stored_sql_hash": str | None,
                "on_chain_hash": str | None,
                "tx_hash": str | None,
                "block_number": int | None,
                "details": str,
            },
            ...
        ]
    }
    """
    bclient = client or get_blockchain_client()
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Fetch all off-chain SQL records
    sql_records = AuditLog.query.order_by(AuditLog.id.desc()).all()
    sql_records_by_id = {rec.log_id: rec for rec in sql_records}

    # Check blockchain reachability and contract availability
    is_online = bclient.is_connected()
    contract = bclient.get_contract() if is_online else None

    # Handle scenario: Blockchain is OFFLINE
    if not is_online or contract is None:
        logger.info("Verification engine: Blockchain RPC offline. Classifying as BLOCKCHAIN_UNAVAILABLE.")
        records_out = []
        for rec in sql_records:
            # Recompute canonical hash to check internal SQL consistency
            canonical_str = canonical_serialize(
                rec.log_id, rec.user_id, rec.action_type, rec.file_name, rec.timestamp
            )
            recalculated_hash = compute_sha256_hash(canonical_str)
            internal_mismatch = (recalculated_hash.lower() != (rec.log_hash or "").lower())

            details = (
                "Blockchain testnet is offline or unreachable. "
                "Unable to verify against immutable smart contract. "
                "(Connection failure - NOT classified as tampering)"
            )
            if internal_mismatch:
                details += f" [Warning: Internal SQL row stored hash {rec.log_hash} does not match recalculated {recalculated_hash}]"

            records_out.append({
                "log_id": rec.log_id,
                "user_id": rec.user_id,
                "action_type": rec.action_type,
                "file_name": rec.file_name,
                "timestamp": rec.timestamp,
                "verification_status": STATUS_BLOCKCHAIN_UNAVAILABLE,
                "recalculated_hash": recalculated_hash,
                "stored_sql_hash": rec.log_hash,
                "on_chain_hash": None,
                "tx_hash": rec.tx_hash,
                "block_number": rec.block_number,
                "details": details,
            })

        return {
            "timestamp": now_utc,
            "blockchain_status": "OFFLINE",
            "summary": {
                "total_sql_records": len(sql_records),
                "total_chain_records": 0,
                "verified": 0,
                "tampered": 0,
                "missing_sql": 0,
                "unanchored": 0,
                "blockchain_unavailable": len(sql_records),
            },
            "records": records_out,
        }

    # Scenario: Blockchain is ONLINE
    records_out = []
    counts = {
        "verified": 0,
        "tampered": 0,
        "missing_sql": 0,
        "unanchored": 0,
        "blockchain_unavailable": 0,
    }

    try:
        raw_chain_ids = contract.functions.getAllLogIds().call()
        all_chain_ids = set(raw_chain_ids)
    except Exception as e:
        logger.error(f"Failed to query getAllLogIds from contract: {e}")
        all_chain_ids = set()

    # Step 1: Verify each off-chain SQL record against the smart contract
    for rec in sql_records:
        canonical_str = canonical_serialize(
            rec.log_id, rec.user_id, rec.action_type, rec.file_name, rec.timestamp
        )
        recalculated_hash = compute_sha256_hash(canonical_str)

        # Check if record has been anchored on-chain
        if rec.log_id not in all_chain_ids:
            # Check contract directly in case array was not populated
            try:
                is_anchored = contract.functions.isLogAnchored(rec.log_id).call()
            except Exception:
                is_anchored = False

            if not is_anchored:
                status = STATUS_UNANCHORED
                counts["unanchored"] += 1
                details = "Record exists in local SQLite database but has not been anchored to the blockchain."
                records_out.append({
                    "log_id": rec.log_id,
                    "user_id": rec.user_id,
                    "action_type": rec.action_type,
                    "file_name": rec.file_name,
                    "timestamp": rec.timestamp,
                    "verification_status": status,
                    "recalculated_hash": recalculated_hash,
                    "stored_sql_hash": rec.log_hash,
                    "on_chain_hash": None,
                    "tx_hash": rec.tx_hash,
                    "block_number": rec.block_number,
                    "details": details,
                })
                continue

        # Record exists on-chain: Retrieve on-chain record
        try:
            ret_id, ret_hash_bytes, ret_ts, exists = contract.functions.getLogRecord(rec.log_id).call()
            on_chain_hex = f"0x{ret_hash_bytes.hex().lower()}"

            if not exists:
                status = STATUS_UNANCHORED
                counts["unanchored"] += 1
                details = "Record marked non-existent in contract registry."
            elif recalculated_hash.lower() == on_chain_hex:
                status = STATUS_VERIFIED
                counts["verified"] += 1
                details = "Cryptographic integrity verified: Recomputed canonical SHA-256 matches immutable on-chain hash."
            else:
                status = STATUS_TAMPERED
                counts["tampered"] += 1
                details = (
                    f"TAMPER DETECTED: Off-chain SQL row has been modified! "
                    f"Recalculated: {recalculated_hash} != On-chain: {on_chain_hex}"
                )

            records_out.append({
                "log_id": rec.log_id,
                "user_id": rec.user_id,
                "action_type": rec.action_type,
                "file_name": rec.file_name,
                "timestamp": rec.timestamp,
                "verification_status": status,
                "recalculated_hash": recalculated_hash,
                "stored_sql_hash": rec.log_hash,
                "on_chain_hash": on_chain_hex,
                "tx_hash": rec.tx_hash,
                "block_number": rec.block_number,
                "details": details,
            })

        except Exception as e:
            logger.error(f"Error querying getLogRecord for {rec.log_id}: {e}")
            records_out.append({
                "log_id": rec.log_id,
                "user_id": rec.user_id,
                "action_type": rec.action_type,
                "file_name": rec.file_name,
                "timestamp": rec.timestamp,
                "verification_status": STATUS_BLOCKCHAIN_UNAVAILABLE,
                "recalculated_hash": recalculated_hash,
                "stored_sql_hash": rec.log_hash,
                "on_chain_hash": None,
                "tx_hash": rec.tx_hash,
                "block_number": rec.block_number,
                "details": f"RPC query error: {e}",
            })
            counts["blockchain_unavailable"] += 1

    # Step 2: Detect deleted SQL records (MISSING_SQL)
    # Check all on-chain IDs for any that do NOT exist in SQLite audit_logs
    missing_from_sql = all_chain_ids - set(sql_records_by_id.keys())
    for missing_id in sorted(list(missing_from_sql)):
        try:
            ret_id, ret_hash_bytes, ret_ts, exists = contract.functions.getLogRecord(missing_id).call()
            on_chain_hex = f"0x{ret_hash_bytes.hex().lower()}"
            ts_iso = datetime.fromtimestamp(ret_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ret_ts else "UNKNOWN"
        except Exception:
            on_chain_hex = "UNKNOWN"
            ts_iso = "UNKNOWN"

        counts["missing_sql"] += 1
        records_out.insert(0, {
            "log_id": missing_id,
            "user_id": "UNKNOWN [DELETED]",
            "action_type": "UNKNOWN",
            "file_name": "UNKNOWN",
            "timestamp": ts_iso,
            "verification_status": STATUS_MISSING_SQL,
            "recalculated_hash": None,
            "stored_sql_hash": None,
            "on_chain_hash": on_chain_hex,
            "tx_hash": None,
            "block_number": None,
            "details": (
                "DELETED RECORD DETECTED: This log ID is permanently anchored on the blockchain, "
                "but its corresponding row in the local SQL database has been destroyed/deleted."
            ),
        })

    return {
        "timestamp": now_utc,
        "blockchain_status": "ONLINE",
        "summary": {
            "total_sql_records": len(sql_records),
            "total_chain_records": len(all_chain_ids),
            "verified": counts["verified"],
            "tampered": counts["tampered"],
            "missing_sql": counts["missing_sql"],
            "unanchored": counts["unanchored"],
            "blockchain_unavailable": counts["blockchain_unavailable"],
        },
        "records": records_out,
    }
