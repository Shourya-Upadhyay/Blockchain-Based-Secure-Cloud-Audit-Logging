"""
Centralized Audit Service Interface.
Dispatches and records verified audit events into SQLite off-chain storage.
Separates SQL audit persistence from cryptographic hashing and blockchain anchoring.
"""
from app.extensions import db
from app.models.audit_log import AuditLog
from app.services.hashing_service import (
    canonical_serialize,
    compute_sha256_hash,
    hash_audit_fields,
    generate_log_id,
    get_current_utc_iso,
    validate_iso8601_utc,
    SUPPORTED_ACTIONS,
)


def record_audit_event(
    user_id: str,
    action_type: str,
    file_name: str | None = None,
    timestamp: str | None = None,
    log_id: str | None = None,
    auto_anchor: bool = True,
) -> AuditLog:
    """
    Record a single verified cloud or authentication event in the SQL audit log,
    and attempt real-time blockchain hash anchoring if auto_anchor is enabled.
    
    Parameters:
    - user_id: Username or identifier of the user performing the action.
    - action_type: Event type (LOGIN, UPLOAD, DOWNLOAD, MODIFY, DELETE).
    - file_name: Target filename or 'SESSION' (defaults to 'SESSION' for LOGIN).
    - timestamp: Optional ISO-8601 UTC timestamp string (auto-generated if omitted).
    - log_id: Optional unique Log ID (auto-generated if omitted).
    - auto_anchor: When True, immediately submits the SHA-256 hash to the smart contract.

    Returns:
    - The committed AuditLog database entity.
    """
    normalized_action = (action_type or "").strip().upper()
    if normalized_action not in SUPPORTED_ACTIONS:
        raise ValueError(f"Invalid action_type '{action_type}'. Must be one of {sorted(list(SUPPORTED_ACTIONS))}")

    clean_user = (user_id or "").strip()
    if not clean_user:
        clean_user = "ANONYMOUS"

    clean_file = (file_name or "").strip()
    if not clean_file:
        if normalized_action == "LOGIN":
            clean_file = "SESSION"
        else:
            raise ValueError(f"Action '{normalized_action}' requires a valid file_name.")

    final_log_id = log_id.strip() if log_id else generate_log_id()

    if timestamp:
        clean_timestamp = timestamp.strip()
        if not validate_iso8601_utc(clean_timestamp):
            raise ValueError(f"Timestamp '{timestamp}' does not conform to ISO-8601 UTC format (YYYY-MM-DDTHH:MM:SSZ)")
    else:
        clean_timestamp = get_current_utc_iso()

    # Derive deterministic canonical string and 0x-prefixed SHA-256 hash
    canonical_str, log_hash = hash_audit_fields(
        log_id=final_log_id,
        user_id=clean_user,
        action_type=normalized_action,
        file_name=clean_file,
        timestamp=clean_timestamp,
    )

    # Persist in SQLite first (database transaction committed before blockchain call)
    audit_entry = AuditLog(
        log_id=final_log_id,
        user_id=clean_user,
        action_type=normalized_action,
        file_name=clean_file,
        timestamp=clean_timestamp,
        log_hash=log_hash,
        anchored_status="PENDING",
        retry_count=0,
    )

    db.session.add(audit_entry)
    db.session.commit()

    # Attempt two-phase blockchain hash anchoring
    if auto_anchor:
        try:
            from app.blockchain.anchoring import anchor_single_log
            anchor_single_log(audit_entry.id)
            db.session.refresh(audit_entry)
        except Exception:
            # Ensure off-chain database transaction is never affected by RPC errors
            pass

    return audit_entry


def get_audit_log_by_id(log_id: str) -> AuditLog | None:
    """Retrieve an audit log row by its unique log_id."""
    return AuditLog.query.filter_by(log_id=log_id).first()


def get_all_audit_logs(
    user_id: str | None = None,
    action_type: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[AuditLog]:
    """Retrieve filtered audit logs ordered chronologically by ID descending."""
    query = AuditLog.query

    if user_id:
        query = query.filter_by(user_id=user_id.strip())
    if action_type:
        query = query.filter_by(action_type=action_type.strip().upper())

    query = query.order_by(AuditLog.id.desc())

    if offset:
        query = query.offset(offset)
    if limit:
        query = query.limit(limit)

    return query.all()


def recalculate_audit_log_hash(audit_log: AuditLog) -> tuple[str, str]:
    """
    Rebuild the canonical string from an AuditLog's immutable fields and recompute its SHA-256 digest.
    Crucially ignores mutable metadata: anchored_status, tx_hash, block_number, error_message, retry_count.
    """
    return hash_audit_fields(
        log_id=audit_log.log_id,
        user_id=audit_log.user_id,
        action_type=audit_log.action_type,
        file_name=audit_log.file_name,
        timestamp=audit_log.timestamp,
    )


def is_audit_log_tampered(audit_log: AuditLog) -> bool:
    """
    Check if the off-chain SQL record's current fields match its stored SHA-256 digest.
    Returns True if fields have been tampered with; False if intact.
    """
    _, recalculated_hash = recalculate_audit_log_hash(audit_log)
    return recalculated_hash.lower() != audit_log.log_hash.lower()
