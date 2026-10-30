"""
Canonical Serialization and SHA-256 Hashing Service.
Enforces the strict canonical format defined in ARCHITECTURE.md:
LogID | UserID | ActionType | FileName | Timestamp

This module contains pure cryptographic and string serialization logic.
It has zero dependencies on databases, ORMs, or blockchain clients.
"""
import re
import hmac
import hashlib
import uuid
from datetime import datetime, timezone

# Strict ISO-8601 UTC regex pattern: YYYY-MM-DDTHH:MM:SSZ
ISO8601_UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# Supported Cloud Action Types
SUPPORTED_ACTIONS = {"LOGIN", "UPLOAD", "DOWNLOAD", "MODIFY", "DELETE"}


def validate_iso8601_utc(timestamp_str: str) -> bool:
    """
    Validate that a timestamp strictly conforms to ISO-8601 UTC format: YYYY-MM-DDTHH:MM:SSZ
    """
    if not isinstance(timestamp_str, str):
        return False
    if not ISO8601_UTC_PATTERN.match(timestamp_str):
        return False
    try:
        # Validate that the date and time components are calendar-valid
        datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except ValueError:
        return False


def escape_canonical_field(value: str) -> str:
    """
    Escape literal pipe characters and backslashes in canonical log fields.
    Leading and trailing whitespace is stripped.
    Backslashes are escaped as '\\\\', and pipes are escaped as '\\|'.
    """
    if value is None:
        return ""
    cleaned = str(value).strip()
    # Escape existing backslashes first to preserve idempotence, then escape pipes
    cleaned = cleaned.replace("\\", "\\\\").replace("|", "\\|")
    return cleaned


def canonical_serialize(log_id: str, user_id: str, action_type: str, file_name: str, timestamp: str) -> str:
    """
    Serialize audit record fields into the exact canonical string format:
    LogID | UserID | ActionType | FileName | Timestamp
    """
    escaped_id = escape_canonical_field(log_id)
    escaped_user = escape_canonical_field(user_id)
    escaped_action = escape_canonical_field(action_type).upper()
    escaped_file = escape_canonical_field(file_name)
    escaped_time = escape_canonical_field(timestamp)

    return f"{escaped_id} | {escaped_user} | {escaped_action} | {escaped_file} | {escaped_time}"


def compute_sha256_hash(canonical_string: str) -> str:
    """
    Compute deterministic SHA-256 hexadecimal digest from canonical string UTF-8 bytes.
    Returns 0x-prefixed 64-character lowercase hex digest matching Solidity bytes32 representation.
    """
    digest_hex = hashlib.sha256(canonical_string.encode("utf-8")).hexdigest().lower()
    return f"0x{digest_hex}"


def hash_audit_fields(log_id: str, user_id: str, action_type: str, file_name: str, timestamp: str) -> tuple[str, str]:
    """
    Convenience helper serializing the five canonical fields and computing the SHA-256 digest.
    Returns (canonical_string, hash_0x_hex).
    """
    canonical_str = canonical_serialize(log_id, user_id, action_type, file_name, timestamp)
    hash_hex = compute_sha256_hash(canonical_str)
    return canonical_str, hash_hex


def to_bytes32(hash_hex_str: str) -> bytes:
    """
    Convert 0x-prefixed 64-character hex string into exact 32-byte representation
    for Ethereum / Solidity bytes32 compatibility.
    """
    cleaned_hex = hash_hex_str.strip()
    if cleaned_hex.startswith("0x") or cleaned_hex.startswith("0X"):
        cleaned_hex = cleaned_hex[2:]

    if len(cleaned_hex) != 64:
        raise ValueError(f"Hex string must represent exactly 32 bytes (64 hex characters), got {len(cleaned_hex)}")

    raw_bytes = bytes.fromhex(cleaned_hex)
    if len(raw_bytes) != 32:
        raise ValueError(f"Expected 32 bytes, got {len(raw_bytes)}")
    return raw_bytes


def verify_canonical_hash(
    log_id: str,
    user_id: str,
    action_type: str,
    file_name: str,
    timestamp: str,
    expected_hash: str,
) -> bool:
    """
    Rebuild canonical string, recompute SHA-256 digest, and perform constant-time comparison
    against expected hash to verify record integrity.
    """
    canonical_str = canonical_serialize(log_id, user_id, action_type, file_name, timestamp)
    recalculated_hash = compute_sha256_hash(canonical_str)
    return hmac.compare_digest(recalculated_hash.lower(), expected_hash.strip().lower())


def generate_log_id() -> str:
    """
    Generate unique cryptographically secure Log ID:
    LOG-YYYYMMDD-<8-char-uuid-hex>
    """
    date_part = datetime.now(timezone.utc).strftime("%Y%m%d")
    unique_suffix = uuid.uuid4().hex[:8].upper()
    return f"LOG-{date_part}-{unique_suffix}"


def get_current_utc_iso() -> str:
    """
    Get current UTC timestamp formatted strictly as ISO-8601 string: YYYY-MM-DDTHH:MM:SSZ
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
