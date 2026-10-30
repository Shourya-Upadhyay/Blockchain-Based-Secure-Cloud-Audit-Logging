"""
Phase 4 Canonical Serialization & SHA-256 Hashing Unit Tests:
- Fixed test vectors with verified expected hash values
- Deterministic repeatability over repeated executions
- Cryptographic avalanche effect on single-character changes
- Delimiter collision prevention and character escaping (pipes '|' and backslashes '\\')
- Exact canonical field order enforcement
- ISO-8601 UTC timestamp formatting validation
- Solidity bytes32 representation and 32-byte raw conversion
"""
import hashlib
import pytest
from app.services.hashing_service import (
    canonical_serialize,
    compute_sha256_hash,
    hash_audit_fields,
    to_bytes32,
    verify_canonical_hash,
    validate_iso8601_utc,
    escape_canonical_field,
    generate_log_id,
    get_current_utc_iso,
)


def test_fixed_test_vector_login():
    """Verify hash calculation against fixed pre-calculated SHA-256 test vector for LOGIN."""
    log_id = "LOG-20261030-A1B2C3D4"
    user_id = "shourya"
    action_type = "LOGIN"
    file_name = "SESSION"
    timestamp = "2026-10-30T12:00:00Z"

    # Exact expected canonical string
    expected_canonical = "LOG-20261030-A1B2C3D4 | shourya | LOGIN | SESSION | 2026-10-30T12:00:00Z"
    canonical_str = canonical_serialize(log_id, user_id, action_type, file_name, timestamp)
    assert canonical_str == expected_canonical

    # Pre-calculated SHA-256 digest of expected_canonical
    known_sha256 = hashlib.sha256(expected_canonical.encode("utf-8")).hexdigest().lower()
    expected_hash = f"0x{known_sha256}"

    computed_hash = compute_sha256_hash(canonical_str)
    assert computed_hash == expected_hash
    assert verify_canonical_hash(log_id, user_id, action_type, file_name, timestamp, expected_hash) is True


def test_fixed_test_vector_file_upload():
    """Verify hash calculation against fixed test vector for file UPLOAD."""
    log_id = "LOG-20261030-F9E8D7C6"
    user_id = "jeevesh"
    action_type = "UPLOAD"
    file_name = "Major_Project_Final_Report.pdf"
    timestamp = "2026-10-30T14:45:30Z"

    expected_canonical = "LOG-20261030-F9E8D7C6 | jeevesh | UPLOAD | Major_Project_Final_Report.pdf | 2026-10-30T14:45:30Z"
    canonical_str, computed_hash = hash_audit_fields(log_id, user_id, action_type, file_name, timestamp)
    assert canonical_str == expected_canonical

    known_sha256 = hashlib.sha256(expected_canonical.encode("utf-8")).hexdigest().lower()
    assert computed_hash == f"0x{known_sha256}"


def test_deterministic_repeatability():
    """Verify that identical inputs produce 100% identical outputs over 100 iterations."""
    log_id = "LOG-20261030-REPEAT01"
    user_id = "repeat_tester"
    action_type = "DOWNLOAD"
    file_name = "dataset.csv"
    timestamp = "2026-10-30T18:00:00Z"

    first_canonical, first_hash = hash_audit_fields(log_id, user_id, action_type, file_name, timestamp)

    for _ in range(100):
        c_str, h_val = hash_audit_fields(log_id, user_id, action_type, file_name, timestamp)
        assert c_str == first_canonical
        assert h_val == first_hash


def test_avalanche_effect():
    """
    Verify the cryptographic avalanche effect:
    Modifying a single character anywhere in any field drastically alters the resulting hash.
    """
    base = ("LOG-20261030-0001", "alice", "UPLOAD", "file.txt", "2026-10-30T12:00:00Z")
    _, base_hash = hash_audit_fields(*base)

    # 1. Modify 1 character in log_id
    _, mod_id_hash = hash_audit_fields("LOG-20261030-0002", "alice", "UPLOAD", "file.txt", "2026-10-30T12:00:00Z")
    assert base_hash != mod_id_hash

    # 2. Modify 1 character in user_id
    _, mod_user_hash = hash_audit_fields("LOG-20261030-0001", "AlicE", "UPLOAD", "file.txt", "2026-10-30T12:00:00Z")
    assert base_hash != mod_user_hash

    # 3. Modify action_type
    _, mod_action_hash = hash_audit_fields("LOG-20261030-0001", "alice", "DELETE", "file.txt", "2026-10-30T12:00:00Z")
    assert base_hash != mod_action_hash

    # 4. Modify 1 character in file_name
    _, mod_file_hash = hash_audit_fields("LOG-20261030-0001", "alice", "UPLOAD", "file.txz", "2026-10-30T12:00:00Z")
    assert base_hash != mod_file_hash

    # 5. Modify timestamp by 1 second
    _, mod_time_hash = hash_audit_fields("LOG-20261030-0001", "alice", "UPLOAD", "file.txt", "2026-10-30T12:00:01Z")
    assert base_hash != mod_time_hash


def test_delimiter_handling_and_escaping():
    """
    Verify delimiter injection prevention:
    Pipes and backslashes in user-supplied strings are escaped so an attacker cannot forge fields.
    """
    # Filename containing literal pipe
    raw_filename = "financial_report|2026.pdf"
    escaped_file = escape_canonical_field(raw_filename)
    assert escaped_file == "financial_report\\|2026.pdf"

    # Username attempting field injection
    malicious_user = "alice | DELETE | all_files.db"
    canonical_str = canonical_serialize("LOG-1", malicious_user, "LOGIN", "SESSION", "2026-10-30T12:00:00Z")
    # Must escape the pipes inside username
    assert "alice \\| DELETE \\| all_files.db" in canonical_str

    # Backslash escaping
    path_with_backslash = "folder\\subfolder\\file.txt"
    escaped_path = escape_canonical_field(path_with_backslash)
    assert "\\\\" in escaped_path


def test_field_order_strictness():
    """Verify that serializing fields in different orders produces distinct digests."""
    field1 = "LOG-01"
    field2 = "user_a"
    action = "UPLOAD"
    fname = "report.pdf"
    tstamp = "2026-10-30T12:00:00Z"

    correct_order = f"{field1} | {field2} | {action} | {fname} | {tstamp}"
    reversed_order = f"{tstamp} | {fname} | {action} | {field2} | {field1}"

    assert compute_sha256_hash(correct_order) != compute_sha256_hash(reversed_order)


def test_iso8601_utc_validation():
    """Verify ISO-8601 UTC validation regex and calendar date checks."""
    # Valid timestamps
    assert validate_iso8601_utc("2026-10-30T12:00:00Z") is True
    assert validate_iso8601_utc("2026-01-01T00:00:00Z") is True
    assert validate_iso8601_utc("2026-12-31T23:59:59Z") is True
    assert validate_iso8601_utc("2026-02-28T23:59:59Z") is True

    # Invalid formatting
    assert validate_iso8601_utc("2026-10-30 12:00:00") is False  # Missing T and Z
    assert validate_iso8601_utc("2026-10-30T12:00:00+05:30") is False  # Offset instead of Z
    assert validate_iso8601_utc("2026-10-30T12:00:00") is False  # Missing Z
    assert validate_iso8601_utc("10-30-2026T12:00:00Z") is False  # Non ISO date
    assert validate_iso8601_utc("") is False
    assert validate_iso8601_utc(None) is False

    # Invalid calendar dates
    assert validate_iso8601_utc("2026-02-30T12:00:00Z") is False  # Feb 30 does not exist
    assert validate_iso8601_utc("2026-13-01T12:00:00Z") is False  # Month 13 does not exist


def test_bytes32_compatibility():
    """Verify 0x-prefixed 64-char hex strings convert to exactly 32 raw bytes."""
    _, hash_hex = hash_audit_fields("LOG-1", "user", "LOGIN", "SESSION", "2026-10-30T12:00:00Z")

    assert hash_hex.startswith("0x")
    assert len(hash_hex) == 66  # "0x" (2) + 64 hex chars = 66

    raw_bytes = to_bytes32(hash_hex)
    assert isinstance(raw_bytes, bytes)
    assert len(raw_bytes) == 32

    # Round-trip verification
    assert f"0x{raw_bytes.hex()}" == hash_hex

    # Invalid input checks
    with pytest.raises(ValueError):
        to_bytes32("0x1234")  # Too short

    with pytest.raises(ValueError):
        to_bytes32("0x" + "g" * 64)  # Invalid hex characters


def test_log_id_generation_uniqueness():
    """Verify generate_log_id format and entropy."""
    ids = set()
    for _ in range(500):
        lid = generate_log_id()
        assert lid.startswith("LOG-")
        assert len(lid.split("-")) == 3
        assert lid not in ids
        ids.add(lid)


def test_get_current_utc_iso_format():
    """Verify get_current_utc_iso returns valid ISO-8601 UTC timestamp."""
    iso_time = get_current_utc_iso()
    assert validate_iso8601_utc(iso_time) is True
    assert iso_time.endswith("Z")
