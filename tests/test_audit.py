"""
Phase 4 Centralized Audit Service & SQL Persistence Integration Tests:
- Recording of all 5 supported actions: LOGIN, UPLOAD, DOWNLOAD, MODIFY, DELETE
- Automatic SESSION filename assignment for LOGIN events
- Input validation and rejection of unsupported actions or missing filenames
- Custom ISO-8601 UTC timestamp validation
- Hash recalculation and off-chain SQL row tamper detection
- Invariance of canonical hash against mutable anchoring fields (tx_hash, block_number, status)
- Audit log query helpers
- End-to-end integration confirming real file operations generate complete audit trails
"""
import io
import pytest
from app.extensions import db
from app.models.user import User
from app.models.audit_log import AuditLog
from app.services.audit_service import (
    record_audit_event,
    get_audit_log_by_id,
    get_all_audit_logs,
    recalculate_audit_log_hash,
    is_audit_log_tampered,
)
from app.services.hashing_service import SUPPORTED_ACTIONS


def test_record_audit_event_all_actions(app):
    """Test creating audit records for all five supported cloud actions."""
    with app.app_context():
        for action in SUPPORTED_ACTIONS:
            fname = "SESSION" if action == "LOGIN" else f"target_{action.lower()}.bin"
            log = record_audit_event(
                user_id="audit_actor",
                action_type=action,
                file_name=fname,
                auto_anchor=False,
            )
            assert log.id is not None
            assert log.action_type == action
            assert log.user_id == "audit_actor"
            assert log.file_name == fname
            assert log.anchored_status == "PENDING"
            assert log.retry_count == 0
            assert log.tx_hash is None
            assert log.block_number is None
            assert log.log_hash.startswith("0x")
            assert len(log.log_hash) == 66


def test_login_action_default_session_filename(app):
    """Test that LOGIN events default to 'SESSION' when filename is omitted."""
    with app.app_context():
        log = record_audit_event("alice_login", "LOGIN")
        assert log.action_type == "LOGIN"
        assert log.file_name == "SESSION"


def test_invalid_action_rejected(app):
    """Test that unsupported action types raise ValueError."""
    with app.app_context():
        with pytest.raises(ValueError) as excinfo:
            record_audit_event("actor", "UNSUPPORTED_ACTION", "file.txt")
        assert "Invalid action_type" in str(excinfo.value)


def test_missing_filename_for_file_actions_rejected(app):
    """Test that file actions (UPLOAD, DOWNLOAD, MODIFY, DELETE) require a valid filename."""
    with app.app_context():
        for action in ["UPLOAD", "DOWNLOAD", "MODIFY", "DELETE"]:
            with pytest.raises(ValueError) as excinfo:
                record_audit_event("actor", action, file_name="")
            assert "requires a valid file_name" in str(excinfo.value)


def test_custom_timestamp_validation(app):
    """Test custom timestamp acceptance and invalid timestamp rejection."""
    with app.app_context():
        # Valid ISO-8601 UTC timestamp
        log = record_audit_event(
            user_id="actor",
            action_type="UPLOAD",
            file_name="doc.pdf",
            timestamp="2026-10-30T10:15:30Z",
        )
        assert log.timestamp == "2026-10-30T10:15:30Z"

        # Invalid timestamp format raises ValueError
        with pytest.raises(ValueError) as excinfo:
            record_audit_event(
                user_id="actor",
                action_type="UPLOAD",
                file_name="doc.pdf",
                timestamp="2026-10-30 10:15:30",  # Missing T and Z
            )
        assert "does not conform to ISO-8601 UTC" in str(excinfo.value)


def test_recalculate_hash_and_tamper_detection(app):
    """
    Test that tampering with off-chain SQL fields is detected through hash mismatch.
    """
    with app.app_context():
        log = record_audit_event(
            user_id="legit_user",
            action_type="UPLOAD",
            file_name="financial_ledger.xlsx",
        )
        original_hash = log.log_hash

        # Initially intact
        assert is_audit_log_tampered(log) is False
        _, recalc_hash = recalculate_audit_log_hash(log)
        assert recalc_hash == original_hash

        # Simulate rogue insider tampering: directly update the action in SQL to DELETE
        log.action_type = "DELETE"
        db.session.commit()

        # Verification engine immediately catches the tampering
        assert is_audit_log_tampered(log) is True
        _, tampered_hash = recalculate_audit_log_hash(log)
        assert tampered_hash != original_hash


def test_mutable_fields_do_not_alter_canonical_hash(app):
    """
    CRITICAL ARCHITECTURAL RULE:
    Mutable fields (anchored_status, tx_hash, block_number, error_message, retry_count)
    must NOT affect the canonical serialization or hash.
    """
    with app.app_context():
        log = record_audit_event(
            user_id="blockchain_tester",
            action_type="MODIFY",
            file_name="system_config.json",
        )
        initial_hash = log.log_hash

        # Simulate on-chain confirmation updating mutable anchoring fields
        log.anchored_status = "ANCHORED"
        log.tx_hash = "0x" + "e" * 64
        log.block_number = 12345
        log.retry_count = 2
        log.error_message = None
        db.session.commit()

        # Recalculated hash remains strictly identical!
        _, new_hash = recalculate_audit_log_hash(log)
        assert new_hash == initial_hash
        assert is_audit_log_tampered(log) is False


def test_audit_log_query_helpers(app):
    """Test get_audit_log_by_id and get_all_audit_logs filtering."""
    with app.app_context():
        log1 = record_audit_event("user_alpha", "UPLOAD", "file_alpha.txt")
        log2 = record_audit_event("user_beta", "DOWNLOAD", "file_beta.txt")
        log3 = record_audit_event("user_alpha", "DELETE", "file_alpha.txt")

        # By ID
        found = get_audit_log_by_id(log1.log_id)
        assert found is not None
        assert found.user_id == "user_alpha"

        # Filter by user
        alpha_logs = get_all_audit_logs(user_id="user_alpha")
        assert len(alpha_logs) == 2

        # Filter by action
        downloads = get_all_audit_logs(action_type="DOWNLOAD")
        assert len(downloads) == 1
        assert downloads[0].log_id == log2.log_id


def test_end_to_end_audit_pipeline(client, app):
    """
    Integration test confirming that all client operations (login, upload, download, modify, delete)
    generate verified audit records in the off-chain SQLite database.
    """
    # 1. Register user
    client.post(
        "/auth/register",
        data={"username": "pipeline_user", "password": "PipelinePass2026!", "confirm_password": "PipelinePass2026!"},
    )

    # 2. Login -> LOGIN audit event
    client.post(
        "/auth/login",
        data={"username": "pipeline_user", "password": "PipelinePass2026!"},
    )

    # 3. Upload -> UPLOAD audit event
    client.post(
        "/cloud/upload",
        data={"file": (io.BytesIO(b"Pipeline original content"), "pipeline_doc.txt")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        from app.models.audit_log import FileMetadata
        file_rec = FileMetadata.query.filter_by(filename="pipeline_doc.txt").first()
        file_id = file_rec.id

    # 4. Download -> DOWNLOAD audit event
    client.get(f"/cloud/download/{file_id}")

    # 5. Modify -> MODIFY audit event
    client.post(
        f"/cloud/modify/{file_id}",
        data={"file": (io.BytesIO(b"Pipeline modified content"), "pipeline_doc.txt")},
        content_type="multipart/form-data",
    )

    # 6. Delete -> DELETE audit event
    client.post(f"/cloud/delete/{file_id}")

    # Inspect all audit records created in SQLite
    with app.app_context():
        user_logs = AuditLog.query.filter_by(user_id="pipeline_user").order_by(AuditLog.id.asc()).all()
        actions = [l.action_type for l in user_logs]
        assert actions == ["LOGIN", "UPLOAD", "DOWNLOAD", "MODIFY", "DELETE"]

        # Verify every audit record's cryptographic hash is intact and valid
        for l in user_logs:
            assert is_audit_log_tampered(l) is False
            assert l.anchored_status in ("PENDING", "ANCHORED")
            assert l.log_hash.startswith("0x")
            assert len(l.log_hash) == 66
