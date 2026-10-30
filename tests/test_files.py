"""
Phase 3 Simulated Cloud Storage Portal Tests:
- Secure file upload with filename sanitization and disk storage
- Path traversal prevention
- User file listing with ownership isolation
- Auditor file listing with global visibility
- Secure download with ownership enforcement (403 for unauthorized users)
- Auditor download privileges
- File modification (content replacement) with timestamp update and MODIFY audit log
- File deletion with disk cleanup and audit history preservation
- Unified audit logging verification across all actions (UPLOAD, DOWNLOAD, MODIFY, DELETE)
- Non-existent file operations return 404
"""
import io
import pytest
from app.extensions import db
from app.models.user import User
from app.models.audit_log import AuditLog, FileMetadata
from app.services.file_service import get_upload_directory


def create_user_and_login(client, username, password="Password123!", role="user"):
    """Helper to create and authenticate a test user session."""
    client.post(
        "/auth/register",
        data={"username": username, "password": password, "confirm_password": password},
    )
    if role == "auditor":
        # Upgrade role in DB
        user = User.query.filter_by(username=username).first()
        user.role = "auditor"
        db.session.commit()

    client.post(
        "/auth/login",
        data={"username": username, "password": password},
    )


def test_file_upload_success(client, app):
    """Test standard file upload creates DB record, disk file, and UPLOAD audit log."""
    with app.app_context():
        create_user_and_login(client, "alice_uploader")

    data = {
        "file": (io.BytesIO(b"Hello simulated cloud storage!"), "project_proposal.pdf"),
    }
    response = client.post("/cloud/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "project_proposal.pdf" in html

    with app.app_context():
        file_rec = FileMetadata.query.filter_by(filename="project_proposal.pdf").first()
        assert file_rec is not None
        assert file_rec.filesize == len(b"Hello simulated cloud storage!")

        # Verify physical file exists in upload directory
        upload_dir = get_upload_directory()
        physical_path = upload_dir / file_rec.stored_filename
        assert physical_path.exists()
        assert physical_path.read_bytes() == b"Hello simulated cloud storage!"

        # Verify UPLOAD audit log record
        audit_rec = AuditLog.query.filter_by(user_id="alice_uploader", action_type="UPLOAD").first()
        assert audit_rec is not None
        assert audit_rec.file_name == "project_proposal.pdf"
        assert audit_rec.anchored_status in ("PENDING", "ANCHORED")
        assert audit_rec.log_hash.startswith("0x")


def test_file_upload_empty_rejected(client, app):
    """Test uploading an empty or missing file is rejected and logs no event."""
    with app.app_context():
        create_user_and_login(client, "alice_empty")

    initial_audit_count = AuditLog.query.count()

    response = client.post(
        "/cloud/upload",
        data={"file": (io.BytesIO(b""), "")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Please select a file to upload" in response.get_data(as_text=True)

    with app.app_context():
        # Confirm no file metadata or upload audit event was added
        assert FileMetadata.query.count() == 0
        assert AuditLog.query.filter_by(action_type="UPLOAD").count() == 0


def test_file_listing_ownership_isolation(client, app):
    """Test users see only their own uploaded files in the portal."""
    with app.app_context():
        create_user_and_login(client, "alice_lister")
    client.post(
        "/cloud/upload",
        data={"file": (io.BytesIO(b"Alice file content"), "alice_file.txt")},
        content_type="multipart/form-data",
    )

    # Bob logs in and uploads
    client.post("/auth/logout")
    with app.app_context():
        create_user_and_login(client, "bob_lister")
    client.post(
        "/cloud/upload",
        data={"file": (io.BytesIO(b"Bob file content"), "bob_file.txt")},
        content_type="multipart/form-data",
    )

    # Bob's file portal
    bob_view = client.get("/cloud/files").get_data(as_text=True)
    assert "bob_file.txt" in bob_view
    assert "alice_file.txt" not in bob_view

    # Switch back to Alice
    client.post("/auth/logout")
    client.post("/auth/login", data={"username": "alice_lister", "password": "Password123!"})
    alice_view = client.get("/cloud/files").get_data(as_text=True)
    assert "alice_file.txt" in alice_view
    assert "bob_file.txt" not in alice_view


def test_auditor_file_listing_global_scope(client, app):
    """Test auditors have global visibility across all users' uploaded files."""
    with app.app_context():
        create_user_and_login(client, "charlie_user")
    client.post(
        "/cloud/upload",
        data={"file": (io.BytesIO(b"Charlie data"), "charlie_doc.docx")},
        content_type="multipart/form-data",
    )

    # Auditor logs in
    client.post("/auth/logout")
    with app.app_context():
        create_user_and_login(client, "chief_auditor", role="auditor")

    auditor_view = client.get("/cloud/files").get_data(as_text=True)
    assert "charlie_doc.docx" in auditor_view
    assert "charlie_user" in auditor_view
    assert "Auditor Global Scope" in auditor_view


def test_file_download_success_owner(client, app):
    """Test file owner can successfully download their file and logs DOWNLOAD event."""
    with app.app_context():
        create_user_and_login(client, "david_owner")
    client.post(
        "/cloud/upload",
        data={"file": (io.BytesIO(b"Downloadable payload 12345"), "data_export.csv")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        file_rec = FileMetadata.query.filter_by(filename="data_export.csv").first()
        file_id = file_rec.id

    download_res = client.get(f"/cloud/download/{file_id}")
    assert download_res.status_code == 200
    assert download_res.data == b"Downloadable payload 12345"
    assert "data_export.csv" in download_res.headers.get("Content-Disposition", "")

    with app.app_context():
        audit_download = AuditLog.query.filter_by(user_id="david_owner", action_type="DOWNLOAD").first()
        assert audit_download is not None
        assert audit_download.file_name == "data_export.csv"


def test_file_download_unauthorized_blocked(client, app):
    """Test unauthorized users cannot download another user's file (HTTP 403)."""
    with app.app_context():
        create_user_and_login(client, "emma_owner")
    client.post(
        "/cloud/upload",
        data={"file": (io.BytesIO(b"Confidential financial report"), "confidential.pdf")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        file_id = FileMetadata.query.filter_by(filename="confidential.pdf").first().id

    # Attacker logs in
    client.post("/auth/logout")
    with app.app_context():
        create_user_and_login(client, "frank_attacker")

    # Attacker attempts to download Emma's file
    bad_download = client.get(f"/cloud/download/{file_id}")
    assert bad_download.status_code == 403

    with app.app_context():
        # Ensure NO download audit event was recorded for Frank
        assert AuditLog.query.filter_by(user_id="frank_attacker", action_type="DOWNLOAD").count() == 0


def test_file_download_auditor_permitted(client, app):
    """Test auditors are authorized to download files across users for audit inspection."""
    with app.app_context():
        create_user_and_login(client, "george_client")
    client.post(
        "/cloud/upload",
        data={"file": (io.BytesIO(b"Audit sample dataset"), "audit_sample.json")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        file_id = FileMetadata.query.filter_by(filename="audit_sample.json").first().id

    client.post("/auth/logout")
    with app.app_context():
        create_user_and_login(client, "senior_auditor", role="auditor")

    res = client.get(f"/cloud/download/{file_id}")
    assert res.status_code == 200
    assert res.data == b"Audit sample dataset"

    with app.app_context():
        audit = AuditLog.query.filter_by(user_id="senior_auditor", action_type="DOWNLOAD").first()
        assert audit is not None
        assert audit.file_name == "audit_sample.json"


def test_path_traversal_prevention(client, app):
    """Test path traversal characters in filenames are safely neutralized."""
    with app.app_context():
        create_user_and_login(client, "hacker_user")

    # Malicious filename attempting directory escape
    traversal_data = {
        "file": (io.BytesIO(b"Root escape attempt"), "../../../../etc/malicious_payload.sh"),
    }
    client.post("/cloud/upload", data=traversal_data, content_type="multipart/form-data")

    with app.app_context():
        file_rec = FileMetadata.query.filter_by(owner_id=User.query.filter_by(username="hacker_user").first().id).first()
        assert file_rec is not None
        # Verify filename was stripped of traversal path
        assert file_rec.filename == "malicious_payload.sh"
        assert "/" not in file_rec.filename
        assert "\\" not in file_rec.filename

        # Verify physical path is strictly inside upload directory
        upload_dir = get_upload_directory()
        physical_path = upload_dir / file_rec.stored_filename
        assert upload_dir in physical_path.parents
        assert physical_path.exists()


def test_file_modification_success(client, app):
    """Test modifying an existing file overwrites content and logs MODIFY event."""
    with app.app_context():
        create_user_and_login(client, "irene_editor")
    client.post(
        "/cloud/upload",
        data={"file": (io.BytesIO(b"Version 1 content"), "document.txt")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        file_rec = FileMetadata.query.filter_by(filename="document.txt").first()
        file_id = file_rec.id
        orig_upload_time = file_rec.upload_date

    # Modify content
    modify_data = {
        "file": (io.BytesIO(b"Version 2 updated content with changes"), "replacement_document.txt"),
    }
    res = client.post(f"/cloud/modify/{file_id}", data=modify_data, content_type="multipart/form-data", follow_redirects=True)
    assert res.status_code == 200
    assert "modified and logged successfully" in res.get_data(as_text=True)

    with app.app_context():
        updated_rec = db.session.get(FileMetadata, file_id)
        assert updated_rec.filesize == len(b"Version 2 updated content with changes")
        assert updated_rec.last_modified >= orig_upload_time

        # Verify physical file has updated content
        upload_dir = get_upload_directory()
        assert (upload_dir / updated_rec.stored_filename).read_bytes() == b"Version 2 updated content with changes"

        # Verify MODIFY audit log
        audit_modify = AuditLog.query.filter_by(user_id="irene_editor", action_type="MODIFY").first()
        assert audit_modify is not None
        assert audit_modify.file_name == "document.txt"


def test_file_modification_unauthorized_blocked(client, app):
    """Test unauthorized users cannot modify another user's file (HTTP 403)."""
    with app.app_context():
        create_user_and_login(client, "jack_owner")
    client.post(
        "/cloud/upload",
        data={"file": (io.BytesIO(b"Jack content"), "jack_spec.md")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        file_id = FileMetadata.query.filter_by(filename="jack_spec.md").first().id

    client.post("/auth/logout")
    with app.app_context():
        create_user_and_login(client, "kevin_attacker")

    bad_modify = client.post(
        f"/cloud/modify/{file_id}",
        data={"file": (io.BytesIO(b"Malicious replacement"), "hacked.md")},
        content_type="multipart/form-data",
    )
    assert bad_modify.status_code == 403

    with app.app_context():
        # Verify Jack's original content intact
        file_rec = db.session.get(FileMetadata, file_id)
        upload_dir = get_upload_directory()
        assert (upload_dir / file_rec.stored_filename).read_bytes() == b"Jack content"
        # Verify no MODIFY log recorded for Kevin
        assert AuditLog.query.filter_by(user_id="kevin_attacker", action_type="MODIFY").count() == 0


def test_file_deletion_success_and_audit_preservation(client, app):
    """
    Test deleting a file removes it from disk and metadata table,
    records a DELETE audit event, and PRESERVES all previous audit events!
    """
    with app.app_context():
        create_user_and_login(client, "laura_cleaner")
    client.post(
        "/cloud/upload",
        data={"file": (io.BytesIO(b"Temporary draft content"), "temp_draft.txt")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        file_rec = FileMetadata.query.filter_by(filename="temp_draft.txt").first()
        file_id = file_rec.id
        stored_disk_name = file_rec.stored_filename

    upload_dir = get_upload_directory()
    assert (upload_dir / stored_disk_name).exists()

    # Delete the file
    del_res = client.post(f"/cloud/delete/{file_id}", follow_redirects=True)
    assert del_res.status_code == 200
    assert "File deleted successfully" in del_res.get_data(as_text=True)

    with app.app_context():
        # Metadata row is deleted
        assert db.session.get(FileMetadata, file_id) is None
        # Physical file is deleted from disk
        assert not (upload_dir / stored_disk_name).exists()

        # CRITICAL RULE: Previous UPLOAD audit event MUST BE PRESERVED
        upload_log = AuditLog.query.filter_by(user_id="laura_cleaner", action_type="UPLOAD", file_name="temp_draft.txt").first()
        assert upload_log is not None

        # NEW DELETE audit event must be recorded
        delete_log = AuditLog.query.filter_by(user_id="laura_cleaner", action_type="DELETE", file_name="temp_draft.txt").first()
        assert delete_log is not None
        assert delete_log.anchored_status in ("PENDING", "ANCHORED")
        assert delete_log.log_hash.startswith("0x")


def test_file_deletion_unauthorized_blocked(client, app):
    """Test unauthorized users cannot delete another user's file (HTTP 403)."""
    with app.app_context():
        create_user_and_login(client, "mary_owner")
    client.post(
        "/cloud/upload",
        data={"file": (io.BytesIO(b"Valuable intellectual property"), "ip_asset.dat")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        file_id = FileMetadata.query.filter_by(filename="ip_asset.dat").first().id

    client.post("/auth/logout")
    with app.app_context():
        create_user_and_login(client, "nathan_attacker")

    bad_del = client.post(f"/cloud/delete/{file_id}")
    assert bad_del.status_code == 403

    with app.app_context():
        # File still exists
        assert db.session.get(FileMetadata, file_id) is not None
        # No DELETE audit log for Nathan
        assert AuditLog.query.filter_by(user_id="nathan_attacker", action_type="DELETE").count() == 0


def test_file_operations_nonexistent_file_returns_404(client, app):
    """Test downloading, modifying, or deleting non-existent file IDs returns HTTP 404."""
    with app.app_context():
        create_user_and_login(client, "oliver_user")

    # Download non-existent
    assert client.get("/cloud/download/99999").status_code == 404

    # Modify non-existent
    assert client.post(
        "/cloud/modify/99999",
        data={"file": (io.BytesIO(b"Data"), "test.txt")},
        content_type="multipart/form-data",
    ).status_code == 404

    # Delete non-existent
    assert client.post("/cloud/delete/99999").status_code == 404
