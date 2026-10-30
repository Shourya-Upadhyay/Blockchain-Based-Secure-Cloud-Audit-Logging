"""
File Service for Simulated Cloud File Storage.
Handles secure file upload, listing, download, modification, and deletion.
Enforces ownership, path-traversal prevention, and dispatches audit events.
"""
import os
import uuid
from pathlib import Path
from datetime import datetime, timezone
from flask import current_app
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage

from app.extensions import db
from app.models.user import User
from app.models.audit_log import FileMetadata
from app.services.audit_service import record_audit_event


def get_upload_directory() -> Path:
    """Return resolved absolute path to the controlled upload directory."""
    upload_dir = Path(current_app.config.get("UPLOAD_FOLDER")).resolve()
    upload_dir.mkdir(parents=True, exist_ok=True)
    return upload_dir


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename against path-traversal characters.
    Strips directory components and replaces unsafe characters.
    """
    if not filename:
        raise ValueError("Filename cannot be empty.")

    # Strip directory paths (e.g. ../ or /etc/)
    base_name = os.path.basename(filename.replace("\\", "/"))
    clean_name = secure_filename(base_name)

    if not clean_name:
        # Fallback for filenames consisting entirely of stripped characters
        clean_name = f"cloud_file_{uuid.uuid4().hex[:6]}.bin"

    return clean_name


def validate_path_safety(file_path: Path, root_dir: Path) -> None:
    """
    Ensure the resolved file path resides strictly inside root_dir.
    Raises PermissionError if path traversal is detected.
    """
    resolved_file = file_path.resolve()
    resolved_root = root_dir.resolve()

    if resolved_root not in resolved_file.parents and resolved_file != resolved_root:
        raise PermissionError(f"Path traversal detected: {file_path} escapes {root_dir}")


def save_uploaded_file(file_storage: FileStorage, user: User) -> FileMetadata:
    """
    Save an uploaded file to physical disk and record metadata in SQLite.
    On success, records an UPLOAD event in the audit log.
    """
    if not file_storage or not file_storage.filename:
        raise ValueError("No file selected for upload.")

    clean_name = sanitize_filename(file_storage.filename)
    upload_dir = get_upload_directory()

    # Generate isolated physical disk filename to prevent collisions and overwrites
    unique_prefix = uuid.uuid4().hex
    stored_filename = f"{unique_prefix}_{clean_name}"
    target_path = upload_dir / stored_filename

    # Validate destination safety
    validate_path_safety(target_path, upload_dir)

    # Save to disk
    file_storage.save(str(target_path))
    filesize = target_path.stat().st_size

    # Record metadata in SQLite
    file_record = FileMetadata(
        filename=clean_name,
        stored_filename=stored_filename,
        filesize=filesize,
        owner_id=user.id,
    )
    db.session.add(file_record)
    db.session.commit()

    # Dispatch UPLOAD audit event through single audit service
    record_audit_event(
        user_id=user.username,
        action_type="UPLOAD",
        file_name=clean_name,
    )

    return file_record


def list_files_for_user(user: User) -> list[FileMetadata]:
    """
    List files available to the user.
    Auditors can inspect all files across users; regular users see only their own.
    """
    if user.is_auditor:
        return FileMetadata.query.order_by(FileMetadata.upload_date.desc()).all()
    return FileMetadata.query.filter_by(owner_id=user.id).order_by(FileMetadata.upload_date.desc()).all()


def get_file_for_download(file_id: int, user: User) -> tuple[Path, str]:
    """
    Validate permissions and return physical file path for download.
    On success, records a DOWNLOAD event in the audit log.
    """
    file_record = db.session.get(FileMetadata, file_id)
    if not file_record:
        raise FileNotFoundError(f"File with ID {file_id} not found.")

    # Enforce server-side ownership / role permission
    if file_record.owner_id != user.id and not user.is_auditor:
        raise PermissionError("Access denied: You do not have permission to download this file.")

    upload_dir = get_upload_directory()
    target_path = upload_dir / file_record.stored_filename

    validate_path_safety(target_path, upload_dir)

    if not target_path.exists():
        raise FileNotFoundError(f"Physical file missing on server disk: {file_record.filename}")

    # Dispatch DOWNLOAD audit event through single audit service
    record_audit_event(
        user_id=user.username,
        action_type="DOWNLOAD",
        file_name=file_record.filename,
    )

    return target_path, file_record.filename


def modify_file_content(file_id: int, replacement_storage: FileStorage, user: User) -> FileMetadata:
    """
    Modify an existing cloud file's physical content.
    On success, updates metadata and records a MODIFY event in the audit log.
    """
    if not replacement_storage or not replacement_storage.filename:
        raise ValueError("No replacement file provided.")

    file_record = db.session.get(FileMetadata, file_id)
    if not file_record:
        raise FileNotFoundError(f"File with ID {file_id} not found.")

    # Enforce server-side ownership / role permission
    if file_record.owner_id != user.id and not user.is_auditor:
        raise PermissionError("Access denied: You do not have permission to modify this file.")

    upload_dir = get_upload_directory()
    target_path = upload_dir / file_record.stored_filename

    validate_path_safety(target_path, upload_dir)

    # Overwrite physical file content
    replacement_storage.save(str(target_path))
    new_size = target_path.stat().st_size

    # Update metadata
    file_record.filesize = new_size
    file_record.last_modified = datetime.now(timezone.utc)
    db.session.commit()

    # Dispatch MODIFY audit event through single audit service
    record_audit_event(
        user_id=user.username,
        action_type="MODIFY",
        file_name=file_record.filename,
    )

    return file_record


def delete_file(file_id: int, user: User) -> bool:
    """
    Delete a cloud file from disk and SQLite.
    Preserves all previous and newly dispatched DELETE audit events.
    """
    file_record = db.session.get(FileMetadata, file_id)
    if not file_record:
        raise FileNotFoundError(f"File with ID {file_id} not found.")

    # Enforce server-side ownership / role permission
    if file_record.owner_id != user.id and not user.is_auditor:
        raise PermissionError("Access denied: You do not have permission to delete this file.")

    target_filename = file_record.filename
    upload_dir = get_upload_directory()
    target_path = upload_dir / file_record.stored_filename

    # Delete physical file if present
    try:
        validate_path_safety(target_path, upload_dir)
        if target_path.exists():
            target_path.unlink()
    except Exception as e:
        current_app.logger.warning(f"Could not remove physical file {target_path}: {e}")

    # Remove database metadata
    db.session.delete(file_record)
    db.session.commit()

    # Dispatch DELETE audit event through single audit service
    record_audit_event(
        user_id=user.username,
        action_type="DELETE",
        file_name=target_filename,
    )

    return True
