"""
AuditLog and FileMetadata database models.
Tracks simulated cloud files, user activities, and blockchain anchoring statuses.
"""
from datetime import datetime, timezone
from app.extensions import db


class AuditLog(db.Model):
    """
    Audit log record capturing cloud events off-chain.
    Contains both canonical data fields used in cryptographic hashing
    and separate mutable blockchain anchoring status metadata.
    """
    __tablename__ = "audit_logs"

    # Internal Primary Key
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # Core Canonical Audit Fields (used in SHA-256 calculation)
    log_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.String(64), nullable=False, index=True)
    action_type = db.Column(db.String(20), nullable=False)  # LOGIN, UPLOAD, DOWNLOAD, MODIFY, DELETE
    file_name = db.Column(db.String(255), nullable=False)   # Target filename or 'SESSION'
    timestamp = db.Column(db.String(30), nullable=False)    # ISO-8601 UTC string

    # Cryptographic Hash (Calculated only from the 5 canonical fields above)
    log_hash = db.Column(db.String(66), nullable=False)     # 0x-prefixed 64-char hex SHA-256 digest

    # Separate Blockchain Anchoring Status & Metadata (NOT included in canonical hash)
    anchored_status = db.Column(db.String(20), nullable=False, default="PENDING", index=True)  # PENDING, ANCHORED, FAILED
    tx_hash = db.Column(db.String(66), nullable=True)        # Ethereum transaction hash
    block_number = db.Column(db.Integer, nullable=True)      # Mined block number
    error_message = db.Column(db.Text, nullable=True)        # Error description if anchoring failed or pending
    retry_count = db.Column(db.Integer, nullable=False, default=0)

    # Local Audit Insertion Timestamp
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict:
        """Serialize audit log record into a dictionary."""
        return {
            "id": self.id,
            "log_id": self.log_id,
            "user_id": self.user_id,
            "action_type": self.action_type,
            "file_name": self.file_name,
            "timestamp": self.timestamp,
            "log_hash": self.log_hash,
            "anchored_status": self.anchored_status,
            "tx_hash": self.tx_hash,
            "block_number": self.block_number,
            "error_message": self.error_message,
            "retry_count": self.retry_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def canonical_dict(self) -> dict:
        """Return exactly the 5 fields that constitute the canonical log entry."""
        return {
            "log_id": self.log_id,
            "user_id": self.user_id,
            "action_type": self.action_type,
            "file_name": self.file_name,
            "timestamp": self.timestamp,
        }

    def __repr__(self) -> str:
        return f"<AuditLog log_id='{self.log_id}' user='{self.user_id}' action='{self.action_type}' status='{self.anchored_status}'>"


class FileMetadata(db.Model):
    """
    Metadata representation of files uploaded to the simulated cloud portal.
    """
    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    filename = db.Column(db.String(255), nullable=False)           # Original display filename
    stored_filename = db.Column(db.String(255), unique=True, nullable=False) # UUID-prefixed file on disk
    filesize = db.Column(db.Integer, nullable=False)               # Size in bytes
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    upload_date = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    last_modified = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict:
        """Serialize file metadata into a dictionary."""
        return {
            "id": self.id,
            "filename": self.filename,
            "stored_filename": self.stored_filename,
            "filesize": self.filesize,
            "owner_id": self.owner_id,
            "upload_date": self.upload_date.isoformat() if self.upload_date else None,
            "last_modified": self.last_modified.isoformat() if self.last_modified else None,
        }

    def __repr__(self) -> str:
        return f"<FileMetadata id={self.id} filename='{self.filename}' owner_id={self.owner_id}>"
