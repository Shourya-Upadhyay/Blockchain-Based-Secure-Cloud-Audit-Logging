"""
User database model with role-based access control and Werkzeug password hashing.
"""
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db


class User(db.Model):
    """
    User entity representing regular cloud users and auditors.
    """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # 'user' or 'auditor'
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    files = db.relationship("FileMetadata", backref="owner", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        """Hash password using Werkzeug PBKDF2 with SHA-256."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify plain password against stored hash."""
        return check_password_hash(self.password_hash, password)

    @property
    def is_auditor(self) -> bool:
        """Check if user has auditor privileges."""
        return self.role.lower() == "auditor"

    def to_dict(self) -> dict:
        """Serialize user data for API responses (excluding password hash)."""
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "is_auditor": self.is_auditor,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<User id={self.id} username='{self.username}' role='{self.role}'>"
