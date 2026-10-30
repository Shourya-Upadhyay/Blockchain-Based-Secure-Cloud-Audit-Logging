import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the repository
BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

# Load environment variables from .env file
load_dotenv(BASE_DIR / ".env")


def resolve_database_uri(default_filename: str = "cloud_audit.db") -> str:
    """
    Resolve and normalize the database URI to an absolute path.
    Prevents sqlite3.OperationalError: unable to open database file
    when relative URIs like sqlite:///instance/cloud_audit.db are used.
    """
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        return f"sqlite:///{(INSTANCE_DIR / default_filename).as_posix()}"

    # Normalize relative SQLite URIs to absolute paths
    if db_url.startswith("sqlite:///") and db_url != "sqlite:///:memory:":
        raw_path = db_url[len("sqlite:///"):]
        path_obj = Path(raw_path)
        if not path_obj.is_absolute():
            # If specified as instance/name.db or instance\name.db, anchor directly inside INSTANCE_DIR
            if raw_path.startswith("instance/") or raw_path.startswith("instance\\"):
                rel_file = raw_path[len("instance/"):]
                abs_path = INSTANCE_DIR / rel_file
            else:
                abs_path = INSTANCE_DIR / raw_path
            return f"sqlite:///{abs_path.as_posix()}"
    return db_url


class Config:
    """Base configuration with shared defaults."""
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-major-project-default-secret-key-32b")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File upload settings
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", str(BASE_DIR / "uploads"))
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 16 * 1024 * 1024))  # 16 MB default
    
    # Blockchain settings (Ganache)
    GANACHE_RPC_URL = os.getenv("GANACHE_RPC_URL", "http://127.0.0.1:7545")
    GANACHE_CHAIN_ID = int(os.getenv("GANACHE_CHAIN_ID", 1337))
    CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "")
    DEPLOYER_ADDRESS = os.getenv("DEPLOYER_ADDRESS", "")
    DEPLOYER_PRIVATE_KEY = os.getenv("DEPLOYER_PRIVATE_KEY", "")
    
    # Web3 resilience settings
    WEB3_TIMEOUT_SECONDS = int(os.getenv("WEB3_TIMEOUT_SECONDS", 10))
    ANCHOR_RETRY_LIMIT = int(os.getenv("ANCHOR_RETRY_LIMIT", 3))
    AUTO_RETRY_PENDING_ON_STARTUP = os.getenv("AUTO_RETRY_PENDING_ON_STARTUP", "true").lower() == "true"
    
    # Security & Tamper testing flags
    ALLOW_TAMPER_SIMULATION = os.getenv("ALLOW_TAMPER_SIMULATION", "true").lower() == "true"


class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = True
    INSTANCE_DIR = INSTANCE_DIR
    SQLALCHEMY_DATABASE_URI = resolve_database_uri("cloud_audit.db")


class TestingConfig(Config):
    """Testing environment configuration using in-memory SQLite."""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    UPLOAD_FOLDER = str(BASE_DIR / "instance" / "test_uploads")
    ALLOW_TAMPER_SIMULATION = True
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    """Production environment configuration with strict security defaults."""
    DEBUG = False
    ALLOW_TAMPER_SIMULATION = False
    SQLALCHEMY_DATABASE_URI = resolve_database_uri("cloud_audit_prod.db")


# Configuration registry mapping environment names to classes
config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
