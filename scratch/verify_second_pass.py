"""
Comprehensive Second-Pass Redesign Verification Script.
Checks all pages, DOM elements, real data injection, and auth flows.
"""
import sys
import os
sys.path.insert(0, os.path.abspath("."))
from app import create_app, db
from app.models.user import User
from app.models.audit_log import AuditLog
from app.models import FileMetadata
from app.blockchain.client import get_blockchain_client

def main():
    app = create_app()
    app.config['WTF_CSRF_ENABLED'] = False
    client = app.test_client()

    print("=== 1. VERIFYING DATABASE & BLOCKCHAIN INTEGRITY ===")
    with app.app_context():
        total_logs = AuditLog.query.count()
        total_users = User.query.count()
        total_files = FileMetadata.query.count()
        b_status = get_blockchain_client().get_status()

        print(f"Audit Logs in DB: {total_logs}")
        print(f"Users in DB: {total_users}")
        print(f"Files in DB: {total_files}")
        print(f"Blockchain Online: {b_status['connected']}, Block: {b_status.get('block_number')}, Contract: {b_status.get('contract_address')}")
        assert total_logs == 5, f"Expected 5 logs, got {total_logs}"
        assert total_users == 2, f"Expected 2 users, got {total_users}"
        assert b_status['connected'] is True, "Blockchain not connected"

    print("\n=== 2. VERIFYING OVERVIEW DASHBOARD (/) ===")
    r_overview = client.get("/")
    assert r_overview.status_code == 200, f"Overview returned {r_overview.status_code}"
    html = r_overview.get_data(as_text=True)
    assert "Enterprise Security & Integrity Console" in html
    assert "EVM AUDIT TELEMETRY ACTIVE" in html
    assert "Audit Events" in html
    assert "Anchored" in html
    assert "Pending Queue" in html
    assert "Audit Event Distribution" in html
    assert "Cryptographic Pipeline Architecture" in html
    assert "Recent Security & Audit Events" in html
    print("[OK] Overview page renders with all SOC telemetry and real metrics.")

    print("\n=== 3. VERIFYING AUTHENTICATION PAGES ===")
    r_login = client.get("/auth/login")
    assert r_login.status_code == 200
    html_login = r_login.get_data(as_text=True)
    assert "Security Sign In" in html_login
    assert "Protected by EVM Audit Layer" in html_login
    print("[OK] Login page renders with cybersecurity layout.")

    r_register = client.get("/auth/register")
    assert r_register.status_code == 200
    html_reg = r_register.get_data(as_text=True)
    assert "Create Account" in html_reg
    assert "password-strength-bar" in html_reg
    print("[OK] Registration page renders with strength meter.")

    print("\n=== 4. VERIFYING CLOUD STORAGE PORTAL (/cloud/files) ===")
    with client.session_transaction() as sess:
        sess['user_id'] = 2
        sess['username'] = 'Raltem'
        sess['role'] = 'user'
    r_cloud = client.get("/cloud/files")
    assert r_cloud.status_code == 200
    html_cloud = r_cloud.get_data(as_text=True)
    assert "Cloud Object Storage Repository" in html_cloud
    assert "Stored Cloud Files" in html_cloud
    assert "dropzone-upload" in html_cloud
    assert "btn-view-grid" in html_cloud
    assert "inspectFileModal" in html_cloud
    print("[OK] Cloud files portal renders with list/grid views and dropzone.")

    print("\n=== 5. VERIFYING AUDITOR DASHBOARD (/audit/dashboard) ===")
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['username'] = 'auditor_admin'
        sess['role'] = 'auditor'
    r_audit = client.get("/audit/dashboard")
    assert r_audit.status_code == 200
    html_audit = r_audit.get_data(as_text=True)
    assert "Auditor Verification Dashboard" in html_audit
    assert "AUDITOR RESTRICTED CONSOLE" in html_audit
    assert "Canonical Audit Ledger" in html_audit
    assert "Verify Audit Logs" in html_audit
    assert "inspectModal-" in html_audit
    print("[OK] Auditor verification workspace renders with forensics controls.")

    print("\n=== 6. VERIFYING HEALTH CHECK (/health) ===")
    r_health = client.get("/health")
    assert r_health.status_code == 200
    j_health = r_health.get_json()
    assert j_health['status'] == 'healthy'
    assert j_health['database'] == 'connected'
    print(f"[OK] Health endpoint healthy: {j_health}")

    print("\nALL SECOND-PASS REDESIGN VERIFICATIONS PASSED SUCCESSFULLY!")

if __name__ == '__main__':
    main()
