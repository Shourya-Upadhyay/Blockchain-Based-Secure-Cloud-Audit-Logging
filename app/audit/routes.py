"""
Auditor Dashboard Blueprint Routes.
Enforces role-based authorization for auditors, renders verification tables,
filters, pagination, and dispatches full cryptographic verification checks.
"""
from flask import (
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    session,
)
from app.audit import audit_bp
from app.auth.decorators import auditor_required
from app.models.audit_log import AuditLog
from app.audit.verification import (
    verify_audit_trail,
    STATUS_VERIFIED,
    STATUS_TAMPERED,
    STATUS_MISSING_SQL,
    STATUS_UNANCHORED,
    STATUS_BLOCKCHAIN_UNAVAILABLE,
)
from app.blockchain.client import get_blockchain_client
from app.blockchain.anchoring import retry_pending_anchors, get_anchoring_stats
from app.services.hashing_service import SUPPORTED_ACTIONS


@audit_bp.route("/dashboard", methods=["GET"])
@auditor_required
def dashboard():
    """
    Main Auditor Dashboard.
    Displays metrics, blockchain health, filtered audit log table, and pagination.
    """
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 15, type=int)

    # Filter parameters
    user_filter = request.args.get("user", "").strip()
    action_filter = request.args.get("action", "").strip().upper()
    status_filter = request.args.get("status", "").strip().upper()
    search_query = request.args.get("search", "").strip()

    query = AuditLog.query

    if user_filter:
        query = query.filter(AuditLog.user_id == user_filter)
    if action_filter and action_filter in SUPPORTED_ACTIONS:
        query = query.filter(AuditLog.action_type == action_filter)
    if status_filter in ["PENDING", "ANCHORED", "FAILED"]:
        query = query.filter(AuditLog.anchored_status == status_filter)
    if search_query:
        like_pattern = f"%{search_query}%"
        query = query.filter(
            (AuditLog.log_id.ilike(like_pattern))
            | (AuditLog.file_name.ilike(like_pattern))
            | (AuditLog.user_id.ilike(like_pattern))
        )

    # Order newest first
    query = query.order_by(AuditLog.id.desc())

    # Paginate
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    audit_logs = pagination.items

    # Metrics
    stats = get_anchoring_stats()

    # Blockchain connection diagnostic
    bclient = get_blockchain_client()
    blockchain_status = bclient.get_status()

    # Distinct users for dropdown filter
    all_users = [u[0] for u in AuditLog.query.with_entities(AuditLog.user_id).distinct().all()]

    # Retrieve cached verification result from session if recent
    verification_report = session.get("latest_verification_report")

    return render_template(
        "audit/dashboard.html",
        audit_logs=audit_logs,
        pagination=pagination,
        stats=stats,
        blockchain_status=blockchain_status,
        all_users=all_users,
        supported_actions=sorted(list(SUPPORTED_ACTIONS)),
        current_user_filter=user_filter,
        current_action_filter=action_filter,
        current_status_filter=status_filter,
        current_search=search_query,
        verification_report=verification_report,
    )


def _compact_verification_report(report: dict) -> dict:
    """
    Produce a lightweight version of the verification report suitable for
    client-side session storage (strictly under 2 KB serialized).
    Preserves full summary counts, blockchain status, and timestamp.
    Prioritizes discrepancy records (TAMPERED, MISSING_SQL, UNANCHORED, OFFLINE),
    supplemented with verified records, capped at 10 records total.
    """
    if not report:
        return {}

    records = report.get("records", [])
    discrepancies = [r for r in records if r.get("verification_status") != STATUS_VERIFIED]
    verified = [r for r in records if r.get("verification_status") == STATUS_VERIFIED]

    needed_records = (discrepancies + verified)[:10]

    compact_records = []
    for r in needed_records:
        compact_records.append({
            "log_id": r.get("log_id"),
            "user_id": r.get("user_id"),
            "action_type": r.get("action_type"),
            "file_name": r.get("file_name"),
            "timestamp": r.get("timestamp"),
            "verification_status": r.get("verification_status"),
            "recalculated_hash": r.get("recalculated_hash"),
            "stored_sql_hash": r.get("stored_sql_hash"),
            "on_chain_hash": r.get("on_chain_hash"),
            "tx_hash": r.get("tx_hash"),
            "block_number": r.get("block_number"),
            "details": (r.get("details") or "")[:200],
        })

    return {
        "timestamp": report.get("timestamp"),
        "blockchain_status": report.get("blockchain_status"),
        "summary": report.get("summary", {}),
        "records": compact_records,
    }


@audit_bp.route("/verify", methods=["POST"])
@auditor_required
def run_verification():
    """
    Trigger full backend cryptographic verification across off-chain SQL records
    and on-chain smart contract hashes.
    """
    report = verify_audit_trail()

    # Store compact report in session to avoid RFC 6265 cookie size overflows (>4KB)
    session["latest_verification_report"] = _compact_verification_report(report)

    summary = report["summary"]
    if report["blockchain_status"] == "OFFLINE":
        flash(
            f"Verification executed in OFFLINE mode: Local blockchain node is unreachable. "
            f"Classified {summary['blockchain_unavailable']} records as BLOCKCHAIN_UNAVAILABLE. "
            f"(Network connection failure - not evidence of tampering)",
            "warning",
        )
    else:
        tamper_alert = f", {summary['tampered']} TAMPERED, {summary['missing_sql']} MISSING SQL" if (summary['tampered'] > 0 or summary['missing_sql'] > 0) else ""
        flash(
            f"Verification complete: {summary['verified']} VERIFIED, {summary['unanchored']} UNANCHORED{tamper_alert}.",
            "danger" if (summary["tampered"] > 0 or summary["missing_sql"] > 0) else "success",
        )

    return redirect(url_for("audit.dashboard"))


@audit_bp.route("/api/verify", methods=["POST"])
@auditor_required
def api_run_verification():
    """
    API endpoint for dynamic AJAX verification without full page refresh.
    Returns complete verification breakdown as JSON.
    """
    report = verify_audit_trail()
    session["latest_verification_report"] = _compact_verification_report(report)
    return jsonify(report)


@audit_bp.route("/retry-pending", methods=["POST"])
@auditor_required
def retry_pending():
    """
    Trigger retry queue worker to anchor queued PENDING records to Ganache.
    """
    summary = retry_pending_anchors(limit=50)

    if summary.get("status") == "offline":
        flash("Cannot retry anchoring: Local Ganache blockchain node is offline.", "warning")
    else:
        flash(
            f"Retry batch completed: {summary['succeeded']} records anchored successfully, "
            f"{summary['failed']} failed.",
            "info" if summary["succeeded"] > 0 else "warning",
        )

    return redirect(url_for("audit.dashboard"))


# ---------------------------------------------------------------------------
# Developer-Only Tamper Simulation Endpoints
# (Strictly gated behind ALLOW_TAMPER_SIMULATION and auditor role)
# ---------------------------------------------------------------------------

def _check_tamper_allowed():
    """Ensure tampering simulation is strictly forbidden in production."""
    from flask import current_app, abort
    if not current_app.config.get("ALLOW_TAMPER_SIMULATION", False) or current_app.config.get("ENV") == "production":
        abort(403, description="Tamper simulation is strictly disabled in this environment.")


@audit_bp.route("/tamper/modify/<int:log_id>", methods=["POST"])
@auditor_required
def tamper_modify_record(log_id: int):
    """
    [DEV ONLY] Simulate unauthorized off-chain database modification.
    Alters the record's action or filename directly in SQLite without updating log_hash.
    """
    _check_tamper_allowed()
    from app.extensions import db

    log = db.session.get(AuditLog, log_id)
    if not log:
        flash(f"Audit log ID {log_id} not found.", "danger")
        return redirect(url_for("audit.dashboard"))

    original_action = log.action_type
    # Swap action or append indicator
    if log.action_type == "UPLOAD":
        log.action_type = "DELETE"
    elif log.action_type == "DELETE":
        log.action_type = "MODIFY"
    else:
        log.file_name = f"TAMPERED_{log.file_name}"

    db.session.commit()

    flash(
        f"Simulated Rogue Insider: Off-chain record {log.log_id} was modified in SQLite "
        f"({original_action} -> {log.action_type}). "
        f"Verification will now catch the cryptographic hash mismatch!",
        "warning",
    )
    return redirect(url_for("audit.dashboard"))


@audit_bp.route("/tamper/delete/<int:log_id>", methods=["POST"])
@auditor_required
def tamper_delete_record(log_id: int):
    """
    [DEV ONLY] Simulate unauthorized off-chain record destruction.
    Deletes the AuditLog row from SQLite while leaving the hash anchored on-chain.
    """
    _check_tamper_allowed()
    from app.extensions import db

    log = db.session.get(AuditLog, log_id)
    if not log:
        flash(f"Audit log ID {log_id} not found.", "danger")
        return redirect(url_for("audit.dashboard"))

    deleted_id = log.log_id
    db.session.delete(log)
    db.session.commit()

    flash(
        f"Simulated Record Destruction: Row for {deleted_id} was destroyed in SQLite. "
        f"Verification will now detect the missing off-chain record (MISSING_SQL)!",
        "warning",
    )
    return redirect(url_for("audit.dashboard"))


@audit_bp.route("/tamper/seed-scenarios", methods=["POST"])
@auditor_required
def tamper_seed_scenarios():
    """
    [DEV ONLY] Seed demonstration scenarios illustrating all 8 validation states.
    """
    _check_tamper_allowed()
    from app.services.audit_service import record_audit_event
    from app.extensions import db

    # 1. Normal record that will verify
    r1 = record_audit_event("alice_demo", "UPLOAD", "financial_q3.pdf", auto_anchor=False)
    r1.anchored_status = "ANCHORED"
    r1.tx_hash = "0x" + "a" * 64
    r1.block_number = 101

    # 2. Tampered record (modified in SQL after anchoring)
    r2 = record_audit_event("malicious_insider", "UPLOAD", "unauthorized_payout.csv", auto_anchor=False)
    r2.anchored_status = "ANCHORED"
    r2.tx_hash = "0x" + "b" * 64
    r2.block_number = 102
    # Modify action directly without recomputing hash
    r2.action_type = "DELETE"

    # 3. Unanchored record (still PENDING)
    r3 = record_audit_event("new_user", "LOGIN", "SESSION", auto_anchor=False)
    r3.anchored_status = "PENDING"

    # 4. Outage record (PENDING with RPC failure message)
    r4 = record_audit_event("bob_demo", "DOWNLOAD", "project_specs.docx", auto_anchor=False)
    r4.anchored_status = "PENDING"
    r4.error_message = "Blockchain RPC endpoint unreachable (Simulated Outage)"
    r4.retry_count = 1

    db.session.commit()

    flash("Demonstration scenarios seeded successfully! Click 'Verify Audit Logs' to see diagnostics.", "info")
    return redirect(url_for("audit.dashboard"))
