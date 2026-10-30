# PROJECT PLAN: Blockchain-Based Secure Cloud Audit Logging

**Institution**: School of Computer Science and Engineering, IILM University, Greater Noida  
**Degree**: Bachelor of Technology (B.Tech) in Computer Science and Engineering  
**Academic Session**: 2026–2027  
**Project Team**:
- Shourya Upadhyay (Enrollment No: `2410031159`)
- Jeevesh Pachauri (Enrollment No: `2410031186`)

**Project Guide**: Prof. Dr. Leena Arya  
**Project Title**: *Blockchain-Based Secure Cloud Audit Logging*

---

## 1. Project Overview & Motivation

Cloud storage enables distributed data access and collaboration. However, cloud environments produce high volumes of security-critical audit events: user logins, file uploads, file downloads, content modifications, and file deletions. In traditional cloud architectures, audit trails are stored in centralized logging systems (e.g., standard SQL databases or syslog servers). 

**The Centralized Trust Vulnerability**:
Centralized audit logs are subject to insider threats and administrative tampering. A malicious insider or external attacker gaining privileged database access can alter or erase log records to conceal unauthorized activities, compromising forensic investigations.

**The Solution**:
This project introduces a **Hybrid Dual-Layer Audit Logging System**:
1. **Off-Chain Storage Layer (SQLite)**: Stores human-readable, detailed, queryable audit logs (`log_id`, `user_id`, `action_type`, `file_name`, `timestamp`) and file metadata to maintain high throughput and low latency.
2. **On-Chain Anchoring Layer (Private Ethereum via Ganache & Solidity Smart Contract)**: Generates a deterministic SHA-256 cryptographic digest of each canonical log entry and permanently anchors the digest onto an Ethereum smart contract (`AuditLogContract.sol`).
3. **Automated Verification Engine**: Compares recomputed off-chain cryptographic digests against immutable on-chain records, detecting modified, deleted, or unanchored audit events.

---

## 2. Academic Traceability & Research Foundation

This project directly operationalizes the architectural foundations established in our **Phase-I Report**, **Phase-II Report**, and relevant academic literature:

- **BlockAudit (Ahmad et al., 2019)**: Demonstrated the feasibility of storing audit hashes on blockchain for tamper resistance; our architecture adopts fixed-length digest anchoring while keeping heavy payloads off-chain.
- **LogProof (Nagpal et al., 2025)**: Established that storing off-chain log entries alongside on-chain cryptographic digests provides proof-of-integrity and tamper detection without blockchain bloat.
- **Javed et al. (2024)**: Focused on defeating malicious insiders through immutable transaction logs; our system implements strict smart-contract write-authorization (`onlyOwner`) and non-overwrite invariants.
- **Han et al. (2022)** & **Wang et al. (2024)**: Emphasized decentralization in cloud data auditing and protecting against untrustworthy auditing authorities.

---

## 3. Technology Stack & Runtime Specifications

| Component | Technology / Library | Version / Specification | Role in Project |
|---|---|---|---|
| **Backend Framework** | Python 3 / Flask | Python 3.11.9, Flask 3.0+ | Application server, REST APIs, routing, session management |
| **Relational Database** | SQLite 3 | Embedded engine | Off-chain storage of users, files, and complete audit records |
| **Database ORM / Driver** | SQLAlchemy / SQLite3 | Standard Flask integration | Schema management, structured queries, transaction control |
| **Password Security** | Werkzeug Security | PBKDF2 with SHA-256 / scrypt | Secure password hashing and verification |
| **Blockchain Network** | Ganache (Local Ethereum) | JSON-RPC 2.0 (Port 7545 / 8545) | Local private Ethereum blockchain with zero-cost gas test accounts |
| **Smart Contract Language**| Solidity | `^0.8.20` | Smart contract logic (`AuditLogContract.sol`) |
| **Web3 Client Bridge** | `web3.py` | Web3 6.x+ | Python-to-Ethereum JSON-RPC communication and transaction signing |
| **Contract Compilation** | `py-solc-x` / Hardhat | Solidity 0.8.20+ compiler | Local compilation of Solidity contracts to ABI and Bytecode |
| **Frontend UI** | HTML5, CSS3, Vanilla JS, Bootstrap 5 | Bootstrap 5.3+, Google Fonts (Inter) | Cloud portal, Auditor Dashboard, Tamper Simulator, responsive UX |
| **Automated Testing** | `pytest` | pytest 8.x+ | Unit, integration, security, and verification test suite |
| **Configuration** | `python-dotenv` | Standard `.env` loading | Environment-specific variables, keys, and RPC endpoints |

---

## 4. Master Phase Checklist & Progress Tracking

| Phase | Description | Deliverables | Status | Acceptance Criteria Summary |
|:---:|---|---|:---:|---|
| **Phase 0** | **Inspection, Architecture & Project Rules** | `PROJECT_PLAN.md`, `ARCHITECTURE.md`, `docs/PHASE_LOG.md`, `.gitignore`, `.env.example` | **COMPLETED** | Complete workspace inspection, academic report analysis, runtime environment assessment, architectural specifications, file breakdown, risk matrix, and environment variable template. |
| **Phase 1** | **Development Environment & Flask Scaffold** | `requirements.txt`, `package.json`, `config.py`, `app.py`, `app/__init__.py`, `app/extensions.py`, `app/models/`, `app/templates/`, `app/static/`, `tests/` | **COMPLETED** | Virtualenv creation, dependency installation, Flask application factory, SQLite database initialization, database migration scripts, health check endpoint. |
| **Phase 2** | **Authentication & Role-Based Access Control** | `app/auth/`, User model, login/register templates, password hashing, session guards | **COMPLETED** | Secure registration, PBKDF2 password hashing, role management (`user`, `auditor`), server-side permission checks, session protection. |
| **Phase 3** | **Simulated Cloud File Storage Portal** | `app/cloud/`, `services/file_service.py`, cloud dashboard templates, upload directory | **COMPLETED** | Secure upload, list, download, modify, delete operations; path-traversal prevention; ownership checks; controlled storage directory. |
| **Phase 4** | **Audit Logging, Serialization & SHA-256 Hashing** | `app/models/audit_log.py`, `services/hashing_service.py`, `services/audit_service.py`, tests | **PENDING** | Canonical serialization (`LogID \| UserID \| ActionType \| FileName \| Timestamp`), pipe escaping/validation, deterministic SHA-256 generation, audit event persistence for 5 core actions. |
| **Phase 5** | **Smart Contract Implementation & Local Deployment** | `contracts/AuditLogContract.sol`, compile & deploy scripts, Ganache deployment | **PENDING** | Solidity contract with `storeLogHash`, `getLogRecord`, `getAllLogIds`, `onlyOwner` access control, overwrite rejection, event emission, successful Ganache deployment. |
| **Phase 6** | **Web3 Middleware & Reliable Hash Anchoring** | `app/blockchain/client.py`, `app/blockchain/anchoring.py`, retry worker | **PENDING** | Dual-write reliability: SQL first, Web3 transaction submission, transaction confirmation wait, block number and tx_hash persistence, offline queue handling, duplicate prevention. |
| **Phase 7** | **Auditor Dashboard & Verification Engine** | `app/audit/`, `app/audit/verification.py`, auditor UI templates, filtering | **PENDING** | Comprehensive auditor view, metric cards, filtering by user/action/status, automated verification algorithm, detection of verified, modified, deleted, and unanchored records. |
| **Phase 8** | **Tamper Demonstration, Recovery & Benchmarks** | Dev-only tamper controls, test scripts, performance benchmark harness | **PENDING** | Safe dev-mode tampering triggers, simulated row edit/delete, automated detection in dashboard, benchmark measurements (logging, anchoring, verification latency). |
| **Phase 9** | **End-to-End Testing, Security Hardening & Documentation** | Full `pytest` suite, `README.md`, `TESTING.md`, UI polish, final walkthrough | **PENDING** | >90% test coverage across modules, security validation (OWASP top 5 cloud vectors), error boundary testing, comprehensive deployment documentation. |

---

## 5. Detailed Acceptance Criteria by Phase

### Phase 0: Workspace Inspection & Architecture (Completed)
- [x] Inspect the workspace and identify all existing reports, literature surveys, and documents.
- [x] Extract and incorporate problem statements and findings from Academic Phase-I and Phase-II reports.
- [x] Assess runtime environment (Python 3.11.9 detected; Node.js/Ganache availability noted and handled).
- [x] Produce comprehensive `PROJECT_PLAN.md` with master checklist and acceptance criteria.
- [x] Produce detailed `ARCHITECTURE.md` defining canonical serialization, schemas, contract interfaces, security rules, and discrepancy handling (pending transactions, modified rows, deleted rows, duplicate IDs).
- [x] Produce `docs/PHASE_LOG.md` recording Phase 0 findings.
- [x] Produce `.gitignore` ensuring zero secret leaks, clean git hygiene, and ignored build artifacts.
- [x] Produce `.env.example` documenting all configuration keys, ports, contract addresses, and security flags.

### Phase 1: Environment Setup & Flask Scaffold (Completed)
- [x] Working Python virtual environment configured (`.venv`).
- [x] Dependencies documented in `requirements.txt` with tested version pins (Flask 3, SQLAlchemy, Web3.py, py-solc-x, pytest).
- [x] Working `package.json` created for optional Node/Solidity workflow.
- [x] Application factory in `app/__init__.py` loading settings from `config.py`.
- [x] Configuration classes created for `development`, `testing`, and `production`.
- [x] SQLite database initialized in `instance/cloud_audit.db` with `users`, `audit_logs`, and `files` tables created.
- [x] Dedicated `anchored_status` field on `audit_logs` model, strictly separated from the 5 canonical hashed fields.
- [x] Global design system implemented in `app/static/css/style.css` (dark-glass theme, curated palette, custom badges).
- [x] Responsive `base.html` template and `index.html` landing overview.
- [x] HTTP error templates created for 400, 403, 404, and 500 error codes.
- [x] Health check endpoints `/health` and `/api/health` returning JSON database connectivity and table counts.
- [x] CLI `flask init-db` command registered and tested.
- [x] Comprehensive automated test suite in `tests/test_phase1.py` passing with 10/10 tests.

### Phase 2: Authentication & Authorization (Completed)
- [x] User registration with input validation (username length, character validation, password strength).
- [x] Secure password hashing using Werkzeug `generate_password_hash` / `check_password_hash` (PBKDF2 SHA-256).
- [x] Role-based access control with distinct `user` and `auditor` roles.
- [x] Route decorators (`@login_required`, `@role_required('auditor')`, `@auditor_required`) enforcing server-side authorization.
- [x] Ordinary users strictly blocked from auditor routes (HTTP 403 Forbidden).
- [x] Session protection with secure cookie settings (`HttpOnly`, `SameSite=Lax`).
- [x] CSRF protection enabled on state-mutating requests (`POST`, `PUT`, `DELETE`).
- [x] Audit event triggered upon successful user login (`LOGIN` action, `SESSION` filename, status `PENDING`).
- [x] Safe development CLI command `flask create-auditor` to provision initial auditor accounts without hardcoded secrets.
- [x] Comprehensive test suite in `tests/test_auth.py` passing with 13/13 tests (23/23 total).

### Phase 3: Simulated Cloud File Portal (Completed)
- [x] File upload with secure filename sanitization (`werkzeug.utils.secure_filename`).
- [x] File storage within dedicated `uploads/` directory with UUID-prefixed isolation and strict path-traversal prevention.
- [x] File listing displaying filename, size, owner, and timestamp with ownership isolation.
- [x] Secure download permitted only to file owner or authorized auditor (403 Forbidden for unauthorized requests).
- [x] File modification/replacement and file deletion operations functioning correctly.
- [x] All file operations trigger corresponding audit events (`UPLOAD`, `DOWNLOAD`, `MODIFY`, `DELETE`) through a single unified `audit_service` interface.
- [x] Failed operations are never falsely recorded as successful operations in the audit log.
- [x] When deleting a file, the `DELETE` event is added and all previous historical audit events are preserved.
- [x] Comprehensive test suite in `tests/test_files.py` passing with 13/13 tests (36/36 total).

### Phase 4: Cryptographic Hashing & Audit Records (Completed)
- [x] Canonical serializer enforcing exact field order: `LogID | UserID | ActionType | FileName | Timestamp`.
- [x] Pipe delimiter escaping and backslash normalization preventing field injection attacks.
- [x] Deterministic SHA-256 digest output matching identical inputs across repeated runs.
- [x] Complete audit record saved to SQLite with initial status `PENDING`.
- [x] Support for all 5 cloud and authentication actions: `LOGIN`, `UPLOAD`, `DOWNLOAD`, `MODIFY`, `DELETE`.
- [x] Consistent representation for login events without a file (`SESSION` default value).
- [x] Strict ISO-8601 UTC timestamp formatting and calendar validation (`YYYY-MM-DDTHH:MM:SSZ`).
- [x] Cryptographic avalanche effect and bytes32 hex representation (`0x` + 64 hex chars) verified.
- [x] Full suite of serialization and hashing tests in `tests/test_hashing.py` (9 tests).
- [x] Centralized audit service and SQL persistence tests in `tests/test_audit.py` (10 tests).

### Phase 5: Solidity Smart Contract Deployment (Completed)
- [x] `AuditLogContract.sol` implemented in Solidity `^0.8.20`.
- [x] `LogRecord` struct storing `string logId`, `bytes32 logHash`, `uint256 blockTimestamp`, `bool exists`.
- [x] `storeLogHash` restricted via `onlyOwner` modifier.
- [x] Rejection of empty IDs (`Log ID cannot be empty`), zero hashes (`Log hash cannot be zero`), and duplicate IDs (`Log ID already anchored`).
- [x] Chronologically ordered array `logIdArray` and `getAllLogIds()` maintaining all anchored IDs for deletion detection.
- [x] Automated compilation toolchain `scripts/compile_contract.py` using `solcx` 0.8.20 generating `build/AuditLogContract.json`.
- [x] Deployment script `scripts/deploy_contract.py` targeting local Ganache RPC endpoint with clean offline fallback (no fabricated data).
- [x] Full test suite in `tests/test_blockchain.py` verifying compilation, ABI interface, method identifiers, calldata encoding, and live Ganache integration.

### Phase 6: Web3 Middleware & Reliable Anchoring (Completed)
- [x] Dedicated blockchain client in `app/blockchain/client.py` loading settings from env and local deployment artifacts.
- [x] Two-phase commit logic in `app/blockchain/anchoring.py`: Commit in SQL (`PENDING`) -> Submit transaction -> Confirm receipt -> Update SQL (`ANCHORED`, `tx_hash`, `block_number`).
- [x] Database connections/transactions released before awaiting blockchain mining receipts.
- [x] Graceful degradation when blockchain node is offline (records preserved as `PENDING` with diagnostics).
- [x] Retry queue worker `retry_pending_anchors` and aggregation helper `get_anchoring_stats`.
- [x] Idempotent duplicate transaction prevention via on-chain `isLogAnchored` pre-flight checks.
- [x] Centralized audit service `record_audit_event` connected to anchoring service with non-blocking error handling.
- [x] Comprehensive test suite in `tests/test_anchoring.py` (8 isolated mock tests + 2 live Ganache integration tests).

### Phase 7: Auditor Dashboard & Verification Engine (Completed)
- [x] Auditor-only access protected by server-side role check (`@auditor_required` / `@login_required`).
- [x] Summary metric cards: Total Events, Anchored Hashes, Pending Queue, Blockchain Status & Block Number.
- [x] Interactive filtering by User, Action Type, Anchoring Status, Search query, and paginated table navigation.
- [x] Backend verification engine (`app/audit/verification.py`):
  - Re-serializes each off-chain SQL record and recomputes canonical SHA-256 digest.
  - Queries smart contract for original on-chain hash and cross-checks integrity.
  - Cross-references on-chain `logIdArray` against off-chain SQL rows to detect deleted records (`MISSING_SQL`).
  - Flags records in SQL that have not been anchored (`UNANCHORED`).
  - Accurately classifies offline blockchain as `BLOCKCHAIN_UNAVAILABLE` without falsely labeling connection drops as tampering.
- [x] Distinct visual badges and drill-down diagnostics for `VERIFIED`, `TAMPERED`, `MISSING_SQL`, `UNANCHORED`, and `BLOCKCHAIN_UNAVAILABLE`.
- [x] "Verify Audit Logs" actions via form submit (`POST /audit/verify`) and JSON API (`POST /audit/api/verify`).
- [x] Complete test suite in `tests/test_verification.py` (8 tests passing with 100% coverage).

### Phase 8: Tamper Demonstration & Performance Evaluation (Completed)
- [x] Developer-only tampering simulation routes in `app/audit/routes.py` (`/audit/tamper/modify`, `/audit/tamper/delete`, `/audit/tamper/seed-scenarios`).
- [x] Strict environment restrictions: Tampering tools blocked when `ALLOW_TAMPER_SIMULATION` is False or in production (403 Forbidden).
- [x] Ordinary users strictly blocked from invoking tampering endpoints (403 Forbidden).
- [x] Automated validation suite in `tests/test_tamper_scenarios.py` verifying all 8 demonstration scenarios (10/10 tests passing).
- [x] Empirical benchmark script `scripts/benchmark_performance.py` measuring:
  - Canonical hashing throughput (~300,000 hashes/sec; ~3-4 $\mu$s/hash).
  - SQLite persistence throughput (~2,500 events/sec; ~0.4 ms/event).
  - Dual-layer verification engine scaling over 10, 50, 100, 250, and 500 records (~2,400 verifications/sec).
- [x] Real benchmark figures and hardware specs documented in `docs/benchmark_results.json` and `TESTING.md`.
- [x] Realistic security disclaimers and boundary analysis documented.

### Phase 9: End-to-End Hardening & Documentation (Completed)
- [x] Full `pytest` test suite covering auth, files, hashing, audit, blockchain, and verification (86 tests passing, 100% pass rate).
- [x] Comprehensive `README.md` with step-by-step setup, run commands, architecture diagrams, and 8-step demonstration walkthrough.
- [x] `TESTING.md` detailing test cases, execution instructions, actual benchmark results, module documentation, and honest limitations.
- [x] Polished, modern UI adhering to design excellence, dark-glass theme, and responsive Bootstrap 5 layout.
- [x] Final acceptance checklist verified with zero committed credentials or fake data.
