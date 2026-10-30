# Testing Strategy, Validation Suite & Empirical Performance Evaluation

**Project**: Blockchain-Based Secure Cloud Audit Logging  
**Academic Year**: 2026–2027 (B.Tech CSE Major Project)  
**Institution**: School of Computer Science and Engineering, IILM University, Greater Noida  
**Students**: Shourya Upadhyay (`2410031159`) & Jeevesh Pachauri (`2410031186`)  
**Project Guide**: Prof. Dr. Leena Arya  

---

## 1. Testing Philosophy & Invariants

The testing framework verifies the dual-layer architecture pairing off-chain SQLite storage with on-chain Ethereum/Ganache smart contract anchoring.

### Core Testing Invariants
1. **Pure Determinism**: Identical audit inputs must strictly produce identical canonical strings and SHA-256 digests across all executions.
2. **Field Immutability**: Mutable anchoring metadata (`tx_hash`, `block_number`, `anchored_status`, `error_message`, `retry_count`) must never enter canonical serialization or hashing.
3. **Non-Blocking Resilience**: If the blockchain node is offline, off-chain SQL records must remain safely stored as `PENDING`. Application operations (upload, download, modify, delete) must never fail due to RPC connectivity issues.
4. **Connection Isolation**: A blockchain connection failure is classified as `BLOCKCHAIN_UNAVAILABLE` and **never** falsely labeled as proof of data tampering.
5. **Zero Fabrication**: Tests and deployment scripts never fabricate contract addresses, fake transaction hashes, or synthetic benchmark timings.

---

## 2. Test Suite Inventory

The project features **9 comprehensive test modules** containing **86 automated test cases** (and 10 live-node integration tests that run when a local Ganache instance is online):

| Test Module File | Tests | Focus Area & Verified Behaviors |
|---|---|---|
| [`tests/test_phase1.py`](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/tests/test_phase1.py) | 10 | Application factory, environment configurations (`development`, `testing`, `production`), SQLite schemas (`users`, `files`, `audit_logs`), health check endpoints, custom CLI commands (`flask init-db`). |
| [`tests/test_auth.py`](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/tests/test_auth.py) | 13 | Registration validation, PBKDF2 password hashing, login sessions, CSRF protection, server-side RBAC (`user` vs `auditor`), CLI auditor provisioning. |
| [`tests/test_files.py`](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/tests/test_files.py) | 13 | Cloud file storage in `uploads/`, path-traversal prevention (`../../`), upload, download, modify, delete, audit trail preservation on file deletion. |
| [`tests/test_hashing.py`](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/tests/test_hashing.py) | 9 | Strict canonical order, fixed SHA-256 test vectors, avalanche effect, delimiter escaping (`\|`), ISO-8601 UTC validation, `bytes32` conversion. |
| [`tests/test_audit.py`](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/tests/test_audit.py) | 9 | Centralized audit persistence, 5 actions (`LOGIN`, `UPLOAD`, `DOWNLOAD`, `MODIFY`, `DELETE`), tamper detection, mutable field invariance. |
| [`tests/test_blockchain.py`](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/tests/test_blockchain.py) | 13 | Solidity `^0.8.20` compilation via `solcx`, ABI integrity, 4-byte EVM method selectors, calldata encoding, live Ganache deployment. |
| [`tests/test_anchoring.py`](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/tests/test_anchoring.py) | 10 | Web3 middleware, offline RPC resilience, two-phase commit, idempotent duplicate transaction prevention, retry queue worker. |
| [`tests/test_verification.py`](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/tests/test_verification.py) | 8 | Auditor dashboard access control (403 for non-auditors), table filtering, pagination, cryptographic verification engine classifications. |
| [`tests/test_tamper_scenarios.py`](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/tests/test_tamper_scenarios.py) | 10 | Automated validation of the 8 demonstration scenarios and developer-only endpoint security constraints. |

---

## 3. The 8 Core Demonstration Scenarios

An automated validation suite in [`tests/test_tamper_scenarios.py`](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/tests/test_tamper_scenarios.py) proves the system handles all discrepancy and edge-case states:

| # | Scenario Description | Tested State | Verification Engine Classification | Result |
|---|---|---|---|---|
| **1** | **Normal Verified Event** | Valid off-chain SQL record with matching on-chain smart contract hash. | `VERIFIED` | Intact & authentic |
| **2** | **SQL Field Tampered** | Rogue insider modifies an off-chain SQL column (e.g. `action_type` or `file_name`) after anchoring. | `TAMPERED` | Cryptographic hash mismatch flagged |
| **3** | **SQL Row Destroyed** | Rogue insider physically deletes an `AuditLog` row from SQLite after on-chain anchoring. | `MISSING_SQL` | Missing off-chain record detected via on-chain ID list |
| **4** | **Unanchored Event** | An event is saved in SQLite with status `PENDING` but has not yet been submitted to blockchain. | `UNANCHORED` | Local-only record identified |
| **5** | **Blockchain Outage** | The Ganache RPC endpoint is unreachable during an operation. | `BLOCKCHAIN_UNAVAILABLE` | Preserved as PENDING; connection failure isolated from tampering |
| **6** | **Recovery After Outage** | Ganache comes back online; background worker `retry_pending_anchors` executes. | Transitions to `ANCHORED` | Queue cleared and confirmed on-chain |
| **7** | **Duplicate Anchor Attempt** | The application attempts to re-anchor an already confirmed `log_id`. | Idempotent Pass | Revert avoided; SQL synced to `ANCHORED` |
| **8** | **Orphan On-Chain ID** | Smart contract `logIdArray` contains an ID absent from SQLite. | `MISSING_SQL` | Deletion detected via blockchain log list |

---

## 4. Empirical Performance Benchmark Evaluation

Benchmarks were executed on authentic host hardware using [`scripts/benchmark_performance.py`](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/scripts/benchmark_performance.py). All raw measurements are preserved in [`docs/benchmark_results.json`](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/docs/benchmark_results.json).

### Benchmark Environment Configuration
- **Host Operating System**: Windows 10/11 Enterprise (Build `10.0.26100`, AMD64)
- **Host Processor**: Intel64 Family 6 Model 151 Stepping 2, GenuineIntel (8 Logical Cores)
- **Runtime Environment**: Python `3.11.9` (MSC v.1938 64-bit)
- **Off-Chain Database**: SQLite 3 (WAL mode)
- **Compiler Version**: Solidity `0.8.20` (Optimizer enabled, 200 runs)

---

### Benchmark 1: Canonical Serialization & SHA-256 Hashing
Measures raw cryptographic serialization, pipe escaping, and SHA-256 hashing:

| Event Count | Trials | Avg Duration (s) | Throughput (hashes/sec) | Latency ($\mu$s/hash) |
|---|---|---|---|---|
| **10** | 3 | 0.00004 | 248,962.68 | **4.02 $\mu$s** |
| **50** | 3 | 0.00012 | 408,608.02 | **2.45 $\mu$s** |
| **100** | 3 | 0.00025 | 398,724.08 | **2.51 $\mu$s** |
| **250** | 3 | 0.00070 | 356,938.89 | **2.80 $\mu$s** |
| **500** | 3 | 0.00149 | 335,728.19 | **2.98 $\mu$s** |

> **Key Finding**: Canonical serialization and SHA-256 hashing achieve over **330,000 to 400,000 hashes/second** with sub-3-microsecond latency, confirming that cryptographic hash calculation introduces negligible overhead to cloud operations.

---

### Benchmark 2: SQLite Off-Chain Persistence
Measures database model creation, validation, and SQLite disk commit latency:

| Record Count | Trials | Avg Duration (s) | Throughput (events/sec) | Latency (ms/event) |
|---|---|---|---|---|
| **10** | 3 | 0.00444 | 2,254.55 | **0.44 ms** |
| **50** | 3 | 0.01881 | 2,658.54 | **0.38 ms** |
| **100** | 3 | 0.03979 | 2,513.36 | **0.40 ms** |
| **250** | 3 | 0.09573 | 2,611.40 | **0.38 ms** |
| **500** | 3 | 0.20686 | 2,417.06 | **0.41 ms** |

> **Key Finding**: Off-chain SQL audit logging operates at **~2,500 events/second** (~0.4 ms per record). Committing off-chain records before contacting the blockchain ensures cloud operations remain fast and responsive.

---

### Benchmark 3: Dual-Layer Verification Engine Scaling
Measures full-table re-serialization, hash recomputation, on-chain lookup, and discrepancy detection:

| Record Count | Trials | Avg Duration (s) | Throughput (records/sec) | Latency (ms/record) |
|---|---|---|---|---|
| **10** | 3 | 0.00354 | 2,824.70 | **0.354 ms** |
| **50** | 3 | 0.01424 | 3,511.48 | **0.285 ms** |
| **100** | 3 | 0.04492 | 2,226.38 | **0.449 ms** |
| **250** | 3 | 0.08331 | 3,000.84 | **0.333 ms** |
| **500** | 3 | 0.16125 | 3,100.67 | **0.323 ms** |

> **Key Finding**: Verification of **500 audit logs executes in ~161 milliseconds** (~3,100 verifications/second). The auditor dashboard can perform instant real-time cryptographic audit trail integrity checks with sub-second response times.

---

## 5. Major Module Documentation

### A. Authentication & Authorization Module (`app/auth/`)
- **[routes.py](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/app/auth/routes.py)**: Manages `/register`, `/login`, `/logout`, and `/profile`. Validates usernames (3–30 chars, alphanumeric) and passwords (8+ chars, digit/special char). Prevents open redirects using relative-path verification.
- **[decorators.py](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/app/auth/decorators.py)**: `@login_required` redirects unauthenticated users to `/login`. `@auditor_required` returns HTTP `403 Forbidden` for non-auditors.
- **[auth_service.py](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/app/services/auth_service.py)**: Werkzeug PBKDF2 with SHA-256 hashing. Automatically emits `LOGIN` event with filename `SESSION` upon successful authentication. Manages CSRF tokens with constant-time comparison (`hmac.compare_digest`).

### B. Cloud Storage Portal (`app/cloud/`)
- **[routes.py](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/app/cloud/routes.py)**: Portal interface at `/cloud/files`. Handles file upload (`/cloud/upload`), download (`/cloud/download/<id>`), content replacement (`/cloud/modify/<id>`), and deletion (`/cloud/delete/<id>`).
- **[file_service.py](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/app/services/file_service.py)**: Enforces ownership checks on every operation. Validates paths against traversal attacks (`validate_path_safety`). Dispatches `UPLOAD`, `DOWNLOAD`, `MODIFY`, and `DELETE` events through the unified audit service.

### C. Centralized Audit & Canonical Hashing Service (`app/services/`)
- **[audit_service.py](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/app/services/audit_service.py)**: Unified `record_audit_event` entry point. Persists in SQLite first as `PENDING`, then triggers Web3 anchoring. Guarantees file operations never fail if blockchain is offline.
- **[hashing_service.py](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/app/services/hashing_service.py)**: Serializes canonical string: `LogID | UserID | ActionType | FileName | Timestamp`. Escapes `|` to `\|` and `\` to `\\`. Validates ISO-8601 UTC. Digests to SHA-256 and formats as `bytes32`.

### D. Smart Contract & Blockchain Middleware (`contracts/`, `app/blockchain/`)
- **[AuditLogContract.sol](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/contracts/AuditLogContract.sol)**: Owner-controlled `storeLogHash(logId, logHash, timestamp)`. Rejects duplicate IDs and empty hashes. Maintains `logIdArray` for deletion detection. Emits `LogAnchored` event.
- **[client.py](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/app/blockchain/client.py)**: Web3 connection manager with 3.0s TTL connection caching. Resolves ABI and address from `build/` or `.env`. Manages deployer account signing.
- **[anchoring.py](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/app/blockchain/anchoring.py)**: Implements two-phase commit. Closes DB transactions before Web3 calls. Performs pre-flight idempotency checks. Updates SQL record to `ANCHORED` upon receipt confirmation. Manages `retry_pending_anchors` queue worker.

### E. Auditor Dashboard & Verification Engine (`app/audit/`)
- **[verification.py](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/app/audit/verification.py)**: Full cryptographic audit trail verification. Compares recalculated canonical SHA-256 against on-chain hash. Enumerates on-chain `logIdArray` to detect deleted SQL rows (`MISSING_SQL`). Categorizes 5 distinct statuses.
- **[routes.py](file:///c:/Users/shour/OneDrive/Desktop/MAJOR%20PROJECT%20072/app/audit/routes.py)**: Dashboard views with filtering and pagination. Form and JSON verification endpoints. Developer tampering simulation endpoints protected by `ALLOW_TAMPER_SIMULATION` and `@auditor_required`.

---

## 6. Honest Assessment of Known Limitations

In compliance with academic integrity and engineering honesty, the following constraints of this prototype are explicitly noted:

1. **Off-Chain Database Concurrency (SQLite)**:
   - SQLite is an embedded file-based database. While WAL (Write-Ahead Logging) mode permits concurrent readers, write operations require a database file lock. In an enterprise cloud deployment handling thousands of concurrent writes, SQLite must be replaced with PostgreSQL or MySQL.
2. **Local Physical File Storage**:
   - Uploaded files are stored in a local directory (`uploads/`). In production, physical files should be distributed across decentralized object stores (e.g. MinIO, AWS S3, or IPFS) with content-addressable storage (CID).
3. **Single-Node Testnet (Ganache)**:
   - The blockchain layer runs on a local Ganache instance. Ganache does not utilize distributed Byzantine Fault Tolerant (BFT) consensus or proof-of-stake across multiple independent validator nodes.
4. **Deployer Key Centralization**:
   - Transaction signing uses a single deployer private key loaded from environment configuration. If this key is compromised, an attacker could submit unauthorized hashes. Production architectures require Hardware Security Modules (HSM) or Multi-Party Computation (MPC) key management.
5. **Metadata Anchoring vs Whole-File Hashing**:
   - The system anchors *audit metadata* (log ID, user, action, filename, timestamp), not the raw binary contents of multi-gigabyte files. File integrity is verified through file modification events (`MODIFY`), but physical disk corruption without application awareness would require separate file integrity monitoring (FIM).
6. **Academic Prototype Status**:
   - The application is an academic proof-of-concept demonstration. While fully functional and thoroughly tested, it is not production-ready without enterprise hardening (WAF, rate-limiting, TLS termination, KMS integration, and independent security audits).

---

## 7. Final Acceptance Checklist

- [x] **Registration & Authentication**: Tested with PBKDF2 hashing, secure session cookies, and CSRF protection.
- [x] **Role-Based Access Control**: Ordinary users blocked from auditor and tampering routes (`403 Forbidden`).
- [x] **Cloud File Portal**: Safe file upload, listing, download, content modification, and deletion with path traversal protection.
- [x] **Unified Audit Service**: Every authentication and file operation logs an event via a single interface; deletions preserve audit history.
- [x] **Canonical Serialization**: Strict 5-field order, delimiter escaping, and ISO-8601 UTC validation.
- [x] **Solidity Smart Contract**: `AuditLogContract.sol` compiled with 0.8.20 optimizer; stores `bytes32` hashes and log IDs with duplicate prevention.
- [x] **Two-Phase Commit Web3 Middleware**: Commits SQL first, checks idempotency, anchors on Ganache, updates receipt status, and queues pending transactions on outage.
- [x] **Auditor Verification Engine**: Recalculates canonical hashes, detects `VERIFIED`, `TAMPERED`, `MISSING_SQL`, `UNANCHORED`, and `BLOCKCHAIN_UNAVAILABLE`.
- [x] **8 Demonstration Scenarios**: Fully verified via automated test suite `tests/test_tamper_scenarios.py`.
- [x] **Zero Fabrications**: Real hardware benchmarks recorded; offline nodes handled gracefully without fake addresses.
- [x] **No Committed Secrets**: Verified zero hardcoded private keys or passwords in version control.
