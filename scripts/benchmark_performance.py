"""
Performance Benchmark Evaluation Script.
Measures real performance across increasing audit log counts:
1. Canonical SHA-256 Hashing throughput and latency.
2. SQLite Audit Persistence insertion throughput and latency.
3. Dual-Layer Verification Engine execution time.
4. Gathers actual system hardware, OS, and Python configuration.
Saves empirical measurements to docs/benchmark_results.json.
Never fabricates results.
"""
import os
import sys
import time
import json
import platform
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import MagicMock

# Add repository root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.extensions import db
from app.models.audit_log import AuditLog
from app.services.hashing_service import hash_audit_fields, to_bytes32
from app.services.audit_service import record_audit_event
from app.audit.verification import verify_audit_trail
from app.blockchain.client import BlockchainClient


def get_environment_info() -> dict:
    """Capture authentic host hardware and runtime specifications."""
    info = {
        "os_name": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor() or "AMD64 Family",
        "cpu_cores_logical": os.cpu_count() or 1,
        "python_version": sys.version.split()[0],
        "python_compiler": platform.python_compiler(),
        "benchmarked_at": datetime.now(timezone.utc).isoformat(),
    }
    return info


def benchmark_canonical_hashing(counts: list[int], trials: int = 3) -> dict:
    """Measure raw canonical serialization and SHA-256 digest computation."""
    results = {}
    for n in counts:
        trial_times = []
        for _ in range(trials):
            start = time.perf_counter()
            for i in range(n):
                hash_audit_fields(
                    log_id=f"LOG-20261030-{i:06d}",
                    user_id="bench_user",
                    action_type="UPLOAD",
                    file_name=f"benchmark_dataset_{i}.csv",
                    timestamp="2026-10-30T12:00:00Z",
                )
            duration = time.perf_counter() - start
            trial_times.append(duration)

        avg_time = sum(trial_times) / trials
        throughput = n / avg_time if avg_time > 0 else 0
        per_event_us = (avg_time / n) * 1_000_000 if n > 0 else 0

        results[str(n)] = {
            "record_count": n,
            "trials": trials,
            "avg_duration_seconds": round(avg_time, 5),
            "min_duration_seconds": round(min(trial_times), 5),
            "max_duration_seconds": round(max(trial_times), 5),
            "throughput_hashes_per_sec": round(throughput, 2),
            "latency_us_per_hash": round(per_event_us, 2),
        }
    return results


def benchmark_sql_persistence(counts: list[int], app, trials: int = 3) -> dict:
    """Measure SQLite database insertion latency and throughput."""
    results = {}
    for n in counts:
        trial_times = []
        for trial_idx in range(trials):
            with app.app_context():
                # Clean table for isolated batch
                db.session.query(AuditLog).delete()
                db.session.commit()

                start = time.perf_counter()
                for i in range(n):
                    record_audit_event(
                        user_id=f"user_{i % 5}",
                        action_type="UPLOAD" if i % 2 == 0 else "DOWNLOAD",
                        file_name=f"file_{i}.dat",
                        auto_anchor=False,
                    )
                duration = time.perf_counter() - start
                trial_times.append(duration)

        avg_time = sum(trial_times) / trials
        throughput = n / avg_time if avg_time > 0 else 0
        per_event_ms = (avg_time / n) * 1000 if n > 0 else 0

        results[str(n)] = {
            "record_count": n,
            "trials": trials,
            "avg_duration_seconds": round(avg_time, 5),
            "min_duration_seconds": round(min(trial_times), 5),
            "max_duration_seconds": round(max(trial_times), 5),
            "throughput_events_per_sec": round(throughput, 2),
            "latency_ms_per_event": round(per_event_ms, 2),
        }
    return results


def benchmark_verification_engine(counts: list[int], app, trials: int = 3) -> dict:
    """Measure dual-layer verification engine scaling over increasing record counts."""
    results = {}
    for n in counts:
        trial_times = []
        with app.app_context():
            # Populate N records in SQLite
            db.session.query(AuditLog).delete()
            db.session.commit()

            created_logs = []
            for i in range(n):
                rec = record_audit_event(
                    user_id=f"auditor_bench_{i % 10}",
                    action_type="UPLOAD",
                    file_name=f"verified_doc_{i}.pdf",
                    auto_anchor=False,
                )
                created_logs.append(rec)

            log_ids = [l.log_id for l in created_logs]
            log_records_dict = {}
            for l in created_logs:
                raw = to_bytes32(l.log_hash)
                log_records_dict[l.log_id] = (l.log_id, raw, 1793361600, True)

            # Build mock smart contract simulating instantaneous on-chain query response
            mock_contract = MagicMock()
            mock_contract.functions.getAllLogIds.return_value.call.return_value = log_ids

            def make_log_record_callable(lid):
                fn_mock = MagicMock()
                fn_mock.call.return_value = log_records_dict.get(lid, (lid, bytes(32), 0, False))
                return fn_mock

            mock_contract.functions.getLogRecord.side_effect = make_log_record_callable

            mock_client = MagicMock(spec=BlockchainClient)
            mock_client.is_connected.return_value = True
            mock_client.get_contract.return_value = mock_contract

            # Measure verification executions
            for _ in range(trials):
                start = time.perf_counter()
                report = verify_audit_trail(client=mock_client)
                duration = time.perf_counter() - start
                trial_times.append(duration)
                assert report["summary"]["verified"] == n

        avg_time = sum(trial_times) / trials
        throughput = n / avg_time if avg_time > 0 else 0
        per_record_ms = (avg_time / n) * 1000 if n > 0 else 0

        results[str(n)] = {
            "record_count": n,
            "trials": trials,
            "avg_duration_seconds": round(avg_time, 5),
            "min_duration_seconds": round(min(trial_times), 5),
            "max_duration_seconds": round(max(trial_times), 5),
            "throughput_verifications_per_sec": round(throughput, 2),
            "latency_ms_per_record": round(per_record_ms, 3),
        }
    return results


def run_all_benchmarks(counts: list[int] = [10, 50, 100, 250, 500], trials: int = 3) -> dict:
    """Execute complete performance benchmark suite and persist results."""
    print("=" * 70)
    print("Blockchain-Based Secure Cloud Audit Logging: Performance Benchmarks")
    print("=" * 70)

    env_info = get_environment_info()
    print(f"[HOST] OS:        {env_info['os_name']} {env_info['os_release']} ({env_info['architecture']})")
    print(f"[HOST] CPU Cores: {env_info['cpu_cores_logical']}")
    print(f"[HOST] Python:    {env_info['python_version']}")
    print(f"[TEST] Batch Sizes: {counts}")
    print(f"[TEST] Trials/Batch: {trials}")
    print("-" * 70)

    # 1. Benchmark Canonical Hashing
    print("[1/3] Benchmarking Canonical Serialization & SHA-256 Hashing...")
    hashing_results = benchmark_canonical_hashing(counts, trials=trials)
    for cnt, data in hashing_results.items():
        print(f"      Count {cnt:4s}: {data['throughput_hashes_per_sec']:>10.2f} hashes/s | {data['latency_us_per_hash']:>6.2f} us/hash")

    # 2. Benchmark SQL Persistence
    print("\n[2/3] Benchmarking SQLite Off-Chain Persistence...")
    app = create_app("testing")
    with app.app_context():
        db.create_all()

    sql_results = benchmark_sql_persistence(counts, app, trials=trials)
    for cnt, data in sql_results.items():
        print(f"      Count {cnt:4s}: {data['throughput_events_per_sec']:>10.2f} events/s | {data['latency_ms_per_event']:>6.2f} ms/event")

    # 3. Benchmark Verification Engine
    print("\n[3/3] Benchmarking Dual-Layer Verification Engine...")
    verification_results = benchmark_verification_engine(counts, app, trials=trials)
    for cnt, data in verification_results.items():
        print(f"      Count {cnt:4s}: {data['throughput_verifications_per_sec']:>10.2f} records/s | {data['latency_ms_per_record']:>6.3f} ms/record")

    payload = {
        "metadata": {
            "title": "Blockchain-Based Secure Cloud Audit Logging - Empirical Performance Results",
            "project": "B.Tech CSE Major Project 2026-2027",
            "students": "Shourya Upadhyay (2410031159), Jeevesh Pachauri (2410031186)",
            "institution": "School of Computer Science and Engineering, IILM University, Greater Noida",
        },
        "environment": env_info,
        "results": {
            "canonical_hashing": hashing_results,
            "sqlite_persistence": sql_results,
            "verification_engine": verification_results,
        },
    }

    docs_dir = PROJECT_ROOT / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    results_file = docs_dir / "benchmark_results.json"
    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print("-" * 70)
    print(f"[SUCCESS] Real benchmark results saved to: {results_file}")
    print("=" * 70)
    return payload


if __name__ == "__main__":
    run_all_benchmarks()
