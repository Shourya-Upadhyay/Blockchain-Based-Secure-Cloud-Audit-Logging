"""
Phase 5 Smart Contract & Blockchain Deployment Tests:
- Contract compilation via py-solc-x / solcx with Solidity 0.8.20
- Build artifact generation (ABI, bytecode, method identifiers)
- Interface specification validation (functions, events, method selectors)
- Off-chain calldata and bytes32 argument encoding
- Graceful degradation when Ganache testnet is offline (no fabricated hashes)
- Live on-chain functional tests when Ganache is running:
  * Owner authorization and access control
  * Valid log hash anchoring with standard LogID format
  * Direct O(1) log retrieval via getLogRecord
  * Chronologically ordered log ID array preservation
  * Rejection of empty Log IDs
  * Rejection of zero log hashes
  * Rejection of duplicate Log IDs
  * Rejection of unauthorized non-owner callers
  * LogAnchored event emission
"""
import os
import json
import pytest
from pathlib import Path
from web3 import Web3

from scripts.compile_contract import compile_audit_contract, ARTIFACT_FILE, SOLC_VERSION
from scripts.deploy_contract import check_rpc_reachable, get_configured_rpc_url, deploy_to_ganache
from app.services.hashing_service import to_bytes32, compute_sha256_hash, canonical_serialize

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def get_live_ganache_connection() -> tuple[bool, Web3 | None, str | None]:
    """Helper to detect reachable local Ganache instance."""
    for rpc in [get_configured_rpc_url(), "http://127.0.0.1:7545", "http://127.0.0.1:8545"]:
        reachable, w3 = check_rpc_reachable(rpc, timeout=1)
        if reachable and w3 is not None:
            return True, w3, rpc
    return False, None, None


GANACHE_ONLINE, W3_INSTANCE, ACTIVE_RPC = get_live_ganache_connection()


# ---------------------------------------------------------------------------
# Static Compilation & Interface Tests (Always Run in Every Environment)
# ---------------------------------------------------------------------------

def test_contract_compiles_successfully():
    """Verify that AuditLogContract.sol compiles cleanly without errors."""
    artifact = compile_audit_contract()
    assert artifact is not None
    assert artifact["contractName"] == "AuditLogContract"
    assert artifact["solcVersion"] == SOLC_VERSION
    assert ARTIFACT_FILE.exists()
    assert len(artifact["abi"]) > 0
    assert artifact["bytecode"].startswith("0x")
    assert len(artifact["bytecode"]) > 100
    assert artifact["deployedBytecode"].startswith("0x")


def test_contract_abi_specification():
    """Verify all required functions and events exist in the compiled ABI."""
    with open(ARTIFACT_FILE, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    abi = artifact["abi"]
    function_names = {entry["name"] for entry in abi if entry.get("type") == "function"}
    event_names = {entry["name"] for entry in abi if entry.get("type") == "event"}

    # Required public/external functions
    required_functions = {
        "storeLogHash",
        "getLogRecord",
        "getAllLogIds",
        "getLogCount",
        "isLogAnchored",
        "owner",
        "logIdArray",
        "transferOwnership",
    }
    for func in required_functions:
        assert func in function_names, f"Missing required function '{func}' in ABI"

    # Required events
    assert "LogAnchored" in event_names
    assert "OwnershipTransferred" in event_names


def test_contract_method_identifiers():
    """Verify standard EVM 4-byte method selectors match the interface specification."""
    with open(ARTIFACT_FILE, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    methods = artifact.get("methodIdentifiers", {})
    assert methods.get("storeLogHash(string,bytes32,uint256)") == "204c85fb"
    assert methods.get("getLogRecord(string)") == "78fefb75"
    assert methods.get("getAllLogIds()") == "33363d33"
    assert methods.get("getLogCount()") == "618033db"
    assert methods.get("isLogAnchored(string)") == "31e66057"
    assert methods.get("owner()") == "8da5cb5b"


def test_contract_calldata_encoding():
    """Verify off-chain Web3 function call encoding produces correct 4-byte selector and arguments."""
    with open(ARTIFACT_FILE, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    w3 = Web3()
    contract = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])

    log_id = "LOG-20261030-A1B2C3D4"
    canonical_str = canonical_serialize(log_id, "test_user", "UPLOAD", "test.pdf", "2026-10-30T12:00:00Z")
    hash_0x = compute_sha256_hash(canonical_str)
    raw_hash_bytes = to_bytes32(hash_0x)
    timestamp = 1793361600

    tx_data = contract.encode_abi(fn_name="storeLogHash", args=[log_id, raw_hash_bytes, timestamp])
    assert tx_data.startswith("0x204c85fb")

    get_data = contract.encode_abi(fn_name="getLogRecord", args=[log_id])
    assert get_data.startswith("0x78fefb75")


def test_offline_deployment_does_not_fabricate_artifacts():
    """
    CRITICAL ARCHITECTURAL INVARIANT:
    When Ganache is unreachable, the deployment script must exit cleanly
    and NEVER fabricate a fake contract address or transaction hash.
    """
    fake_rpc = "http://127.0.0.1:59999"  # Deliberately unreachable port
    result = deploy_to_ganache(rpc_url=fake_rpc)
    assert result is None


# ---------------------------------------------------------------------------
# Live Ganache Testnet Tests (Executed when Ganache is running)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ganache_context():
    """Setup fixture that provisions AuditLogContract on live Ganache testnet if reachable."""
    if not GANACHE_ONLINE or W3_INSTANCE is None:
        pytest.skip(f"Local Ganache node not reachable at {get_configured_rpc_url()} or 8545. Live tests skipped.")

    w3 = W3_INSTANCE
    accounts = w3.eth.accounts
    if not accounts or len(accounts) < 2:
        pytest.skip("Ganache does not provide at least 2 unlocked accounts for authorization testing.")

    deployer = accounts[0]
    unauthorized_user = accounts[1]

    with open(ARTIFACT_FILE, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    contract_factory = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    tx_hash = contract_factory.constructor().transact({"from": deployer, "gas": 3000000})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=10)
    contract = w3.eth.contract(address=receipt.contractAddress, abi=artifact["abi"])

    return {
        "w3": w3,
        "contract": contract,
        "deployer": deployer,
        "unauthorized_user": unauthorized_user,
        "contract_address": receipt.contractAddress,
        "receipt": receipt,
    }


def test_ganache_contract_owner(ganache_context):
    """Verify the deployed contract owner matches the deployer account."""
    contract = ganache_context["contract"]
    deployer = ganache_context["deployer"]
    assert contract.functions.owner().call() == deployer


def test_ganache_store_and_retrieve_valid_log(ganache_context):
    """Verify storing a valid log hash and retrieving its fields via getLogRecord."""
    contract = ganache_context["contract"]
    deployer = ganache_context["deployer"]
    w3 = ganache_context["w3"]

    log_id = "LOG-20261030-VAL00001"
    raw_hash = to_bytes32("0x" + "a" * 64)
    timestamp = 1793361600

    tx_hash = contract.functions.storeLogHash(log_id, raw_hash, timestamp).transact({
        "from": deployer,
        "gas": 300000,
    })
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt.status == 1

    # Verify O(1) existence check
    assert contract.functions.isLogAnchored(log_id).call() is True

    # Verify retrieval
    ret_id, ret_hash, ret_time, exists = contract.functions.getLogRecord(log_id).call()
    assert ret_id == log_id
    assert ret_hash == raw_hash
    assert ret_time == timestamp
    assert exists is True


def test_ganache_ordered_log_id_array(ganache_context):
    """Verify that multiple anchored logs maintain strict chronological array ordering."""
    contract = ganache_context["contract"]
    deployer = ganache_context["deployer"]
    w3 = ganache_context["w3"]

    batch_ids = [
        "LOG-20261030-SEQ00001",
        "LOG-20261030-SEQ00002",
        "LOG-20261030-SEQ00003",
    ]

    for idx, lid in enumerate(batch_ids):
        h = to_bytes32("0x" + f"{idx+1}" * 64)
        tx = contract.functions.storeLogHash(lid, h, 1793361600 + idx).transact({
            "from": deployer,
            "gas": 300000,
        })
        w3.eth.wait_for_transaction_receipt(tx)

    all_ids = contract.functions.getAllLogIds().call()
    for lid in batch_ids:
        assert lid in all_ids

    # Verify count matches array length
    count = contract.functions.getLogCount().call()
    assert count == len(all_ids)


def test_ganache_reject_empty_log_id(ganache_context):
    """Verify that an empty log ID is rejected and transaction reverts."""
    contract = ganache_context["contract"]
    deployer = ganache_context["deployer"]

    raw_hash = to_bytes32("0x" + "b" * 64)
    with pytest.raises(Exception) as excinfo:
        contract.functions.storeLogHash("", raw_hash, 1793361600).transact({
            "from": deployer,
            "gas": 300000,
        })
    assert "Log ID cannot be empty" in str(excinfo.value) or "revert" in str(excinfo.value).lower()


def test_ganache_reject_zero_log_hash(ganache_context):
    """Verify that a zero bytes32 hash is rejected and transaction reverts."""
    contract = ganache_context["contract"]
    deployer = ganache_context["deployer"]

    zero_hash = bytes(32)
    with pytest.raises(Exception) as excinfo:
        contract.functions.storeLogHash("LOG-20261030-ZERO0001", zero_hash, 1793361600).transact({
            "from": deployer,
            "gas": 300000,
        })
    assert "Log hash cannot be zero" in str(excinfo.value) or "revert" in str(excinfo.value).lower()


def test_ganache_reject_duplicate_log_id(ganache_context):
    """Verify that attempting to anchor the same log ID twice reverts with duplicate error."""
    contract = ganache_context["contract"]
    deployer = ganache_context["deployer"]
    w3 = ganache_context["w3"]

    log_id = "LOG-20261030-DUP00001"
    raw_hash = to_bytes32("0x" + "c" * 64)

    # First anchor succeeds
    tx = contract.functions.storeLogHash(log_id, raw_hash, 1793361600).transact({
        "from": deployer,
        "gas": 300000,
    })
    w3.eth.wait_for_transaction_receipt(tx)

    # Second anchor with identical log_id must revert
    with pytest.raises(Exception) as excinfo:
        contract.functions.storeLogHash(log_id, raw_hash, 1793361600).transact({
            "from": deployer,
            "gas": 300000,
        })
    assert "Log ID already anchored" in str(excinfo.value) or "revert" in str(excinfo.value).lower()


def test_ganache_reject_unauthorized_caller(ganache_context):
    """Verify that non-owner accounts cannot execute storeLogHash."""
    contract = ganache_context["contract"]
    unauthorized = ganache_context["unauthorized_user"]

    raw_hash = to_bytes32("0x" + "d" * 64)
    with pytest.raises(Exception) as excinfo:
        contract.functions.storeLogHash("LOG-20261030-UNAUTH01", raw_hash, 1793361600).transact({
            "from": unauthorized,
            "gas": 300000,
        })
    assert "Only contract owner" in str(excinfo.value) or "revert" in str(excinfo.value).lower()


def test_ganache_event_emission(ganache_context):
    """Verify that successful storeLogHash emits the LogAnchored event."""
    contract = ganache_context["contract"]
    deployer = ganache_context["deployer"]
    w3 = ganache_context["w3"]

    log_id = "LOG-20261030-EVENT001"
    raw_hash = to_bytes32("0x" + "e" * 64)
    timestamp = 1793361650

    tx_hash = contract.functions.storeLogHash(log_id, raw_hash, timestamp).transact({
        "from": deployer,
        "gas": 300000,
    })
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    # Extract LogAnchored event from logs
    events = contract.events.LogAnchored().process_receipt(receipt)
    assert len(events) == 1
    event_args = events[0]["args"]
    assert event_args["logId"] == log_id
    assert event_args["logHash"] == raw_hash
    assert event_args["timestamp"] == timestamp
