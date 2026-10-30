"""
Ganache Local Testnet Deployment Script for AuditLogContract.
Deploy the compiled AuditLogContract to the configured local Ganache RPC endpoint.
Records deployment metadata in build/deployment.json and instance/deployment.json.
Never deploys to public networks or fabricates fake addresses.
"""
import os
import sys
import json
from pathlib import Path
from datetime import datetime, timezone
from web3 import Web3
from dotenv import load_dotenv

# Ensure repository root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.compile_contract import compile_audit_contract, ARTIFACT_FILE

load_dotenv(PROJECT_ROOT / ".env")

BUILD_DIR = PROJECT_ROOT / "build"
INSTANCE_DIR = PROJECT_ROOT / "instance"
DEPLOYMENT_BUILD_FILE = BUILD_DIR / "deployment.json"
DEPLOYMENT_INSTANCE_FILE = INSTANCE_DIR / "deployment.json"


def get_configured_rpc_url() -> str:
    """Resolve Ganache RPC endpoint from environment or standard defaults."""
    return (
        os.getenv("GANACHE_RPC_URL")
        or os.getenv("GANACHE_URL")
        or os.getenv("WEB3_PROVIDER_URI")
        or "http://127.0.0.1:7545"
    )


def check_rpc_reachable(rpc_url: str, timeout: int = 2) -> tuple[bool, Web3 | None]:
    """Check if the Ethereum RPC node is reachable and responsive."""
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": timeout}))
        if w3.is_connected():
            return True, w3
    except Exception:
        pass
    return False, None


def deploy_to_ganache(rpc_url: str | None = None) -> dict | None:
    """
    Attempt deployment to local Ganache.
    If Ganache is reachable, compiles the contract, deploys it, and writes the deployment artifact.
    If Ganache is unreachable, skips deployment cleanly without fabricating data.
    """
    target_rpc = rpc_url or get_configured_rpc_url()

    is_reachable, w3 = check_rpc_reachable(target_rpc)
    if not is_reachable:
        # Fallback check for alternate Ganache port 8545
        alt_rpc = "http://127.0.0.1:8545"
        if target_rpc != alt_rpc:
            is_alt_reachable, alt_w3 = check_rpc_reachable(alt_rpc)
            if is_alt_reachable:
                target_rpc = alt_rpc
                w3 = alt_w3
                is_reachable = True

    if not is_reachable or w3 is None:
        print(f"[SKIPPED] Ganache RPC endpoint is not reachable at {target_rpc}.")
        print("[INFO] Local deployment skipped. Invariant upheld: Never fabricating fake deployment addresses or hashes.")
        return None

    # Load or compile contract artifact
    if not ARTIFACT_FILE.exists():
        print("[INFO] Compiled artifact not found. Compiling AuditLogContract.sol...")
        artifact = compile_audit_contract()
    else:
        with open(ARTIFACT_FILE, "r", encoding="utf-8") as f:
            artifact = json.load(f)

    abi = artifact["abi"]
    bytecode = artifact["bytecode"]

    # Select deployer account
    private_key = (
        os.getenv("DEPLOYER_PRIVATE_KEY")
        or os.getenv("GANACHE_PRIVATE_KEY")
        or os.getenv("BLOCKCHAIN_PRIVATE_KEY")
    )
    accounts = w3.eth.accounts

    if private_key:
        account = w3.eth.account.from_key(private_key)
        deployer_address = account.address
        use_signing = True
    elif accounts and len(accounts) > 0:
        deployer_address = accounts[0]
        use_signing = False
    else:
        print("[ERROR] No unlocked accounts found on Ganache and no private key provided.", file=sys.stderr)
        return None

    print(f"[INFO] Deploying AuditLogContract to Ganache ({target_rpc}) from account {deployer_address}...")

    AuditLogContract = w3.eth.contract(abi=abi, bytecode=bytecode)

    if use_signing:
        nonce = w3.eth.get_transaction_count(deployer_address)
        tx_data = AuditLogContract.constructor().build_transaction({
            "from": deployer_address,
            "nonce": nonce,
            "gas": 3000000,
            "gasPrice": w3.eth.gas_price,
        })
        signed_tx = w3.eth.account.sign_transaction(tx_data, private_key=private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    else:
        tx_hash = AuditLogContract.constructor().transact({"from": deployer_address, "gas": 3000000})

    print(f"[INFO] Deployment transaction sent: {tx_hash.hex()}. Awaiting confirmation...")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    contract_address = receipt.contractAddress

    if receipt.status != 1:
        print(f"[ERROR] Deployment transaction failed on-chain! Status: {receipt.status}", file=sys.stderr)
        return None

    chain_id = w3.eth.chain_id

    deployment_data = {
        "contract_name": "AuditLogContract",
        "contract_address": contract_address,
        "transaction_hash": receipt.transactionHash.hex(),
        "block_number": receipt.blockNumber,
        "deployer_address": deployer_address,
        "chain_id": chain_id,
        "rpc_url": target_rpc,
        "deployed_at": datetime.now(timezone.utc).isoformat(),
        "solc_version": artifact.get("solcVersion", "0.8.20"),
    }

    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

    with open(DEPLOYMENT_BUILD_FILE, "w", encoding="utf-8") as f:
        json.dump(deployment_data, f, indent=2)

    with open(DEPLOYMENT_INSTANCE_FILE, "w", encoding="utf-8") as f:
        json.dump(deployment_data, f, indent=2)

    print(f"[SUCCESS] AuditLogContract deployed successfully!")
    print(f"          Contract Address: {contract_address}")
    print(f"          Transaction Hash: {receipt.transactionHash.hex()}")
    print(f"          Block Number:     {receipt.blockNumber}")
    print(f"          Deployment metadata saved to {DEPLOYMENT_BUILD_FILE}")

    return deployment_data


if __name__ == "__main__":
    result = deploy_to_ganache()
    if result is None:
        sys.exit(0)  # Graceful exit when Ganache is offline
    sys.exit(0)
