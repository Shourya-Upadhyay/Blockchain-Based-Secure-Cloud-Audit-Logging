"""
Solidity Contract Compilation Toolchain.
Compiles contracts/AuditLogContract.sol using solcx (Solidity 0.8.20)
and produces reproducible build artifacts in build/AuditLogContract.json.
"""
import json
import sys
from pathlib import Path
from datetime import datetime, timezone
import urllib.request
import solcx

# Repository root directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONTRACT_FILE = PROJECT_ROOT / "contracts" / "AuditLogContract.sol"
BUILD_DIR = PROJECT_ROOT / "build"
ARTIFACT_FILE = BUILD_DIR / "AuditLogContract.json"

SOLC_VERSION = "0.8.20"


def ensure_solc_installed(version: str = SOLC_VERSION) -> str:
    """
    Ensure the target Solidity compiler version is installed locally.
    Uses browser User-Agent header to avoid 403 Forbidden from binaries.soliditylang.org.
    """
    installed_versions = [str(v) for v in solcx.get_installed_solc_versions()]
    if version not in installed_versions:
        opener = urllib.request.build_opener()
        opener.addheaders = [("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")]
        urllib.request.install_opener(opener)
        solcx.install_solc(version)

    solcx.set_solc_version(version)
    return version


def compile_audit_contract() -> dict:
    """
    Compile contracts/AuditLogContract.sol with optimizer enabled (200 runs).
    Returns dict containing contract name, ABI, bytecode, and metadata.
    """
    if not CONTRACT_FILE.exists():
        raise FileNotFoundError(f"Contract file not found at {CONTRACT_FILE}")

    ensure_solc_installed(SOLC_VERSION)

    with open(CONTRACT_FILE, "r", encoding="utf-8") as f:
        contract_source = f.read()

    input_json = {
        "language": "Solidity",
        "sources": {
            "AuditLogContract.sol": {
                "content": contract_source
            }
        },
        "settings": {
            "optimizer": {
                "enabled": True,
                "runs": 200,
            },
            "evmVersion": "paris",
            "outputSelection": {
                "*": {
                    "*": [
                        "abi",
                        "evm.bytecode.object",
                        "evm.deployedBytecode.object",
                        "evm.methodIdentifiers",
                    ]
                }
            },
        },
    }

    compiled = solcx.compile_standard(input_json, solc_version=SOLC_VERSION)

    contract_data = compiled["contracts"]["AuditLogContract.sol"]["AuditLogContract"]
    abi = contract_data["abi"]
    bytecode = contract_data["evm"]["bytecode"]["object"]
    deployed_bytecode = contract_data["evm"]["deployedBytecode"]["object"]
    method_identifiers = contract_data["evm"]["methodIdentifiers"]

    artifact = {
        "contractName": "AuditLogContract",
        "solcVersion": SOLC_VERSION,
        "evmVersion": "paris",
        "compiledAt": datetime.now(timezone.utc).isoformat(),
        "abi": abi,
        "bytecode": bytecode if bytecode.startswith("0x") else f"0x{bytecode}",
        "deployedBytecode": deployed_bytecode if deployed_bytecode.startswith("0x") else f"0x{deployed_bytecode}",
        "methodIdentifiers": method_identifiers,
    }

    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    with open(ARTIFACT_FILE, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)

    return artifact


if __name__ == "__main__":
    try:
        artifact = compile_audit_contract()
        print(f"[OK] AuditLogContract compiled successfully with solc {SOLC_VERSION}")
        print(f"     Artifact saved to: {ARTIFACT_FILE}")
        print(f"     ABI entries: {len(artifact['abi'])}")
        print(f"     Bytecode length: {len(artifact['bytecode'])} hex chars")
    except Exception as e:
        print(f"[ERROR] Compilation failed: {e}", file=sys.stderr)
        sys.exit(1)
