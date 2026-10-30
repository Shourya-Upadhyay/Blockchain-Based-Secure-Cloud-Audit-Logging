"""
Blockchain Client & Web3 Connection Manager.
Manages connection to local Ganache RPC endpoint, resolves contract address and ABI
from environment variables or local deployment artifacts, and handles transaction signing.
"""
import os
import json
import logging
from pathlib import Path
from flask import current_app, has_app_context
from web3 import Web3

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
BUILD_DIR = PROJECT_ROOT / "build"
INSTANCE_DIR = PROJECT_ROOT / "instance"
ARTIFACT_FILE = BUILD_DIR / "AuditLogContract.json"
DEPLOYMENT_BUILD_FILE = BUILD_DIR / "deployment.json"
DEPLOYMENT_INSTANCE_FILE = INSTANCE_DIR / "deployment.json"


class BlockchainClient:
    """Encapsulates Web3 connection, contract binding, and account handling."""

    def __init__(self, rpc_url: str | None = None, contract_address: str | None = None):
        self._rpc_url = rpc_url
        self._contract_address = contract_address
        self._w3: Web3 | None = None
        self._contract = None
        self._abi = None
        self._last_conn_check = 0.0
        self._cached_conn_status = False
        self._conn_cache_ttl = 3.0  # seconds

    def _get_config_value(self, key: str, default: str = "") -> str:
        """Retrieve setting from Flask current_app config or os.environ."""
        if has_app_context() and key in current_app.config:
            val = current_app.config[key]
            if val:
                return str(val)
        return os.getenv(key, default)

    @property
    def rpc_url(self) -> str:
        """Resolve RPC URL from override, Flask config, or environment defaults."""
        if self._rpc_url:
            return self._rpc_url
        url = self._get_config_value("GANACHE_RPC_URL") or self._get_config_value("GANACHE_URL")
        if not url:
            url = "http://127.0.0.1:7545"
        return url

    def get_web3(self) -> Web3:
        """Get or initialize cached Web3 instance."""
        if self._w3 is None:
            timeout = int(self._get_config_value("WEB3_TIMEOUT_SECONDS", "10"))
            self._w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": timeout}))
        return self._w3

    def is_connected(self, force_refresh: bool = False) -> bool:
        """
        Check if local Ganache blockchain node is alive and responsive.
        Uses short TTL cache (3 seconds) to prevent redundant connection delays when offline.
        """
        import time
        now = time.time()
        if not force_refresh and (now - self._last_conn_check < self._conn_cache_ttl):
            return self._cached_conn_status

        try:
            # Fast check with 0.8s timeout to avoid blocking main thread when offline
            check_w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 0.8}))
            self._cached_conn_status = check_w3.is_connected()
        except Exception:
            self._cached_conn_status = False

        self._last_conn_check = now
        return self._cached_conn_status

    def get_contract_abi(self) -> list:
        """Load contract ABI from build artifact."""
        if self._abi is not None:
            return self._abi

        if ARTIFACT_FILE.exists():
            try:
                with open(ARTIFACT_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._abi = data.get("abi", [])
                    return self._abi
            except Exception as e:
                logger.warning(f"Could not load ABI from {ARTIFACT_FILE}: {e}")

        return []

    def get_contract_address(self) -> str:
        """
        Resolve deployed contract address:
        1. Manual override passed to constructor
        2. Flask config / Environment CONTRACT_ADDRESS (if not zero-address)
        3. Local deployment artifact in instance/deployment.json or build/deployment.json
        """
        if self._contract_address:
            return self._contract_address

        env_addr = self._get_config_value("CONTRACT_ADDRESS", "")
        if env_addr and env_addr != "0x0000000000000000000000000000000000000000":
            return env_addr

        # Check deployment artifact files
        for fpath in [DEPLOYMENT_INSTANCE_FILE, DEPLOYMENT_BUILD_FILE]:
            if fpath.exists():
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        addr = data.get("contract_address")
                        if addr and Web3.is_address(addr):
                            return addr
                except Exception as e:
                    logger.debug(f"Error reading deployment artifact {fpath}: {e}")

        return ""

    def get_contract(self):
        """Return bound Web3 contract instance if connected and deployed."""
        if not self.is_connected():
            return None

        contract_addr = self.get_contract_address()
        if not contract_addr or not Web3.is_address(contract_addr):
            return None

        abi = self.get_contract_abi()
        if not abi:
            return None

        w3 = self.get_web3()
        try:
            checksum_addr = w3.to_checksum_address(contract_addr)
            return w3.eth.contract(address=checksum_addr, abi=abi)
        except Exception as e:
            logger.error(f"Failed to instantiate contract at {contract_addr}: {e}")
            return None

    def get_signing_account(self) -> tuple[str | None, str | None]:
        """
        Resolve deployer/signing account.
        Returns (account_address, private_key) tuple.
        If no private key is configured, defaults to first unlocked Ganache account.
        """
        w3 = self.get_web3()
        priv_key = (
            self._get_config_value("DEPLOYER_PRIVATE_KEY")
            or self._get_config_value("GANACHE_PRIVATE_KEY")
            or self._get_config_value("BLOCKCHAIN_PRIVATE_KEY")
        )

        if priv_key and priv_key != "0x0000000000000000000000000000000000000000000000000000000000000000":
            try:
                acc = w3.eth.account.from_key(priv_key)
                return acc.address, priv_key
            except Exception as e:
                logger.warning(f"Invalid private key configured: {e}")

        # Fallback to Ganache unlocked account[0]
        if self.is_connected():
            try:
                accounts = w3.eth.accounts
                if accounts and len(accounts) > 0:
                    return accounts[0], None
            except Exception as e:
                logger.warning(f"Could not retrieve accounts from Ganache: {e}")

        return None, None

    def get_status(self) -> dict:
        """Diagnostic summary of connection, node, and contract state."""
        connected = self.is_connected()
        status = {
            "connected": connected,
            "rpc_url": self.rpc_url,
            "contract_address": self.get_contract_address() or "Not Deployed",
            "chain_id": None,
            "block_number": None,
            "deployer_address": None,
            "has_private_key": False,
        }

        if connected:
            try:
                w3 = self.get_web3()
                status["chain_id"] = w3.eth.chain_id
                status["block_number"] = w3.eth.block_number
                deployer, priv_key = self.get_signing_account()
                status["deployer_address"] = deployer
                status["has_private_key"] = priv_key is not None
            except Exception as e:
                status["error"] = str(e)

        return status


_global_client: BlockchainClient | None = None


def get_blockchain_client() -> BlockchainClient:
    """Module-level singleton accessor for BlockchainClient."""
    global _global_client
    if _global_client is None:
        _global_client = BlockchainClient()
    return _global_client
