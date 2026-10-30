"""
Blockchain Integration Package.
Provides Web3 connection client and reliable two-phase hash anchoring service.
"""
from app.blockchain.client import BlockchainClient, get_blockchain_client
from app.blockchain.anchoring import (
    anchor_single_log,
    retry_pending_anchors,
    get_anchoring_stats,
)

__all__ = [
    "BlockchainClient",
    "get_blockchain_client",
    "anchor_single_log",
    "retry_pending_anchors",
    "get_anchoring_stats",
]
