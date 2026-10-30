// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AuditLogContract
 * @notice Immutable blockchain trust anchor for Cloud Audit Logging.
 * @dev Stores SHA-256 digests of off-chain cloud audit events on private Ethereum/Ganache testnet.
 * Part of B.Tech CSE Major Project: Blockchain-Based Secure Cloud Audit Logging.
 */
contract AuditLogContract {
    // Owner address authorized to commit audit log hashes
    address public owner;

    // Struct encapsulating an immutable anchored audit record
    struct LogRecord {
        string logId;           // Unique event identifier (e.g. LOG-YYYYMMDD-XXXXXXXX)
        bytes32 logHash;        // SHA-256 cryptographic digest as bytes32
        uint256 blockTimestamp; // Unix timestamp recorded at anchoring time
        bool exists;            // Existence flag to guarantee O(1) duplicate prevention
    }

    // Mapping for O(1) constant-time direct lookup by logId
    mapping(string => LogRecord) private logRegistry;

    // Chronologically ordered array of anchored log IDs for comprehensive deletion detection
    string[] public logIdArray;

    // Emitted whenever a log hash is successfully anchored on-chain
    event LogAnchored(
        string indexed logIdIndex,
        string logId,
        bytes32 logHash,
        uint256 timestamp,
        uint256 blockNumber
    );

    // Emitted if contract ownership is transferred
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // Access control modifier restricting write operations strictly to contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only contract owner can perform this action");
        _;
    }

    /**
     * @notice Constructor sets the deploying account as initial contract owner.
     */
    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /**
     * @notice Store a verified SHA-256 audit log hash on-chain.
     * @dev Only callable by contract owner. Rejects empty IDs, duplicate IDs, and zero hashes.
     * @param _logId Unique log identifier (e.g. LOG-20261030-A1B2C3D4).
     * @param _logHash Exact 32-byte SHA-256 cryptographic digest.
     * @param _timestamp Unix timestamp or off-chain block timestamp.
     */
    function storeLogHash(
        string calldata _logId,
        bytes32 _logHash,
        uint256 _timestamp
    ) external onlyOwner {
        require(bytes(_logId).length > 0, "Log ID cannot be empty");
        require(_logHash != bytes32(0), "Log hash cannot be zero");
        require(!logRegistry[_logId].exists, "Log ID already anchored");

        uint256 effectiveTimestamp = _timestamp > 0 ? _timestamp : block.timestamp;

        logRegistry[_logId] = LogRecord({
            logId: _logId,
            logHash: _logHash,
            blockTimestamp: effectiveTimestamp,
            exists: true
        });

        logIdArray.push(_logId);

        emit LogAnchored(_logId, _logId, _logHash, effectiveTimestamp, block.number);
    }

    /**
     * @notice Retrieve an anchored log record by its unique logId.
     * @param _logId Unique log identifier.
     * @return logId The log identifier string.
     * @return logHash The 32-byte SHA-256 hash digest.
     * @return blockTimestamp The timestamp at which the record was anchored.
     * @return exists True if the record exists on-chain, false otherwise.
     */
    function getLogRecord(string calldata _logId)
        external
        view
        returns (
            string memory logId,
            bytes32 logHash,
            uint256 blockTimestamp,
            bool exists
        )
    {
        LogRecord storage record = logRegistry[_logId];
        return (record.logId, record.logHash, record.blockTimestamp, record.exists);
    }

    /**
     * @notice Return the full ordered array of all anchored log IDs.
     * @dev Used by auditor verification engine to detect deleted off-chain SQL records.
     * @return An ordered array of log ID strings.
     */
    function getAllLogIds() external view returns (string[] memory) {
        return logIdArray;
    }

    /**
     * @notice Return total count of anchored records.
     */
    function getLogCount() external view returns (uint256) {
        return logIdArray.length;
    }

    /**
     * @notice Check whether a given logId exists on-chain.
     * @param _logId Unique log identifier.
     * @return True if anchored, false otherwise.
     */
    function isLogAnchored(string calldata _logId) external view returns (bool) {
        return logRegistry[_logId].exists;
    }

    /**
     * @notice Transfer contract ownership to a new address.
     * @param _newOwner Address of the new contract owner.
     */
    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "New owner cannot be zero address");
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }
}
