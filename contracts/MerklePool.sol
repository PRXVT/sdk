// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../lib/poseidon-solidity/contracts/PoseidonT3.sol";
import "../lib/poseidon-solidity/contracts/PoseidonT4.sol";

/**
 * @title MerklePool
 * @notice Pool contract for zk-private X402 payments with UTXO model
 * @dev Stores Merkle commitments using proper binary Merkle tree, manages root buffer
 */
contract MerklePool is Ownable, ReentrancyGuard {
    IERC20 public immutable usdc;

    // Merkle tree parameters
    uint256 public constant TREE_DEPTH = 20; // 2^20 = 1M capacity

    // Root buffer for async proof generation (last 10 roots remain valid)
    bytes32[10] public rootHistory;
    uint256 public currentRootIndex;
    uint256 public nextLeafIndex;

    // Merkle tree storage
    mapping(uint256 => bytes32) public filledSubtrees; // Stores last value at each level
    bytes32[20] public zeros; // Zero hashes for empty subtrees

    mapping(bytes32 => bool) public nullifiers; // Double-spend prevention
    mapping(bytes32 => bool) public commitments; // Track all commitments
    mapping(bytes32 => bool) public validRoots; // Gas-efficient root validation
    mapping(uint256 => bool) public validDenoms; // Gas-efficient denomination check

    address public paymaster;
    address public treasury;
    uint256 public feeBps; // Fee in basis points (0 = 0%, 100 = 1%)

    // Fixed denominations in USDC (6 decimals)
    uint256[4] public DENOMS;

    event Deposit(bytes32 indexed commitment, uint256 amount, uint256 leafIndex);
    event Sponsored(
        bytes32 indexed nullifierHash,
        address indexed merchant,
        uint256 paymentAmount,
        bytes32 changeCommitment,
        uint256 changeAmount
    );
    event RootUpdated(bytes32 newRoot, uint256 index);
    event FeeBpsUpdated(uint256 newFeeBps);

    error InvalidDenomination();
    error CommitmentExists();
    error OnlyPaymaster();
    error NullifierUsed();
    error FeeTooHigh();
    error ZeroAddress();
    error InvalidAmount();

    constructor(address _usdc, address _paymaster, address _treasury) Ownable(msg.sender) {
        if (_usdc == address(0) || _paymaster == address(0) || _treasury == address(0)) {
            revert ZeroAddress();
        }

        usdc = IERC20(_usdc);
        paymaster = _paymaster;
        treasury = _treasury;
        feeBps = 0; // Start with 0% fee (owner sponsors gas)

        // Initialize fixed denominations (0.10, 0.50, 1.00, 5.00 USDC)
        DENOMS[0] = 100000;    // 0.10 USDC
        DENOMS[1] = 500000;    // 0.50 USDC
        DENOMS[2] = 1000000;   // 1.00 USDC
        DENOMS[3] = 5000000;   // 5.00 USDC

        // Initialize denomination mapping for O(1) lookup
        validDenoms[100000] = true;
        validDenoms[500000] = true;
        validDenoms[1000000] = true;
        validDenoms[5000000] = true;

        // Initialize Merkle tree zero hashes
        // zeros[0] = keccak256(abi.encodePacked(bytes32(0)))
        zeros[0] = bytes32(0);
        for (uint256 i = 1; i < TREE_DEPTH; i++) {
            zeros[i] = _hashLeftRight(zeros[i - 1], zeros[i - 1]);
        }

        // Initialize root with empty tree root
        bytes32 initialRoot = zeros[TREE_DEPTH - 1];
        rootHistory[0] = initialRoot;
        validRoots[initialRoot] = true;
    }

    /**
     * @notice Deposit USDC with a commitment (blinded by secret + nullifier)
     * @param commitment Poseidon(secret, nullifier, denomination)
     * @param denomination Must be one of the fixed denominations
     */
    function deposit(bytes32 commitment, uint256 denomination) external nonReentrant {
        if (!_isValidDenom(denomination)) revert InvalidDenomination();
        if (commitments[commitment]) revert CommitmentExists();
        if (denomination == 0) revert InvalidAmount();

        // Transfer USDC from user
        uint256 fee = (denomination * feeBps) / 10000;
        uint256 netAmount = denomination - fee;

        usdc.transferFrom(msg.sender, address(this), netAmount);
        if (fee > 0) {
            usdc.transferFrom(msg.sender, treasury, fee);
        }

        // Add commitment to Merkle tree
        commitments[commitment] = true;

        // Update Merkle tree with new leaf
        bytes32 newRoot = _insert(commitment);

        // Invalidate oldest root if buffer is full
        uint256 oldRootIndex = (currentRootIndex + 1) % 10;
        bytes32 oldRoot = rootHistory[oldRootIndex];
        if (oldRoot != bytes32(0)) {
            validRoots[oldRoot] = false;
        }

        // Store new root in buffer
        currentRootIndex = oldRootIndex;
        rootHistory[currentRootIndex] = newRoot;
        validRoots[newRoot] = true;

        emit Deposit(commitment, denomination, nextLeafIndex);
        emit RootUpdated(newRoot, currentRootIndex);

        nextLeafIndex++;
    }

    /**
     * @notice Sponsor a payment (called by paymaster after ZK proof verification)
     * @param nullifierHash Hash of nullifier (prevents double-spend)
     * @param merchant Recipient address
     * @param paymentAmount Amount being transferred (any value from note balance)
     * @param changeCommitment New commitment for change (if changeAmount > 0)
     * @param changeAmount Remaining balance after payment
     */
    function sponsor(
        bytes32 nullifierHash,
        address merchant,
        uint256 paymentAmount,
        bytes32 changeCommitment,
        uint256 changeAmount
    ) external nonReentrant {
        if (msg.sender != paymaster) revert OnlyPaymaster();
        if (nullifiers[nullifierHash]) revert NullifierUsed();
        if (merchant == address(0)) revert ZeroAddress();
        if (paymentAmount == 0) revert InvalidAmount();

        // Burn nullifier (mark as spent)
        nullifiers[nullifierHash] = true;

        // Add change commitment to Merkle tree (if change > 0)
        if (changeAmount > 0) {
            if (commitments[changeCommitment]) revert CommitmentExists();
            commitments[changeCommitment] = true;

            // Update Merkle tree with change commitment
            bytes32 newRoot = _insert(changeCommitment);

            // Invalidate oldest root if buffer is full
            uint256 oldRootIndex = (currentRootIndex + 1) % 10;
            bytes32 oldRoot = rootHistory[oldRootIndex];
            if (oldRoot != bytes32(0)) {
                validRoots[oldRoot] = false;
            }

            // Store new root in buffer
            currentRootIndex = oldRootIndex;
            rootHistory[currentRootIndex] = newRoot;
            validRoots[newRoot] = true;

            emit RootUpdated(newRoot, currentRootIndex);
            nextLeafIndex++;
        }

        // Transfer USDC to merchant
        usdc.transfer(merchant, paymentAmount);

        emit Sponsored(nullifierHash, merchant, paymentAmount, changeCommitment, changeAmount);
    }

    /**
     * @notice Check if root is valid (O(1) lookup using mapping)
     * @param root Root to check
     * @return isValid True if root is valid
     */
    function isValidRoot(bytes32 root) public view returns (bool isValid) {
        return validRoots[root];
    }

    /**
     * @notice Get current Merkle root
     */
    function getCurrentRoot() external view returns (bytes32) {
        return rootHistory[currentRootIndex];
    }

    // ========== OWNER FUNCTIONS ==========

    /**
     * @notice Set fee in basis points (max 20%)
     */
    function setFeeBps(uint256 _feeBps) external onlyOwner {
        if (_feeBps > 2000) revert FeeTooHigh(); // Max 20%
        feeBps = _feeBps;
        emit FeeBpsUpdated(_feeBps);
    }

    /**
     * @notice Set paymaster address
     */
    function setPaymaster(address _paymaster) external onlyOwner {
        if (_paymaster == address(0)) revert ZeroAddress();
        paymaster = _paymaster;
    }

    /**
     * @notice Set treasury address
     */
    function setTreasury(address _treasury) external onlyOwner {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /**
     * @notice Fund paymaster with ETH for gas (using call for forward compatibility)
     */
    function fundPaymaster() external payable onlyOwner {
        (bool success, ) = paymaster.call{value: msg.value}("");
        require(success, "ETH transfer failed");
    }

    /**
     * @notice Withdraw USDC fees to treasury
     */
    function withdrawTreasury(uint256 amount) external onlyOwner {
        usdc.transfer(treasury, amount);
    }

    /**
     * @notice Emergency withdraw (if needed)
     */
    function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
        IERC20(token).transfer(owner(), amount);
    }

    // ========== INTERNAL ==========

    /**
     * @notice Check if denomination is valid (O(1) lookup using mapping)
     * @param amount Amount to check
     * @return True if valid denomination
     */
    function _isValidDenom(uint256 amount) internal view returns (bool) {
        return validDenoms[amount];
    }

    /**
     * @notice Insert a new leaf into the Merkle tree
     * @param leaf The leaf value to insert
     * @return The new Merkle root after insertion
     */
    function _insert(bytes32 leaf) internal returns (bytes32) {
        uint256 currentIndex = nextLeafIndex;
        bytes32 currentLevelHash = leaf;
        bytes32 left;
        bytes32 right;

        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            if (currentIndex % 2 == 0) {
                // Current node is left child
                left = currentLevelHash;
                right = zeros[i];
                filledSubtrees[i] = currentLevelHash;
            } else {
                // Current node is right child
                left = filledSubtrees[i];
                right = currentLevelHash;
            }

            currentLevelHash = _hashLeftRight(left, right);
            currentIndex = currentIndex / 2;
        }

        return currentLevelHash;
    }

    /**
     * @notice Hash two nodes together using Poseidon (Merkle tree hash function)
     * @param left Left node
     * @param right Right node
     * @return Hash of left and right nodes
     */
    function _hashLeftRight(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        uint[2] memory input;
        input[0] = uint256(left);
        input[1] = uint256(right);
        return bytes32(PoseidonT3.hash(input));
    }
}
