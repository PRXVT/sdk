// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@account-abstraction/contracts/core/BasePaymaster.sol";
import "./MerklePool.sol";

/**
 * @title ZKPaymaster
 * @notice ERC-4337 paymaster that verifies ZK proofs for private X402 payments
 * @dev Sponsors gas for UserOps with valid ZK proofs from MerklePool commitments
 */
contract ZKPaymaster is BasePaymaster {
    MerklePool public immutable pool;
    address public verifier; // Groth16 verifier contract

    event PaymentSponsored(address indexed merchant, uint256 amount, bytes32 nullifierHash);
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    error InvalidProofData();
    error InvalidProof();
    error InvalidRoot();
    error ZeroAddress();

    constructor(
        IEntryPoint _entryPoint,
        address _verifier,
        MerklePool _pool
    ) BasePaymaster(_entryPoint) Ownable(msg.sender) {
        if (_verifier == address(0) || address(_pool) == address(0)) {
            revert ZeroAddress();
        }
        verifier = _verifier;
        pool = _pool;
    }

    /**
     * @notice Validate paymaster user operation with ZK proof
     * @dev Decodes proof from paymasterAndData, verifies it, calls pool.sponsor()
     * @param userOp The user operation
     * @param userOpHash Hash of the user operation
     * @param maxCost Maximum cost of this operation (gas * maxFeePerGas)
     * @return context Data to pass to postOp (empty for now)
     * @return validationData 0 if valid, SIG_VALIDATION_FAILED otherwise
     */
    function _validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) internal override returns (bytes memory context, uint256 validationData) {
        // Decode paymasterAndData
        // Format: address(paymaster) + abi.encode(ProofData)
        // where ProofData = (proof, publicSignals, merchant, paymentAmount, changeCommitment, changeAmount)

        // DO NOT REVERT - return validation failure instead (ERC-4337 spec)
        if (userOp.paymasterAndData.length < 20) {
            return ("", 1); // SIG_VALIDATION_FAILED
        }

        // Extract data after paymaster address (first 20 bytes)
        bytes memory paymasterData = userOp.paymasterAndData[20:];

        (
            uint256[8] memory proof,
            uint256[5] memory publicSignals, // [changeCommitment, nullifierHash, root, paymentAmount, changeAmount] (circom order: outputs then public inputs)
            address merchant,
            uint256 paymentAmount,
            bytes32 changeCommitment,
            uint256 changeAmount
        ) = abi.decode(paymasterData, (uint256[8], uint256[5], address, uint256, bytes32, uint256));

        // Validate merchant address
        if (merchant == address(0)) {
            return ("", 1); // SIG_VALIDATION_FAILED
        }

        // Validate payment amount
        if (paymentAmount == 0) {
            return ("", 1); // SIG_VALIDATION_FAILED
        }

        // Extract values from public signals (circom order: outputs first, then public inputs)
        bytes32 proofChangeCommitment = bytes32(publicSignals[0]);
        bytes32 proofNullifierHash = bytes32(publicSignals[1]);
        bytes32 root = bytes32(publicSignals[2]);
        // publicSignals[3] = paymentAmount
        // publicSignals[4] = changeAmount

        // Verify root is in buffer FIRST (cheaper check)
        // DO NOT REVERT - return validation failure (ERC-4337 spec)
        if (!pool.isValidRoot(root)) {
            return ("", 1); // SIG_VALIDATION_FAILED
        }

        // Verify ZK proof (Groth16) - this proves all the math is correct
        // DO NOT REVERT - return validation failure (ERC-4337 spec)
        bool proofValid = _verifyGroth16Proof(proof, publicSignals);
        if (!proofValid) {
            return ("", 1); // SIG_VALIDATION_FAILED
        }

        // Use values from proof (they're guaranteed correct by ZK proof)
        // Call pool to sponsor (burns nullifier, adds change commitment, transfers USDC)
        pool.sponsor(
            proofNullifierHash,
            merchant,
            paymentAmount,  // From function params (verified by proof)
            proofChangeCommitment,  // From proof outputs
            changeAmount  // From function params (verified by proof)
        );

        emit PaymentSponsored(merchant, paymentAmount, proofNullifierHash);

        // Return empty context, validation success (0)
        return ("", 0);
    }

    /**
     * @notice Verify Groth16 proof
     * @dev Calls external verifier contract (generated from snarkjs)
     * @param proof Proof components [8]
     * @param publicSignals Public inputs [5]
     * @return valid True if proof is valid
     */
    function _verifyGroth16Proof(
        uint256[8] memory proof,
        uint256[5] memory publicSignals
    ) internal view returns (bool valid) {
        // Convert proof from uint256[8] to (a, b, c) format
        // proof[0..1] = a, proof[2..5] = b (2x2), proof[6..7] = c
        uint256[2] memory a = [proof[0], proof[1]];
        uint256[2][2] memory b = [[proof[2], proof[3]], [proof[4], proof[5]]];
        uint256[2] memory c = [proof[6], proof[7]];

        // Call verifier contract with correct format
        // Verifier interface: function verifyProof(uint[2] a, uint[2][2] b, uint[2] c, uint[5] input) returns (bool)
        (bool success, bytes memory result) = verifier.staticcall(
            abi.encodeWithSignature(
                "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[5])",
                a,
                b,
                c,
                publicSignals
            )
        );

        if (!success) return false;
        return abi.decode(result, (bool));
    }

    /**
     * @notice Post-operation handler (unused for now)
     */
    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost)
        internal
        override
    {
        // No post-op logic needed for USDC sponsorship
    }

    // ========== OWNER FUNCTIONS ==========

    /**
     * @notice Update verifier contract
     */
    function setVerifier(address _verifier) external onlyOwner {
        if (_verifier == address(0)) revert ZeroAddress();
        address oldVerifier = verifier;
        verifier = _verifier;
        emit VerifierUpdated(oldVerifier, _verifier);
    }

    /**
     * @notice Receive ETH for gas sponsorship
     */
    receive() external payable {}
}
