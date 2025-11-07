// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title PrivacyWallet
 * @notice Shared privacy-preserving wallet for anonymous payments
 * @dev All users submit UserOps through this single wallet address
 *      Validation happens in ZKPaymaster, this wallet accepts all ops
 *      Privacy maintained because everyone uses same sender address
 */
contract PrivacyWallet is IAccount {
    using ECDSA for bytes32;

    IEntryPoint public immutable entryPoint;
    address public immutable pool;
    address public immutable paymaster;

    event PrivacyPaymentExecuted(address indexed recipient, uint256 amount);

    error OnlyEntryPoint();
    error OnlyPaymaster();

    constructor(IEntryPoint _entryPoint, address _pool, address _paymaster) {
        entryPoint = _entryPoint;
        pool = _pool;
        paymaster = _paymaster;
    }

    /**
     * @notice Validate user operation
     * @dev This wallet accepts any UserOp because validation happens in paymaster
     *      The paymaster validates the ZK proof, not this wallet
     * @param userOp The user operation
     * @param userOpHash Hash of the user operation
     * @param missingAccountFunds Funds needed to pay for this operation
     * @return validationData 0 for success (always succeeds, real validation in paymaster)
     */
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override returns (uint256 validationData) {
        if (msg.sender != address(entryPoint)) revert OnlyEntryPoint();

        // Pay the entry point if needed
        if (missingAccountFunds > 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds}("");
            require(success, "Payment to EntryPoint failed");
        }

        // Always return success - real validation happens in ZKPaymaster
        return 0;
    }

    /**
     * @notice Execute calls from EntryPoint
     * @dev Only EntryPoint can call this
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        if (msg.sender != address(entryPoint)) revert OnlyEntryPoint();

        (bool success, bytes memory result) = dest.call{value: value}(func);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * @notice Allow wallet to receive ETH
     */
    receive() external payable {}

    /**
     * @notice Fund this wallet with ETH for EntryPoint deposits
     */
    function deposit() external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
    }

    /**
     * @notice Withdraw ETH from EntryPoint
     */
    function withdrawFromEntryPoint(address payable recipient, uint256 amount) external {
        if (msg.sender != paymaster) revert OnlyPaymaster();
        entryPoint.withdrawTo(recipient, amount);
    }

    /**
     * @notice Get deposit in EntryPoint
     */
    function getDeposit() external view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }
}
