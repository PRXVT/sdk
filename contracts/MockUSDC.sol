// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MockUSDC
 * @notice Mock USDC token for testing on Base Sepolia
 * @dev Mintable ERC20 with 6 decimals (matching real USDC)
 */
contract MockUSDC is ERC20, Ownable {
    uint8 private constant DECIMALS = 6;

    constructor() ERC20("Mock USDC", "USDC") Ownable(msg.sender) {
        // Mint 1M USDC to deployer for testing
        _mint(msg.sender, 1_000_000 * 10 ** DECIMALS);
    }

    function decimals() public pure override returns (uint8) {
        return DECIMALS;
    }

    /// @notice Mint USDC to any address (for testing - anyone can mint)
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    /// @notice Faucet function for public testing (anyone can mint small amounts)
    function faucet() external {
        _mint(msg.sender, 100 * 10 ** DECIMALS); // Mint 100 USDC
    }
}
