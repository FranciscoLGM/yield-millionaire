// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title MockTokenConverter
 * @notice Mock contract for token conversion and burning
 */
contract MockTokenConverter {
    IERC20 public sourceToken;
    IERC20 public targetToken;

    event TokensConverted(
        address indexed user,
        uint256 sourceAmount,
        uint256 targetAmount
    );

    constructor(address _sourceToken, address _targetToken) {
        sourceToken = IERC20(_sourceToken);
        targetToken = IERC20(_targetToken);
    }

    /**
     * @notice Convert and burn tokens (1:1 mock conversion)
     */
    function convertAndBurn(
        uint256 amount,
        address user
    ) external returns (uint256) {
        uint256 convertedAmount = amount;

        require(targetToken.transfer(user, convertedAmount), "Transfer failed");

        emit TokensConverted(user, amount, convertedAmount);
        return convertedAmount;
    }
}
