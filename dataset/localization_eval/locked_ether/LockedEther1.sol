// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Locked Ether Example 1
 * Funds can be deposited but cannot be withdrawn (missing withdraw function)
 */
contract LockedEther1 {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // BUG: No withdraw function -> Ether becomes permanently locked
}
