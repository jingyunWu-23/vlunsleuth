// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Locked Ether Example 2
 * Contract can receive ETH but has no mechanism to release it
 */
contract LockedEther2 {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}
    fallback() external payable {}

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "not owner");
        owner = newOwner;
    }

    // BUG: Contract balance cannot be withdrawn
}
