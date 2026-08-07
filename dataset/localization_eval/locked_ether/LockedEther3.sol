// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Locked Ether Example 3
 * Logical accounting bug leads to unrecoverable funds
 */
contract LockedEther3 {
    mapping(address => uint256) public credit;

    function deposit(address user) external payable {
        // BUG: assigns funds incorrectly
        credit[address(this)] += msg.value;
    }

    function claim() external {
        uint256 amount = credit[msg.sender];
        require(amount > 0, "no funds");

        credit[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}
