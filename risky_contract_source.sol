// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SuspiciousToken {
    address public owner;
    mapping(address => bool) public blacklisted;
    uint256 public feePercent = 2;
    bool public paused;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function mint(address to, uint256 amount) public onlyOwner {
        // mint logic omitted
    }

    function blacklistAddress(address user) public onlyOwner {
        blacklisted[user] = true;
    }

    function setFee(uint256 newFee) public onlyOwner {
        feePercent = newFee;
    }

    function pause() public onlyOwner {
        paused = true;
    }

    function withdrawAll() public onlyOwner {
        selfdestruct(payable(owner));
    }

    function forward(address target, bytes calldata data) public onlyOwner {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "forward failed");
    }

    function transfer(address to, uint256 amount) public {
        require(!blacklisted[msg.sender], "blacklisted");
        // transfer logic omitted
    }
}
