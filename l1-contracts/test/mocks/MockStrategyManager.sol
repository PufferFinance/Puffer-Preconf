// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

contract MockStrategyManager {
    function strategyIsWhitelistedForDeposit(address strategy) public view returns (bool) {
        return true;
    }
}

