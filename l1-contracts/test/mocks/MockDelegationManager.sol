// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";

contract MockDelegationManager {
    mapping(address operator => bool isOperator) public operators;
    mapping(address podOwner => address delegatee) public delegations;
    mapping(address operator => mapping(IStrategy strategy => uint256 amount)) public operatorShares;

    function isOperator(address operator) external view returns (bool) {
        return operators[operator];
    }

    function delegatedTo(address podOwner) external view returns (address) {
        return delegations[podOwner];
    }

    // Mock function to set an operator for testing
    function setOperator(address operator, bool isActive) external {
        operators[operator] = isActive;
    }

    // Mock function to set a delegation for testing
    function setDelegation(address podOwner, address delegatee) external {
        delegations[podOwner] = delegatee;
    }

    function setShares(address operator, IStrategy strategy, uint256 amount) external {
        operatorShares[operator][strategy] = amount;
    }

    function getOperatorShares(address operator, IStrategy[] memory strategies)
        public
        view
        returns (uint256[] memory)
    {
        uint256[] memory shares = new uint256[](strategies.length);
        for (uint256 i = 0; i < strategies.length; i++) {
            shares[i] = operatorShares[operator][strategies[i]];
        }
        return shares;
    }

    // Implement other functions from IDelegationManager as needed for testing
}
