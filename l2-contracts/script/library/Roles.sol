// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title Roles Library
 * @author Puffer Finance
 * @notice Centralized role definitions for the UniFi Rewards Distributor system
 */
library Roles {
    /// @notice Role ID for addresses that can post new Merkle roots
    uint64 internal constant MERKLE_ROOT_POSTER_ROLE = 1;
    
    /// @notice Role ID for addresses that can cancel pending Merkle roots
    uint64 internal constant MERKLE_ROOT_CANCELLER_ROLE = 2;
    
    /// @notice Role ID for addresses that can rescue funds from the contract
    uint64 internal constant FUNDS_RESCUER_ROLE = 3;
} 