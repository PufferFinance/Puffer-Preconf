// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @notice AVSDeployment
 */
struct AVSDeployment {
    address avsManagerImplementation;
    address avsManagerProxy;
    address accessManager;
    address timelock;
    address dao;
    address operationsMultisig;
}
