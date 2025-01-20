// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import { BaseScript } from "./BaseScript.s.sol";
import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import { Multicall } from "@openzeppelin/contracts/utils/Multicall.sol";
import { UniFiAVSManager } from "../src/UniFiAVSManager.sol";
import { AVSDeployment } from "./DeploymentStructs.sol";

import { ROLE_ID_DAO } from "./Roles.sol";

contract SetupAccess is BaseScript {
    AccessManager internal accessManager;

    AVSDeployment internal avsDeployment;

    function run(AVSDeployment memory deployment, address dao) external broadcast {
        avsDeployment = deployment;
        accessManager = AccessManager(payable(deployment.accessManager));

        // We do one multicall to setup everything
        bytes[] memory calldatas = _generateAccessCalldata({
            rolesCalldatas: _grantRoles(dao),
            uniFiAVSManagerRoles: _setupUniFiAVSManagerRoles(),
            roleLabels: _labelRoles()
        });

        bytes memory multicallData = abi.encodeCall(Multicall.multicall, (calldatas));
        // console.logBytes(multicallData);
        (bool s,) = address(accessManager).call(multicallData);
        require(s, "failed setupAccess 1");
    }

    function _generateAccessCalldata(
        bytes[] memory rolesCalldatas,
        bytes[] memory uniFiAVSManagerRoles,
        bytes[] memory roleLabels
    ) internal view returns (bytes[] memory calldatas) {
        calldatas = new bytes[](4);
        calldatas[0] = rolesCalldatas[0];

        calldatas[1] = uniFiAVSManagerRoles[0];
        calldatas[2] = uniFiAVSManagerRoles[1];

        calldatas[3] = roleLabels[0];
    }

    function _grantRoles(address dao) internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](1);

        calldatas[0] = abi.encodeWithSelector(AccessManager.grantRole.selector, ROLE_ID_DAO, dao, 0);

        return calldatas;
    }

    function _labelRoles() internal pure returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](1);

        calldatas[0] = abi.encodeWithSelector(AccessManager.labelRole.selector, ROLE_ID_DAO, "UniFi DAO");

        return calldatas;
    }

    function _setupUniFiAVSManagerRoles() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](2);

        bytes4[] memory daoSelectors = new bytes4[](0);
        daoSelectors = new bytes4[](4);
        daoSelectors[0] = UniFiAVSManager.setDeregistrationDelay.selector;
        daoSelectors[1] = UniFiAVSManager.setChainID.selector;
        daoSelectors[2] = UniFiAVSManager.updateAVSMetadataURI.selector;
        daoSelectors[3] = UniFiAVSManager.setAllowlistRestakingStrategy.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(avsDeployment.avsManagerProxy),
            daoSelectors,
            ROLE_ID_DAO
        );

        bytes4[] memory publicSelectors = new bytes4[](0);
        publicSelectors = new bytes4[](8);
        publicSelectors[0] = UniFiAVSManager.registerOperator.selector;
        publicSelectors[1] = UniFiAVSManager.registerValidators.selector;
        publicSelectors[2] = UniFiAVSManager.startDeregisterOperator.selector;
        publicSelectors[3] = UniFiAVSManager.finishDeregisterOperator.selector;
        publicSelectors[4] = UniFiAVSManager.deregisterValidators.selector;
        publicSelectors[5] = UniFiAVSManager.setOperatorCommitment.selector;
        publicSelectors[6] = UniFiAVSManager.updateOperatorCommitment.selector;
        publicSelectors[7] = UniFiAVSManager.registerOperatorWithCommitment.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(avsDeployment.avsManagerProxy),
            publicSelectors,
            accessManager.PUBLIC_ROLE()
        );

        return calldatas;
    }
}
