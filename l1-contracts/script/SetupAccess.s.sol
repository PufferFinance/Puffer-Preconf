// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import { console } from "forge-std/console.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import { Multicall } from "@openzeppelin/contracts/utils/Multicall.sol";
import { UniFiAVSManager } from "../src/UniFiAVSManager.sol";
import { AVSDeployment } from "script/DeploymentStructs.sol";
import { UniFiAVSDisputeManager } from "../src/UniFiAVSDisputeManager.sol";
import {
    ROLE_ID_OPERATIONS_MULTISIG,
    ROLE_ID_OPERATIONS_PAYMASTER,
    ROLE_ID_PUFFER_PROTOCOL,
    ROLE_ID_DAO,
    ROLE_ID_OPERATIONS_COORDINATOR,
    ROLE_ID_VT_PRICER,
    ROLE_ID_UNIFI_AVS_MANAGER
} from "../script/Roles.sol";

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
            uniFiAVSDisputeManagerRoles: _setupUniFiAVSDisputeManagerRoles(),
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
        bytes[] memory uniFiAVSDisputeManagerRoles,
        bytes[] memory roleLabels
    ) internal view returns (bytes[] memory calldatas) {
        calldatas = new bytes[](6);
        calldatas[0] = rolesCalldatas[0];
        calldatas[1] = rolesCalldatas[1];

        calldatas[2] = uniFiAVSManagerRoles[0];
        calldatas[3] = uniFiAVSManagerRoles[1];
        calldatas[4] = uniFiAVSDisputeManagerRoles[0];
        calldatas[5] = roleLabels[0];
    }

    function _grantRoles(address dao) internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](2);

        calldatas[0] = abi.encodeWithSelector(AccessManager.grantRole.selector, ROLE_ID_DAO, dao, 0);
        calldatas[1] = abi.encodeWithSelector(
            AccessManager.grantRole.selector, ROLE_ID_UNIFI_AVS_MANAGER, avsDeployment.avsManagerProxy, 0
        );

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
        publicSelectors = new bytes4[](12);
        publicSelectors[0] = UniFiAVSManager.registerOperator.selector;
        publicSelectors[1] = UniFiAVSManager.registerValidators.selector;
        publicSelectors[2] = UniFiAVSManager.startDeregisterOperator.selector;
        publicSelectors[3] = UniFiAVSManager.finishDeregisterOperator.selector;
        publicSelectors[4] = UniFiAVSManager.deregisterValidators.selector;
        publicSelectors[5] = UniFiAVSManager.setOperatorCommitment.selector;
        publicSelectors[6] = UniFiAVSManager.updateOperatorCommitment.selector;
        publicSelectors[7] = UniFiAVSManager.registerOperatorWithCommitment.selector;
        publicSelectors[8] = UniFiAVSManager.registerValidatorsOptimistically.selector;
        publicSelectors[9] = UniFiAVSManager.verifyValidatorSignatures.selector;
        publicSelectors[10] = UniFiAVSManager.slashValidatorsWithInvalidPubkey.selector;
        publicSelectors[11] = UniFiAVSManager.slashValidatorsWithInvalidIndex.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(avsDeployment.avsManagerProxy),
            publicSelectors,
            accessManager.PUBLIC_ROLE()
        );

        return calldatas;
    }

    function _setupUniFiAVSDisputeManagerRoles() internal view returns (bytes[] memory) {
        bytes[] memory calldatas = new bytes[](1);

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = UniFiAVSDisputeManager.slashOperator.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(avsDeployment.disputeManagerProxy),
            selectors,
            ROLE_ID_UNIFI_AVS_MANAGER
        );

        return calldatas;
    }
}
