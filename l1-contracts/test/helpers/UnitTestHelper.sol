// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import { BaseScript } from "../../script/BaseScript.s.sol";
import { DeployEverything } from "../../script/DeployEverything.s.sol";
import { AVSDeployment } from "../../script/DeploymentStructs.sol";
import "../../src/UniFiAVSManager.sol";
import "../mocks/MockEigenPodManager.sol";
import "../mocks/MockDelegationManager.sol";
import "../mocks/MockAVSDirectory.sol";
import { UpgradeableBeacon } from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import "forge-std/console.sol";

contract UnitTestHelper is Test, BaseScript {
    address public constant ADDRESS_ZERO = address(0);
    address public constant ADDRESS_ONE = address(1);
    address public constant ADDRESS_CHEATS = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;

    // Addresses that are supposed to be skipped when fuzzing
    mapping(address fuzzedAddress => bool isFuzzed) internal fuzzedAddressMapping;

    AccessManager public accessManager;
    address public timelock;

    UniFiAVSManager public avsManager;
    MockEigenPodManager public mockEigenPodManager;
    MockDelegationManager public mockDelegationManager;
    MockAVSDirectory public mockAVSDirectory;

    address public DAO = makeAddr("DAO");
    address public COMMUNITY_MULTISIG = makeAddr("communityMultisig");
    address public OPERATIONS_MULTISIG = makeAddr("operationsMultisig");

    uint256 public operatorPrivateKey = 0xA11CE;
    address public operator = vm.addr(operatorPrivateKey);
    address public podOwner = makeAddr("podOwner");

    modifier fuzzedAddress(address addr) virtual {
        vm.assume(fuzzedAddressMapping[addr] == false);
        _;
    }

    modifier assumeEOA(address addr) {
        assumePayable(addr);
        assumeNotPrecompile(addr);
        vm.assume(addr.code.length == 0);
        vm.assume(addr != ADDRESS_ZERO);
        vm.assume(addr != ADDRESS_ONE);
        vm.assume(addr != 0x000000000000000000636F6e736F6c652e6c6f67); // console address
        _;
    }

    function setUp() public virtual {
        _deployContracts();
        _skipDefaultFuzzAddresses();
    }

    function _skipDefaultFuzzAddresses() internal {
        fuzzedAddressMapping[ADDRESS_CHEATS] = true;
        fuzzedAddressMapping[ADDRESS_ZERO] = true;
        fuzzedAddressMapping[ADDRESS_ONE] = true;
        fuzzedAddressMapping[address(accessManager)] = true;
        fuzzedAddressMapping[address(avsManager)] = true;
    }

    function _deployContracts() public {
        // Deploy everything with one script
        mockEigenPodManager = new MockEigenPodManager();
        mockDelegationManager = new MockDelegationManager();
        mockAVSDirectory = new MockAVSDirectory();

        accessManager = new AccessManager(DAO);

        AVSDeployment memory avsDeployment = new DeployEverything().run(
            address(accessManager),
            address(mockEigenPodManager),
            address(mockDelegationManager),
            address(mockAVSDirectory)
        );

        // accessManager = AccessManager(avsDeployment.accessManager);
        timelock = avsDeployment.timelock;
        avsManager = UniFiAVSManager(avsDeployment.avsManagerProxy);
    }
}
