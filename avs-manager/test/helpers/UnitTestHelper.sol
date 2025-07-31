// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { BaseScript } from "../../script/BaseScript.s.sol";
import { DeployEverything } from "../../script/DeployEverything.s.sol";
import { AVSDeployment } from "../../script/DeploymentStructs.sol";
import { UniFiAVSManager } from "../../src/UniFiAVSManager.sol";
import { EigenPodManagerMock } from "../mocks/EigenPodManagerMock.sol";
import { MockDelegationManager } from "../mocks/MockDelegationManager.sol";
import { MockAllocationManager } from "../mocks/MockAllocationManager.sol";
import { MockStrategyManager } from "../mocks/MockStrategyManager.sol";
import { MockRewardsCoordinator } from "../mocks/MockRewardsCoordinator.sol";
import { MockERC20 } from "../mocks/MockERC20.sol";
import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";

contract UnitTestHelper is Test, BaseScript {
    address public constant ADDRESS_ZERO = address(0);
    address public constant ADDRESS_ONE = address(1);
    address public constant ADDRESS_CHEATS = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;

    // Addresses that are supposed to be skipped when fuzzing
    mapping(address fuzzedAddress => bool isFuzzed) internal fuzzedAddressMapping;

    AccessManager public accessManager;
    address public timelock;

    UniFiAVSManager public avsManager;
    EigenPodManagerMock public mockEigenPodManager;
    MockDelegationManager public mockDelegationManager;
    MockAllocationManager public mockAllocationManager;
    MockStrategyManager public mockStrategyManager;
    MockRewardsCoordinator public mockRewardsCoordinator;
    MockERC20 public mockERC20;
    address public DAO = makeAddr("DAO");
    address public COMMUNITY_MULTISIG = makeAddr("communityMultisig");
    address public OPERATIONS_MULTISIG = address(0x031337);

    uint256 public operatorPrivateKey = 0xA11CE;
    address public operator = vm.addr(operatorPrivateKey);
    address public podOwner = makeAddr("podOwner");

    uint64 public constant DEREGISTRATION_DELAY = 65;

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
        mockEigenPodManager = new EigenPodManagerMock();
        mockDelegationManager = new MockDelegationManager();
        mockAllocationManager = new MockAllocationManager();
        mockStrategyManager = new MockStrategyManager();
        mockRewardsCoordinator = new MockRewardsCoordinator(IStrategyManager(address(mockStrategyManager)));
        
        // Set up the AVS registrar in the AllocationManager
        mockAllocationManager.setAVSRegistrar(address(0), address(0)); // Will be set to the AVS contract later
        
        AVSDeployment memory avsDeployment = new DeployEverything().run({
            eigenPodManager: address(mockEigenPodManager),
            eigenDelegationManager: address(mockDelegationManager),
            allocationManager: address(mockAllocationManager),
            rewardsCoordinator: address(mockRewardsCoordinator),
            initialDeregistrationDelay: DEREGISTRATION_DELAY
        });

        mockERC20 = new MockERC20("MockERC20", "MKR", 1000);

        // accessManager = AccessManager(avsDeployment.accessManager);
        timelock = avsDeployment.timelock;
        avsManager = UniFiAVSManager(avsDeployment.avsManagerProxy);
        
        // Set the AVS as its own registrar in the AllocationManager
        mockAllocationManager.setAVSRegistrar(address(avsManager), address(avsManager));
    }
}
