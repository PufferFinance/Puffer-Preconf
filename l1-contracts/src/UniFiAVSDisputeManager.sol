pragma solidity >=0.8.0 <0.9.0;

import "./storage/UniFiAVSDisputeManagerStorage.sol";
import "./structs/ValidatorData.sol";
import { AccessManagedUpgradeable } from
    "@openzeppelin/contracts-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { IUniFiAVSDisputeManager } from "./interfaces/IUniFiAVSDisputeManager.sol";
/**
 * @title UniFiAVSDisputeManager
 * @dev Manages disputes and slashing of operators.
 */

contract UniFiAVSDisputeManager is IUniFiAVSDisputeManager, UniFiAVSDisputeManagerStorage, AccessManagedUpgradeable {
    constructor() {
        _disableInitializers();
    }

    function initialize(address accessManager) external initializer {
        __AccessManaged_init(accessManager);
    }

    /**
     * @inheritdoc IUniFiAVSDisputeManager
     * @dev restricted to the UniFiAVSManager
     */
    function slashOperator(address operator, bytes32[] calldata validators, address slashingBeneficiary)
        external
        restricted
    {
        UniFiAVSDisputeStorage storage $ = _getUniFiAVSDisputeStorage();

        for (uint256 i = 0; i < validators.length; i++) {
            $.slashedOperators[operator].push(
                InvalidValidator({ slashingBeneficiary: slashingBeneficiary, blsPubKeyHash: validators[i] })
            );
        }

        emit OperatorSlashed(operator, validators, slashingBeneficiary);
    }

    /**
     * @inheritdoc IUniFiAVSDisputeManager
     */
    function isOperatorSlashed(address operator) external view returns (bool) {
        UniFiAVSDisputeStorage storage $ = _getUniFiAVSDisputeStorage();
        return $.slashedOperators[operator].length > 0;
    }
}
