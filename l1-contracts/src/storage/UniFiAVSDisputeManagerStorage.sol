// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "../structs/ValidatorData.sol";

/**
 * @title UniFiAVSDisputeManagerStorage
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
abstract contract UniFiAVSDisputeManagerStorage {
    /**
     * @dev +-----------------------------------------------------------+
     *      |                                                           |
     *      | DO NOT CHANGE, REORDER, REMOVE EXISTING STORAGE VARIABLES |
     *      |                                                           |
     *      +-----------------------------------------------------------+
     */
    struct UniFiAVSDisputeStorage {
        // Slashed operators mapping
        mapping(address operator => InvalidValidator[] slashedValidators) slashedOperators;
    }

    /**
     * @dev Storage slot location for UniFiAVSDisputeManager
     * @custom:storage-location erc7201:UniFiAVSDisputeManager.storage
     */
    bytes32 private constant _STORAGE_LOCATION = 0x5637C918091F80BAF4C11B7735D9493160412E6224AE5AFB3BEEAD3699789342;

    function _getUniFiAVSDisputeStorage() internal pure returns (UniFiAVSDisputeStorage storage $) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := _STORAGE_LOCATION
        }
    }
}
