// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { IUniFiAVSManager } from "./interfaces/IUniFiAVSManager.sol";
import { DeprecatedOperatorData } from "./structs/DeprecatedOperatorData.sol";

/**
 * @title UniFiAVSManagerStorage
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
abstract contract UniFiAVSManagerStorage is IUniFiAVSManager {
    struct UniFiAVSStorage {
        mapping(bytes32 => ValidatorData) _deprecated_validators;
        mapping(uint256 => bytes32) _deprecated_validatorIndexes;
        mapping(address => DeprecatedOperatorData) _deprecated_operators;
        uint64 deregistrationDelay;
        mapping(uint8 => uint256) _deprecated_bitmapIndexToChainId;
        mapping(uint256 => uint8) _deprecated_chainIdToBitmapIndex;
        EnumerableSet.AddressSet allowlistedRestakingStrategies;
        mapping(bytes validatorPubkey => ValidatorData validatorData) validators;
        mapping(uint256 validatorIndex => bytes validatorPubkey) validatorIndexes;
        mapping(address operator => OperatorData operatorData) operators;
    }

    /**
     * @dev Storage slot location for UniFiAVSManager
     * @custom:storage-location erc7201:UniFiAVSManager.storage
     */
    bytes32 private constant _STORAGE_LOCATION = 0xfee41a6d2b86b757dd00cd2166d8727686a349977cbc2b6b6a2ca1c3e7215000;

    function _getUniFiAVSManagerStorage() internal pure returns (UniFiAVSStorage storage $) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := _STORAGE_LOCATION
        }
    }
}
