// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IRewardsCoordinator } from "eigenlayer/interfaces/IRewardsCoordinator.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MockRewardsCoordinator {
    using SafeERC20 for IERC20;

    IStrategy public constant beaconChainETHStrategy = IStrategy(0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0);

    /// @notice The maximum rewards token amount for a single rewards submission, constrained by off-chain calculation
    uint256 internal constant MAX_REWARDS_AMOUNT = 1e38 - 1;

    /// @notice The maximum rewards duration for a single rewards submission, constrained by off-chain calculation
    uint256 internal constant MAX_REWARDS_DURATION = 6048000;

    /// @notice The interval at which rewards are calculated, constrained by off-chain calculation
    uint256 internal constant CALCULATION_INTERVAL_SECONDS = 604800; // 2 weeks

    /// @notice The maximum length of time in the past that rewards can be retroactively submitted, constrained by off-chain calculation
    uint256 internal constant MAX_RETROACTIVE_LENGTH = 7776000;

    /// @notice The genesis timestamp for rewards, constrained by off-chain calculation
    uint256 internal constant GENESIS_REWARDS_TIMESTAMP = 1710979200;

    /// @notice Used for unique rewardsSubmissionHashes per AVS and for RewardsForAllSubmitters and the tokenHopper
    mapping(address avs => uint256 nonce) public submissionNonce;

    /// @notice Mapping: avs => operatorDirectedAVSRewardsSubmissionHash => bool to check if operator-directed rewards submission hash has been submitted
    mapping(address avs => mapping(bytes32 operatorDirectedAVSRewardsSubmissionHash => bool)) public
        isOperatorDirectedAVSRewardsSubmissionHash;

    /// @notice The StrategyManager contract for EigenLayer
    IStrategyManager public immutable strategyManager;

    constructor(IStrategyManager _strategyManager) {
        strategyManager = _strategyManager;
    }

    function createOperatorDirectedAVSRewardsSubmission(
        address avs,
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata operatorDirectedRewardsSubmissions
    ) external {
        require(
            msg.sender == avs, "RewardsCoordinator.createOperatorDirectedAVSRewardsSubmission: caller is not the AVS"
        );

        for (uint256 i = 0; i < operatorDirectedRewardsSubmissions.length; i++) {
            IRewardsCoordinator.OperatorDirectedRewardsSubmission calldata operatorDirectedRewardsSubmission =
                operatorDirectedRewardsSubmissions[i];
            uint256 nonce = submissionNonce[avs];
            bytes32 operatorDirectedRewardsSubmissionHash =
                keccak256(abi.encode(avs, nonce, operatorDirectedRewardsSubmission));

            uint256 totalAmount = _validateOperatorDirectedRewardsSubmission(operatorDirectedRewardsSubmission);

            isOperatorDirectedAVSRewardsSubmissionHash[avs][operatorDirectedRewardsSubmissionHash] = true;
            submissionNonce[avs] = nonce + 1;

            emit IRewardsCoordinator.OperatorDirectedAVSRewardsSubmissionCreated({
                caller: msg.sender,
                avs: avs,
                operatorDirectedRewardsSubmissionHash: operatorDirectedRewardsSubmissionHash,
                submissionNonce: nonce,
                operatorDirectedRewardsSubmission: operatorDirectedRewardsSubmission
            });
            operatorDirectedRewardsSubmission.token.safeTransferFrom(msg.sender, address(this), totalAmount);
        }
    }

    /**
     * @notice Validate a OperatorDirectedRewardsSubmission. Called from `createOperatorDirectedAVSRewardsSubmission`.
     * @dev Not checking for `MAX_FUTURE_LENGTH` (Since operator-directed reward submissions are strictly retroactive).
     * @param operatorDirectedRewardsSubmission OperatorDirectedRewardsSubmission to validate.
     * @return total amount to be transferred from the avs to the contract.
     */
    function _validateOperatorDirectedRewardsSubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission calldata operatorDirectedRewardsSubmission
    ) internal view returns (uint256) {
        _validateCommonRewardsSubmission(
            operatorDirectedRewardsSubmission.strategiesAndMultipliers,
            operatorDirectedRewardsSubmission.startTimestamp,
            operatorDirectedRewardsSubmission.duration
        );

        require(
            operatorDirectedRewardsSubmission.operatorRewards.length > 0,
            "RewardsCoordinator._validateOperatorDirectedRewardsSubmission: no operators rewarded"
        );
        uint256 totalAmount = 0;
        address currOperatorAddress = address(0);
        for (uint256 i = 0; i < operatorDirectedRewardsSubmission.operatorRewards.length; ++i) {
            IRewardsCoordinator.OperatorReward calldata operatorReward =
                operatorDirectedRewardsSubmission.operatorRewards[i];
            require(
                operatorReward.operator != address(0),
                "RewardsCoordinator._validateOperatorDirectedRewardsSubmission: operator cannot be 0 address"
            );
            require(
                currOperatorAddress < operatorReward.operator,
                "RewardsCoordinator._validateOperatorDirectedRewardsSubmission: operators must be in ascending order to handle duplicates"
            );
            currOperatorAddress = operatorReward.operator;
            require(
                operatorReward.amount > 0,
                "RewardsCoordinator._validateOperatorDirectedRewardsSubmission: operator reward amount cannot be 0"
            );
            totalAmount += operatorReward.amount;
        }
        require(
            totalAmount <= MAX_REWARDS_AMOUNT,
            "RewardsCoordinator._validateOperatorDirectedRewardsSubmission: total amount too large"
        );

        require(
            operatorDirectedRewardsSubmission.startTimestamp + operatorDirectedRewardsSubmission.duration
                < block.timestamp,
            "RewardsCoordinator._validateOperatorDirectedRewardsSubmission: operator-directed rewards submission is not retroactive"
        );

        return totalAmount;
    }

    /**
     * @notice Common checks for all RewardsSubmissions.
     */
    function _validateCommonRewardsSubmission(
        IRewardsCoordinator.StrategyAndMultiplier[] calldata strategiesAndMultipliers,
        uint32 startTimestamp,
        uint32 duration
    ) internal view {
        require(
            strategiesAndMultipliers.length > 0,
            "RewardsCoordinator._validateCommonRewardsSubmission: no strategies set"
        );
        require(
            duration <= MAX_REWARDS_DURATION,
            "RewardsCoordinator._validateCommonRewardsSubmission: duration exceeds MAX_REWARDS_DURATION"
        );
        require(
            duration % CALCULATION_INTERVAL_SECONDS == 0,
            "RewardsCoordinator._validateCommonRewardsSubmission: duration must be a multiple of CALCULATION_INTERVAL_SECONDS"
        );
        require(
            startTimestamp % CALCULATION_INTERVAL_SECONDS == 0,
            "RewardsCoordinator._validateCommonRewardsSubmission: startTimestamp must be a multiple of CALCULATION_INTERVAL_SECONDS"
        );
        require(
            block.timestamp - MAX_RETROACTIVE_LENGTH <= startTimestamp && GENESIS_REWARDS_TIMESTAMP <= startTimestamp,
            "RewardsCoordinator._validateCommonRewardsSubmission: startTimestamp too far in the past"
        );

        // Require reward submission is for whitelisted strategy or beaconChainETHStrategy
        address currAddress = address(0);
        for (uint256 i = 0; i < strategiesAndMultipliers.length; ++i) {
            IStrategy strategy = strategiesAndMultipliers[i].strategy;
            require(
                strategyManager.strategyIsWhitelistedForDeposit(strategy) || strategy == beaconChainETHStrategy,
                "RewardsCoordinator._validateCommonRewardsSubmission: invalid strategy considered"
            );
            require(
                currAddress < address(strategy),
                "RewardsCoordinator._validateCommonRewardsSubmission: strategies must be in ascending order to handle duplicates"
            );
            currAddress = address(strategy);
        }
    }
}
