// SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.0 <0.9.0;

import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title RewardsCoordinator
 * @author Eigen Labs Inc.
 * @notice Terms of Service: https://docs.eigenlayer.xyz/overview/terms-of-service
 * @notice  This is the contract for rewards in EigenLayer. The main functionalities of this contract are
 * - enabling any ERC20 rewards from AVSs to their operators and stakers for a given time range
 * - allowing stakers and operators to claim their earnings including a commission bips for operators
 * - allowing the protocol to provide ERC20 tokens to stakers over a specified time range
 */
interface IRewardsCoordinator {

    /**
     * @notice Emitted when an AVS creates a valid `OperatorDirectedRewardsSubmission`
     * @param caller The address calling `createOperatorDirectedAVSRewardsSubmission`.
     * @param avs The avs on behalf of which the operator-directed rewards are being submitted.
     * @param operatorDirectedRewardsSubmissionHash Keccak256 hash of (`avs`, `submissionNonce` and `operatorDirectedRewardsSubmission`).
     * @param submissionNonce Current nonce of the avs. Used to generate a unique submission hash.
     * @param operatorDirectedRewardsSubmission The Operator-Directed Rewards Submission. Contains the token, start timestamp, duration, operator rewards, description and, strategy and multipliers.
     */
    event OperatorDirectedAVSRewardsSubmissionCreated(
        address indexed caller,
        address indexed avs,
        bytes32 indexed operatorDirectedRewardsSubmissionHash,
        uint256 submissionNonce,
        OperatorDirectedRewardsSubmission operatorDirectedRewardsSubmission
    );

    /**
     * @notice A linear combination of strategies and multipliers for AVSs to weigh
     * EigenLayer strategies.
     * @param strategy The EigenLayer strategy to be used for the rewards submission
     * @param multiplier The weight of the strategy in the rewards submission
     */
    struct StrategyAndMultiplier {
        IStrategy strategy;
        uint96 multiplier;
    }

    /**
     * @notice A reward struct for an operator
     * @param operator The operator to be rewarded
     * @param amount The reward amount for the operator
     */
    struct OperatorReward {
        address operator;
        uint256 amount;
    }

    /**
     * @notice OperatorDirectedRewardsSubmission struct submitted by AVSs when making operator-directed rewards for their operators and stakers.
     * @param strategiesAndMultipliers The strategies and their relative weights.
     * @param token The rewards token to be distributed.
     * @param operatorRewards The rewards for the operators.
     * @param startTimestamp The timestamp (seconds) at which the submission range is considered for distribution.
     * @param duration The duration of the submission range in seconds.
     * @param description Describes what the rewards submission is for.
     */
    struct OperatorDirectedRewardsSubmission {
        StrategyAndMultiplier[] strategiesAndMultipliers;
        IERC20 token;
        OperatorReward[] operatorRewards;
        uint32 startTimestamp;
        uint32 duration;
        string description;
    }

    /**
     * @notice Creates a new operator-directed rewards submission on behalf of an AVS, to be split amongst the operators and
     * set of stakers delegated to operators who are registered to the `avs`.
     * @param avs The AVS on behalf of which the reward is being submitted
     * @param operatorDirectedRewardsSubmissions The operator-directed rewards submissions being created
     * @dev Expected to be called by the ServiceManager of the AVS on behalf of which the submission is being made
     * @dev The duration of the `rewardsSubmission` cannot exceed `MAX_REWARDS_DURATION`
     * @dev The tokens are sent to the `RewardsCoordinator` contract
     * @dev The `RewardsCoordinator` contract needs a token approval of sum of all `operatorRewards` in the `operatorDirectedRewardsSubmissions`, before calling this function.
     * @dev Strategies must be in ascending order of addresses to check for duplicates
     * @dev Operators must be in ascending order of addresses to check for duplicates.
     * @dev This function will revert if the `operatorDirectedRewardsSubmissions` is malformed.
     */
    function createOperatorDirectedAVSRewardsSubmission(
        address avs,
        OperatorDirectedRewardsSubmission[] calldata operatorDirectedRewardsSubmissions
    ) external;
}
