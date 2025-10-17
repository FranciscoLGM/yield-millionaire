// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title APYExtra
 * @notice Yield contract with extra APY and referral system
 * @dev Uses roles and secure validations to manage deposits and earnings
 */
contract APYExtra is AccessControl {
    uint256 public constant PRECISION = 1000 ether;
    uint256 public constant YEAR = 365 days;
    uint256 public constant APY_DENOMINATOR = 1000;

    error ZeroAmount();
    error InsufficientBalance();
    error InvalidAdmin();
    error CallerNotRebalancer();

    bytes32 public constant REBALANCER_ROLE = keccak256("REBALANCER_ROLE");
    bytes32 public constant APY_MANAGER_ROLE = keccak256("APY_MANAGER_ROLE");

    struct UserInfo {
        uint256 expirationTime;
        uint256 lastUpdateTime;
        uint256 extraAPY;
        uint256 balance;
        uint256 accumulatedEarnings;
        address referrer;
    }

    struct ReferralInfo {
        uint256 lastUpdateTime;
        uint256 accumulatedEarnings;
        address[] referrals;
    }

    mapping(address => UserInfo) public userInfo;
    mapping(address => ReferralInfo) public referralInfo;
    mapping(address => uint256) public referralTotalBalance;

    uint256 public referralAPY;
    bool public apyEnabled;

    event Deposited(
        address indexed user,
        uint256 amount,
        uint256 extraAPY,
        address indexed referrer
    );
    event Withdrawn(address indexed user, uint256 amount);
    event ReferrerAssigned(address indexed user, address indexed referrer);

    modifier onlyRebalancer() {
        if (!hasRole(REBALANCER_ROLE, msg.sender)) revert CallerNotRebalancer();
        _;
    }

    /**
     * @notice Initialize contract with admin and referral APY
     * @param admin Admin address with all roles
     * @param initialReferralAPY Global referral APY (50 = 5%)
     */
    constructor(address admin, uint256 initialReferralAPY) {
        if (admin == address(0)) revert InvalidAdmin();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(REBALANCER_ROLE, admin);
        _grantRole(APY_MANAGER_ROLE, admin);

        referralAPY = initialReferralAPY;
        apyEnabled = true;
    }

    /**
     * @notice Deposit funds without referrer
     * @dev Only rebalancer can call. Updates balances and accumulates earnings.
     */
    function deposit(
        address user,
        uint256 expirationTime,
        uint256 extraAPY,
        uint256 amount
    ) external onlyRebalancer {
        _executeDeposit(user, expirationTime, extraAPY, amount, address(0));
    }

    /**
     * @notice Deposit funds with optional referrer
     * @dev Referrer can only be set on first deposit
     */
    function deposit(
        address user,
        uint256 expirationTime,
        uint256 extraAPY,
        uint256 amount,
        address referrer
    ) external onlyRebalancer {
        _executeDeposit(user, expirationTime, extraAPY, amount, referrer);
    }

    /**
     * @notice Withdraw funds after accumulating earnings
     * @dev Accumulates user earnings, referral earnings, and referrer's earnings
     * @return amount Returns same amount for external handling
     */
    function withdraw(uint256 amount) external returns (uint256) {
        if (amount == 0) revert ZeroAmount();

        address user = msg.sender;
        UserInfo storage userData = userInfo[user];

        if (userData.balance < amount) revert InsufficientBalance();

        _accumulateAllEarnings(user);

        unchecked {
            userData.balance -= amount;
        }
        userData.lastUpdateTime = block.timestamp;

        if (userData.referrer != address(0)) {
            referralTotalBalance[userData.referrer] -= amount;
        }

        emit Withdrawn(user, amount);
        return amount;
    }

    /**
     * @notice Toggle APY system globally
     */
    function toggleAPY() external onlyRole(APY_MANAGER_ROLE) {
        apyEnabled = !apyEnabled;
    }

    /**
     * @notice Update global referral APY rate
     */
    function updateReferralAPY(
        uint256 newReferralAPY
    ) external onlyRole(APY_MANAGER_ROLE) {
        referralAPY = newReferralAPY;
    }

    /**
     * @notice Calculate unclaimed earnings since last update
     * @dev Uses exact formula from specification
     */
    function getLastEarnings(address user) public view returns (uint256) {
        UserInfo memory userData = userInfo[user];

        if (
            !apyEnabled ||
            userData.extraAPY == 0 ||
            userData.balance == 0 ||
            userData.lastUpdateTime == 0
        ) {
            return 0;
        }

        uint256 calculationTime = (userData.expirationTime != 0 &&
            block.timestamp > userData.expirationTime)
            ? userData.expirationTime
            : block.timestamp;

        if (calculationTime <= userData.lastUpdateTime) {
            return 0;
        }

        uint256 timeDelta = calculationTime - userData.lastUpdateTime;
        uint256 principal = userData.balance;

        return
            (principal *
                (PRECISION +
                    (userData.extraAPY * 1 ether * timeDelta) /
                        (APY_DENOMINATOR * YEAR))) /
                1 ether -
            principal;
    }

    /**
     * @notice Calculate total earnings (accumulated + pending)
     */
    function getTotalEarnings(address user) public view returns (uint256) {
        return userInfo[user].accumulatedEarnings + getLastEarnings(user);
    }

    /**
     * @notice Calculate referrer's pending earnings from referrals
     */
    function getReferralsEarnings(
        address referrer
    ) public view returns (uint256) {
        if (!apyEnabled || referralAPY == 0) return 0;

        ReferralInfo memory refData = referralInfo[referrer];
        uint256 totalRefBalance = referralTotalBalance[referrer];

        if (
            totalRefBalance == 0 ||
            refData.lastUpdateTime == 0 ||
            block.timestamp <= refData.lastUpdateTime
        ) {
            return 0;
        }

        uint256 timeDelta = block.timestamp - refData.lastUpdateTime;
        return
            (totalRefBalance * referralAPY * timeDelta) /
            (APY_DENOMINATOR * YEAR);
    }

    /**
     * @dev Execute deposit with earnings accumulation and referrer assignment
     */
    function _executeDeposit(
        address user,
        uint256 expirationTime,
        uint256 extraAPY,
        uint256 amount,
        address referrer
    ) internal {
        UserInfo storage userData = userInfo[user];

        _accumulateAllEarnings(user);
        userData.lastUpdateTime = block.timestamp;

        unchecked {
            userData.balance += amount;
        }

        if (extraAPY > userData.extraAPY) {
            userData.extraAPY = extraAPY;
            userData.expirationTime = expirationTime;
        }

        if (
            referrer != address(0) &&
            userData.referrer == address(0) &&
            referrer != user
        ) {
            userData.referrer = referrer;

            ReferralInfo storage refInfo = referralInfo[referrer];
            refInfo.referrals.push(user);

            if (refInfo.lastUpdateTime == 0) {
                refInfo.lastUpdateTime = block.timestamp;
            }

            emit ReferrerAssigned(user, referrer);
        }

        if (userData.referrer != address(0)) {
            referralTotalBalance[userData.referrer] += amount;
        }

        emit Deposited(user, amount, extraAPY, userData.referrer);
    }

    /**
     * @dev Accumulate all types of earnings for a user
     */
    function _accumulateAllEarnings(address user) internal {
        UserInfo storage userData = userInfo[user];

        uint256 pendingUser = getLastEarnings(user);
        if (pendingUser > 0) {
            userData.accumulatedEarnings += pendingUser;
        }

        ReferralInfo storage refInfo = referralInfo[user];
        if (refInfo.referrals.length > 0) {
            uint256 pendingRef = getReferralsEarnings(user);
            if (pendingRef > 0) {
                refInfo.accumulatedEarnings += pendingRef;
                refInfo.lastUpdateTime = block.timestamp;
            }
        }

        if (userData.referrer != address(0)) {
            address referrer = userData.referrer;
            uint256 pendingReferrer = getReferralsEarnings(referrer);
            if (pendingReferrer > 0) {
                referralInfo[referrer].accumulatedEarnings += pendingReferrer;
                referralInfo[referrer].lastUpdateTime = block.timestamp;
            }
        }
    }
}
