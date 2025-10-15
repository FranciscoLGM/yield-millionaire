// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title APYExtra
 * @notice Yield contract with extra APY and referral system
 * @dev Uses roles, pauses, and secure validations to manage deposits and earnings
 */
contract APYExtra is ReentrancyGuard, AccessControl, Pausable {
    // ============ CONSTANTS ============
    uint256 public constant APY_SCALE = 10_000; // Base scale for calculating percentages (10000 = 100%)
    uint256 public constant YEAR = 365 days; // Time reference for calculating annual interest
    uint256 public constant MAX_EXTRA_APY = 3_000; // Extra APY limit (30%)
    uint256 public constant MIN_DURATION = 30 days; // Minimum duration for applying extra APY

    // ============ ROLES ============
    bytes32 public constant REBALANCER_ROLE = keccak256("REBALANCER_ROLE"); // Can execute deposits per backend
    bytes32 public constant APY_MANAGER_ROLE = keccak256("APY_MANAGER_ROLE"); // Can modify APY rates
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE"); // Can pause or reactivate the contract

    // ============ CUSTOM ERRORS ============
    error ZeroAddress();
    error ZeroAmount();
    error InvalidReferrer();
    error InsufficientBalance();
    error TimeInversion();
    error ReferrerCycle();
    error TransferFailed();
    error APYTooHigh();
    error DurationTooShort();
    error APYDisabled();

    // ============ STRUCTS ============
    struct UserInfo {
        uint256 expirationTime; // When your extra APY expires
        uint256 lastUpdateTime; // Last time your earnings were updated
        uint256 extraAPY; // Individual APY percentage (based on APY_SCALE)
        uint256 balance; // Tokens staked
        uint256 accumulatedEarnings; // Earnings accumulated so far
        address referrer; // Who referred you (if applicable)
    }

    struct ReferralInfo {
        uint256 lastUpdateTime; // Last update of referral earnings
        uint256 accumulatedEarnings; // Accumulated referral earnings
        address[] referrals; // List of referred users (to display in UI)
    }

    // ============ STATE VARIABLES ============
    IERC20 public immutable token;

    mapping(address => UserInfo) public userInfo; // Data for each user
    mapping(address => ReferralInfo) public referralInfo; // Referral data
    mapping(address => uint256) public referralsTotalBalance; // Total amount deposited by referrals
    mapping(address => uint256) public referralCount; // Total historical referrals
    mapping(address => uint256) public activeReferralCount; // Currently active referrals (with balance > 0)

    uint256 public referralAPY; // APY applied to referral earnings
    uint256 public totalStaked; // Total tokens locked in the contract
    bool public apyEnabled; // Whether the APY system is active or not

    // ============ EVENTS ============
    event Deposited(
        address indexed user,
        uint256 amount,
        uint256 extraAPY,
        uint256 expirationTime,
        address indexed referrer
    );

    event Withdrawn(address indexed user, uint256 amount);
    event EarningsUpdated(address indexed user, uint256 earnings);
    event ReferralEarningsUpdated(address indexed referrer, uint256 earnings);
    event APYToggled(bool enabled);
    event ReferralAPYUpdated(uint256 newAPY);
    event ReferrerAssigned(address indexed user, address indexed referrer);
    event ReferralBalanceUpdated(
        address indexed referrer,
        uint256 newTotalBalance
    );
    event EarningsClaimed(address indexed user, uint256 amount);
    event ActiveReferralUpdated(
        address indexed referrer,
        uint256 newActiveCount
    );

    // ============ MODIFIERS ============
    modifier validAddress(address addr) {
        if (addr == address(0)) revert ZeroAddress();
        _;
    }

    modifier validAmount(uint256 amount) {
        if (amount == 0) revert ZeroAmount();
        _;
    }

    modifier whenAPYEnabled() {
        if (!apyEnabled) revert APYDisabled();
        _;
    }

    // ============ CONSTRUCTOR ============
    constructor(
        address admin,
        uint256 _referralAPY,
        IERC20 _token
    ) validAddress(admin) {
        token = _token;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(REBALANCER_ROLE, admin);
        _grantRole(APY_MANAGER_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);

        referralAPY = _referralAPY;
        apyEnabled = true;

        emit ReferralAPYUpdated(_referralAPY);
        emit APYToggled(true);
    }

    // ============ EXTERNAL FUNCTIONS ============

    /**
     * @notice Deposits funds for a user with optional extra APY
     * @dev Can only be called by an address with REBALANCER_ROLE
     * @param user Address of the user making the deposit
     * @param expirationTime Expiration time of the extra APY (0 = no expiration)
     * @param extraAPY Extra APY rate based on APY_SCALE (10000 = 100%)
     * @param amount Amount of tokens to deposit
     * @custom:throws ZeroAddress if `user` is address(0)
     * @custom:throws ZeroAmount if `amount` is 0
     * @custom:throws TimeInversion if `expirationTime` is in the past
     * @custom:throws DurationTooShort if duration is less than MIN_DURATION
     * @custom:throws APYTooHigh if `extraAPY` exceeds MAX_EXTRA_APY
     * @custom:throws TransferFailed if token transfer fails
     */
    function deposit(
        address user,
        uint256 expirationTime,
        uint256 extraAPY,
        uint256 amount
    )
        external
        nonReentrant
        whenNotPaused
        validAddress(user)
        validAmount(amount)
        onlyRole(REBALANCER_ROLE)
    {
        _deposit(user, expirationTime, extraAPY, amount, address(0));
    }

    /**
     * @notice Deposits funds for a user with referrer and extra APY
     * @dev Similar to `deposit` but includes referrer assignment
     * @param user Address of the user making the deposit
     * @param expirationTime Expiration time of the extra APY
     * @param extraAPY Extra APY rate based on APY_SCALE
     * @param amount Amount of tokens to deposit
     * @param referrer Address of the referrer who recommended the user
     * @custom:throws InvalidReferrer if `referrer` is not valid
     * @custom:throws ReferrerCycle if a cycle is detected in the referral tree
     */
    function depositWithReferrer(
        address user,
        uint256 expirationTime,
        uint256 extraAPY,
        uint256 amount,
        address referrer
    )
        external
        nonReentrant
        whenNotPaused
        validAddress(user)
        validAmount(amount)
        onlyRole(REBALANCER_ROLE)
    {
        _deposit(user, expirationTime, extraAPY, amount, referrer);
    }

    /**
     * @notice Withdraws funds from the caller's balance
     * @dev Updates earnings before withdrawal and transfers tokens to the user
     * @param amount Amount of tokens to withdraw
     * @custom:throws ZeroAmount if `amount` is 0
     * @custom:throws InsufficientBalance if balance is less than `amount`
     * @custom:throws TransferFailed if token transfer fails
     */
    function withdraw(
        uint256 amount
    ) external nonReentrant whenNotPaused validAmount(amount) {
        _withdraw(msg.sender, amount);
    }

    /**
     * @notice Claims the caller's accumulated earnings
     * @dev Transfers accumulated earnings without affecting the principal balance
     * @custom:throws TransferFailed if token transfer fails
     */
    function claimEarnings() external nonReentrant whenNotPaused {
        _claimEarnings(msg.sender);
    }

    /**
     * @notice Calculates a user's pending unclaimed earnings
     * @dev Only considers earnings from last update to current time
     * @param user Address of the user to query
     * @return pending Pending earnings in tokens
     * @custom:throws ZeroAddress if `user` is address(0)
     */
    function getPendingEarnings(
        address user
    ) external view validAddress(user) returns (uint256) {
        return _calculatePendingEarnings(user);
    }

    /**
     * @notice Calculates a user's total earnings (accumulated + pending)
     * @dev Useful for displaying total earned including unclaimed amounts
     * @param user Address of the user to query
     * @return total Total earnings in tokens
     * @custom:throws ZeroAddress if `user` is address(0)
     */
    function getTotalEarnings(
        address user
    ) external view validAddress(user) returns (uint256) {
        UserInfo storage userData = userInfo[user];
        return userData.accumulatedEarnings + _calculatePendingEarnings(user);
    }

    /**
     * @notice Calculates pending earnings generated by a referrer's referrals
     * @dev Based on total referral balance and global referralAPY
     * @param referrer Address of the referrer to query
     * @return pending Pending referral earnings in tokens
     * @custom:throws ZeroAddress if `referrer` is address(0)
     */
    function getPendingReferralEarnings(
        address referrer
    ) external view validAddress(referrer) returns (uint256) {
        return _calculatePendingReferralEarnings(referrer);
    }

    /**
     * @notice Gets the total combined balance of all a referrer's referrals
     * @dev Sums balances of all active referrals of the referrer
     * @param referrer Address of the referrer to query
     * @return totalBalance Total referral balance in tokens
     * @custom:throws ZeroAddress if `referrer` is address(0)
     */
    function getReferralsTotalBalance(
        address referrer
    ) external view validAddress(referrer) returns (uint256) {
        return referralsTotalBalance[referrer];
    }

    /**
     * @notice Globally enables or disables APY calculation
     * @dev Can only be called by an address with APY_MANAGER_ROLE
     * @custom:emits APYToggled indicates the new APY state
     */
    function toggleAPY() external onlyRole(APY_MANAGER_ROLE) {
        apyEnabled = !apyEnabled;
        emit APYToggled(apyEnabled);
    }

    /**
     * @notice Updates the APY rate for referral earnings
     * @dev Can only be called by an address with APY_MANAGER_ROLE
     * @param newReferralAPY New referral APY rate based on APY_SCALE
     * @custom:emits ReferralAPYUpdated indicates the new referral APY rate
     */
    function updateReferralAPY(
        uint256 newReferralAPY
    ) external onlyRole(APY_MANAGER_ROLE) {
        referralAPY = newReferralAPY;
        emit ReferralAPYUpdated(newReferralAPY);
    }

    /**
     * @notice Gets the list of addresses of all a referrer's referrals
     * @dev Includes both active and inactive referrals (historical)
     * @param referrer Address of the referrer to query
     * @return referrals Array of referral addresses
     * @custom:throws ZeroAddress if `referrer` is address(0)
     */
    function getReferrals(
        address referrer
    ) external view validAddress(referrer) returns (address[] memory) {
        return referralInfo[referrer].referrals;
    }

    /**
     * @notice Checks if a user's extra APY has expired
     * @dev Considers expired if current time is greater than or equal to expirationTime
     * @param user Address of the user to check
     * @return expired True if extra APY has expired, false otherwise
     * @custom:throws ZeroAddress if `user` is address(0)
     */
    function isExpired(
        address user
    ) external view validAddress(user) returns (bool) {
        return _isExpired(user);
    }

    /**
     * @notice Pauses all critical contract functions
     * @dev Can only be called by an address with PAUSER_ROLE
     * @custom:emits Paused indicates the contract has been paused
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @notice Resumes all contract functions
     * @dev Can only be called by an address with PAUSER_ROLE
     * @custom:emits Unpaused indicates the contract has been resumed
     */
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // ============ IMPROVED GETTERS FOR FRONTEND ============

    /**
     * @notice Gets all user information in a single call
     * @dev Useful for frontends to avoid multiple blockchain calls
     * @param user Address of the user
     * @return Complete user information
     */
    function getUserInfo(
        address user
    ) external view validAddress(user) returns (UserInfo memory) {
        return userInfo[user];
    }

    /**
     * @notice Gets complete referral information for a referrer
     * @param referrer Address of the referrer
     * @return totalBalance Total balance of all referrals
     * @return totalCount Total number of referrals (historical)
     * @return activeCount Number of active referrals (with balance > 0)
     * @return pendingEarnings Pending referral earnings
     * @return accumulatedEarnings Accumulated referral earnings
     */
    function getReferralStats(
        address referrer
    )
        external
        view
        validAddress(referrer)
        returns (
            uint256 totalBalance,
            uint256 totalCount,
            uint256 activeCount,
            uint256 pendingEarnings,
            uint256 accumulatedEarnings
        )
    {
        totalBalance = referralsTotalBalance[referrer];
        totalCount = referralCount[referrer];
        activeCount = activeReferralCount[referrer];
        pendingEarnings = _calculatePendingReferralEarnings(referrer);
        accumulatedEarnings = referralInfo[referrer].accumulatedEarnings;
    }

    /**
     * @notice Gets complete user statistics including referral data
     * @param user Address of the user
     * @return userData User information
     * @return totalEarnings Total earnings (accumulated + pending)
     * @return totalBalance Total referral balance (if user is a referrer)
     * @return totalCount Total number of referrals (if user is a referrer)
     * @return activeCount Number of active referrals (if user is a referrer)
     * @return pendingRefEarnings Pending referral earnings (if user is a referrer)
     * @return accumulatedRefEarnings Accumulated referral earnings (if user is a referrer)
     */
    function getUserFullStats(
        address user
    )
        external
        view
        validAddress(user)
        returns (
            UserInfo memory userData,
            uint256 totalEarnings,
            uint256 totalBalance,
            uint256 totalCount,
            uint256 activeCount,
            uint256 pendingRefEarnings,
            uint256 accumulatedRefEarnings
        )
    {
        userData = userInfo[user];
        totalEarnings =
            userData.accumulatedEarnings + _calculatePendingEarnings(user);

        // If user is a referrer, include referral statistics
        if (referralCount[user] > 0) {
            totalBalance = referralsTotalBalance[user];
            totalCount = referralCount[user];
            activeCount = activeReferralCount[user];
            pendingRefEarnings = _calculatePendingReferralEarnings(user);
            accumulatedRefEarnings = referralInfo[user].accumulatedEarnings;
        }
    }

    // ============ INTERNAL FUNCTIONS ============

    /**
     * @dev Internal function to handle deposit logic with referral assignment
     * @param user Address of the user making the deposit
     * @param expirationTime Expiration time for extra APY (0 = no expiration)
     * @param extraAPY Extra APY rate based on APY_SCALE
     * @param amount Amount of tokens to deposit
     * @param referrer Address of the referrer (optional)
     * @custom:throws TimeInversion if expiration time is in the past
     * @custom:throws DurationTooShort if expiration duration is too short
     * @custom:throws APYTooHigh if extra APY exceeds maximum allowed
     * @custom:throws TransferFailed if token transfer fails
     * @custom:throws InvalidReferrer if referrer is not valid
     * @custom:emits ReferrerAssigned when a new referrer is assigned
     * @custom:emits ActiveReferralUpdated when active referral count changes
     * @custom:emits Deposited when deposit is completed
     */
    function _deposit(
        address user,
        uint256 expirationTime,
        uint256 extraAPY,
        uint256 amount,
        address referrer
    ) internal whenAPYEnabled {
        // Validate expiration time
        if (expirationTime != 0) {
            if (expirationTime <= block.timestamp) revert TimeInversion();
            if (expirationTime - block.timestamp < MIN_DURATION)
                revert DurationTooShort();
        }

        // Validate maximum APY
        if (extraAPY > MAX_EXTRA_APY) revert APYTooHigh();

        // Transfer tokens to contract
        if (!token.transferFrom(msg.sender, address(this), amount)) {
            revert TransferFailed();
        }

        // Use local variable for gas optimization
        UserInfo storage userData = userInfo[user];
        bool isNewUser = userData.balance == 0;

        // Update earnings before modifying balance
        _updateEarnings(user);

        // Assign referrer if valid and first time
        if (referrer != address(0) && userData.referrer == address(0)) {
            if (!_validateReferrer(user, referrer)) revert InvalidReferrer();

            userData.referrer = referrer;
            referralInfo[referrer].referrals.push(user);
            referralCount[referrer]++;

            // Initialize referrer's lastUpdateTime if first time
            if (referralInfo[referrer].lastUpdateTime == 0) {
                referralInfo[referrer].lastUpdateTime = block.timestamp;
            }

            emit ReferrerAssigned(user, referrer);
        }

        // Update user balance
        userData.balance += amount;
        totalStaked += amount;

        // Update referrer's total referral balance
        address userReferrer = userData.referrer;
        if (userReferrer != address(0)) {
            referralsTotalBalance[userReferrer] += amount;

            // If new user, increment active referral count
            if (isNewUser) {
                activeReferralCount[userReferrer]++;
                emit ActiveReferralUpdated(
                    userReferrer,
                    activeReferralCount[userReferrer]
                );
            }
        }

        // Update extra APY only if higher
        if (extraAPY > userData.extraAPY) {
            userData.extraAPY = extraAPY;
            userData.expirationTime = expirationTime;
        }

        // Update timestamp
        userData.lastUpdateTime = block.timestamp;

        emit Deposited(
            user,
            amount,
            extraAPY,
            expirationTime,
            userData.referrer
        );
    }

    /**
     * @dev Internal function to handle withdrawal logic
     * @param user Address of the user withdrawing funds
     * @param amount Amount of tokens to withdraw
     * @custom:throws InsufficientBalance if user balance is less than withdrawal amount
     * @custom:throws TransferFailed if token transfer fails
     * @custom:emits ActiveReferralUpdated if active referral count changes
     * @custom:emits Withdrawn when withdrawal is completed
     */
    function _withdraw(address user, uint256 amount) internal {
        // Use local variable for gas optimization
        UserInfo storage userData = userInfo[user];
        uint256 oldBalance = userData.balance;
        address userReferrer = userData.referrer;

        // Update earnings before withdrawing
        _updateEarnings(user);

        if (userData.balance < amount) revert InsufficientBalance();

        // Effects: update balances
        userData.balance -= amount;
        totalStaked -= amount;

        // Safely update referrer's total referral balance
        if (userReferrer != address(0)) {
            uint256 currentRefBalance = referralsTotalBalance[userReferrer];
            if (currentRefBalance >= amount) {
                referralsTotalBalance[userReferrer] =
                    currentRefBalance - amount;
            } else {
                referralsTotalBalance[userReferrer] = 0;
            }

            // Precise accounting of active referrals
            if (
                oldBalance > 0 &&
                userData.balance == 0 &&
                activeReferralCount[userReferrer] > 0
            ) {
                activeReferralCount[userReferrer]--;
                emit ActiveReferralUpdated(
                    userReferrer,
                    activeReferralCount[userReferrer]
                );
            }
        }

        // Interactions: transfer tokens to user
        if (!token.transfer(user, amount)) revert TransferFailed();

        emit Withdrawn(user, amount);
    }

    /**
     * @dev Internal function to claim accumulated earnings
     * @param user Address of the user claiming earnings
     * @custom:throws TransferFailed if token transfer fails
     * @custom:emits EarningsClaimed when earnings are successfully claimed
     */
    function _claimEarnings(address user) internal {
        _updateEarnings(user);

        UserInfo storage userData = userInfo[user];
        uint256 earnings = userData.accumulatedEarnings;

        if (earnings > 0) {
            userData.accumulatedEarnings = 0;

            if (!token.transfer(user, earnings)) revert TransferFailed();
            emit EarningsClaimed(user, earnings);
        }
    }

    /**
     * @dev Internal function to calculate pending earnings for a user
     * @param user Address of the user to calculate earnings for
     * @return pendingEarnings Amount of pending earnings in tokens
     */
    function _calculatePendingEarnings(
        address user
    ) internal view returns (uint256) {
        UserInfo storage userData = userInfo[user];

        if (!apyEnabled || userData.extraAPY == 0 || userData.balance == 0) {
            return 0;
        }

        uint256 expirationTime = userData.expirationTime;
        uint256 tn = _isExpired(user) ? expirationTime : block.timestamp;
        if (tn <= userData.lastUpdateTime) return 0;

        uint256 delta = tn - userData.lastUpdateTime;

        return
            (userData.balance * userData.extraAPY * delta) / (APY_SCALE * YEAR);
    }

    /**
     * @dev Internal function to calculate pending referral earnings
     * @param referrer Address of the referrer to calculate earnings for
     * @return pendingEarnings Amount of pending referral earnings in tokens
     */
    function _calculatePendingReferralEarnings(
        address referrer
    ) internal view returns (uint256) {
        ReferralInfo storage refData = referralInfo[referrer];
        uint256 totalRefBalance = referralsTotalBalance[referrer];

        if (!apyEnabled || referralAPY == 0 || totalRefBalance == 0) {
            return 0;
        }

        uint256 lastUpdate = refData.lastUpdateTime;
        if (lastUpdate == 0) return 0; // Not initialized yet

        uint256 tn = block.timestamp;
        if (tn <= lastUpdate) return 0;

        uint256 delta = tn - lastUpdate;

        return (totalRefBalance * referralAPY * delta) / (APY_SCALE * YEAR);
    }

    /**
     * @dev Internal function to update user earnings and referral earnings
     * @param user Address of the user to update earnings for
     * @custom:emits EarningsUpdated when user earnings are updated
     * @custom:emits ReferralEarningsUpdated when referral earnings are updated
     */
    function _updateEarnings(address user) internal {
        uint256 pendingEarnings = _calculatePendingEarnings(user);
        UserInfo storage userData = userInfo[user];

        if (pendingEarnings > 0) {
            userData.accumulatedEarnings += pendingEarnings;
            userData.lastUpdateTime = block.timestamp;
            emit EarningsUpdated(user, pendingEarnings);
        }

        // Update referral earnings if user is a referrer
        if (referralCount[user] > 0) {
            _updateReferralEarnings(user);
        }
    }

    /**
     * @dev Internal function to update referral earnings for a referrer
     * @param referrer Address of the referrer to update earnings for
     * @custom:emits ReferralEarningsUpdated when referral earnings are updated
     */
    function _updateReferralEarnings(address referrer) internal {
        uint256 pendingRefEarnings = _calculatePendingReferralEarnings(
            referrer
        );
        if (pendingRefEarnings > 0) {
            referralInfo[referrer].accumulatedEarnings += pendingRefEarnings;
            referralInfo[referrer].lastUpdateTime = block.timestamp;
            emit ReferralEarningsUpdated(referrer, pendingRefEarnings);
        }
    }

    /**
     * @dev Internal function to check if user's extra APY has expired
     * @param user Address of the user to check
     * @return expired True if extra APY has expired, false otherwise
     */
    function _isExpired(address user) internal view returns (bool) {
        UserInfo storage userData = userInfo[user];
        return
            userData.expirationTime > 0 &&
            block.timestamp >= userData.expirationTime;
    }

    /**
     * @dev Internal function to validate referrer assignment
     * @param user Address of the user being referred
     * @param referrer Address of the potential referrer
     * @return valid True if referrer is valid, false otherwise
     * @custom:throws ReferrerCycle if a referral cycle is detected
     */
    function _validateReferrer(
        address user,
        address referrer
    ) internal view returns (bool) {
        if (referrer == address(0) || referrer == user) return false;

        // Prevent cycles in referral tree
        address current = referrer;
        while (current != address(0)) {
            if (current == user) return false;
            current = userInfo[current].referrer;
        }

        return true;
    }
}
