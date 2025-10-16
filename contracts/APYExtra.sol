// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title APYExtra - Minimal Staking Contract with Extra APY and Referrals
 * @dev Optimized version following APY_EXTRA.pdf specification with gas efficiency
 */
contract APYExtra is ReentrancyGuard, AccessControl {
    // ============ CONSTANTS ============
    uint256 public constant APY_SCALE = 10_000;
    uint256 public constant YEAR = 365 days;

    // ============ ROLES ============
    bytes32 public constant REBALANCER_ROLE = keccak256("REBALANCER_ROLE");
    bytes32 public constant APY_MANAGER_ROLE = keccak256("APY_MANAGER_ROLE");

    // ============ CUSTOM ERRORS ============
    error ZeroAddress();
    error ZeroAmount();
    error InsufficientBalance();
    error TransferFailed();
    error InvalidReferrer();

    // ============ STRUCTS ============
    struct UserInfo {
        uint256 expirationTime; // Tiempo expiración APY extra (0 = no aplica)
        uint256 lastUpdateTime; // Timestamp último depósito/actualización
        uint256 extraAPY; // APY extra asignado al usuario
        uint256 balance; // Balance del usuario
        uint256 accumulatedEarnings; // Ganancia acumulada previamente
        address referrer; // Referente del usuario
    }

    struct ReferralInfo {
        uint256 lastUpdateTime; // Timestamp último cálculo de ganancias
        uint256 accumulatedEarnings; // Ganancia acumulada de referidos
        address[] referrals; // Lista de referidos
    }

    // ============ STATE VARIABLES ============
    IERC20 public immutable token;

    mapping(address => UserInfo) public userInfo;
    mapping(address => ReferralInfo) public referralInfo;

    uint256 public referralAPY;
    bool public apyEnabled;

    // ============ EVENTS ============
    event Deposited(
        address indexed user,
        uint256 amount,
        uint256 extraAPY,
        uint256 expirationTime,
        address indexed referrer
    );
    event Withdrawn(address indexed user, uint256 amount);
    event EarningsClaimed(address indexed user, uint256 amount);
    event APYToggled(bool enabled);
    event ReferralAPYUpdated(uint256 newAPY);
    event ReferrerAssigned(address indexed user, address indexed referrer);

    // ============ MODIFIERS ============
    modifier validAddress(address addr) {
        if (addr == address(0)) revert ZeroAddress();
        _;
    }

    modifier validAmount(uint256 amount) {
        if (amount == 0) revert ZeroAmount();
        _;
    }

    // ============ CONSTRUCTOR ============
    constructor(address admin, uint256 _referralAPY, IERC20 _token) {
        token = _token;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(REBALANCER_ROLE, admin);
        _grantRole(APY_MANAGER_ROLE, admin);

        referralAPY = _referralAPY;
        apyEnabled = true;
    }

    // ============ DEPOSIT FUNCTIONS (OVERLOADS) ============

    /**
     * @notice Deposita fondos sin referente
     * @dev Overload sin referente - llama a la función interna con address(0)
     * @param user Address del usuario
     * @param expirationTime Tiempo de expiración APY
     * @param extraAPY APY extra asignado
     * @param amount Cantidad a depositar
     */
    function deposit(
        address user,
        uint256 expirationTime,
        uint256 extraAPY,
        uint256 amount
    )
        external
        nonReentrant
        validAddress(user)
        validAmount(amount)
        onlyRole(REBALANCER_ROLE)
    {
        _deposit(user, expirationTime, extraAPY, amount, address(0));
    }

    /**
     * @notice Deposita fondos con referente
     * @dev Overload con referente - asigna referente si es válido
     * @param user Address del usuario
     * @param expirationTime Tiempo de expiración APY
     * @param extraAPY APY extra asignado
     * @param amount Cantidad a depositar
     * @param referrer Address del referente
     */
    function deposit(
        address user,
        uint256 expirationTime,
        uint256 extraAPY,
        uint256 amount,
        address referrer
    )
        external
        nonReentrant
        validAddress(user)
        validAmount(amount)
        onlyRole(REBALANCER_ROLE)
    {
        _deposit(user, expirationTime, extraAPY, amount, referrer);
    }

    /**
     * @dev Función interna que implementa la lógica de depósito según especificación
     * Flujo exacto del documento:
     * 1. Acumula ganancias existentes
     * 2. Actualiza timestamp lastUpdateTime al actual
     * 3. Incrementa balance
     * 4. Actualiza expirationTime y extraAPY solo si nuevo APY es mayor
     * 5. Si hay referrer, registra y actualiza ganancias de referidos
     */
    function _deposit(
        address user,
        uint256 expirationTime,
        uint256 extraAPY,
        uint256 amount,
        address referrer
    ) internal {
        // Transferir tokens primero (operación crítica)
        if (!token.transferFrom(msg.sender, address(this), amount))
            revert TransferFailed();

        UserInfo storage userData = userInfo[user];

        // 1. Acumular las ganancias existentes (Paso 1 del documento)
        uint256 pendingEarnings = getPendingEarnings(user);
        if (pendingEarnings > 0) {
            userData.accumulatedEarnings += pendingEarnings;
        }

        // 2. Actualizar el timestamp lastUpdateTime al actual (Paso 2 del documento)
        userData.lastUpdateTime = block.timestamp;

        // 3. Incrementar balance con el nuevo depósito (Paso 3 del documento)
        userData.balance += amount;

        // 4. Actualizar expirationTime y extraAPY solo si el nuevo APY es mayor que el existente (Paso 4 del documento)
        if (extraAPY > userData.extraAPY) {
            userData.extraAPY = extraAPY;
            userData.expirationTime = expirationTime;
        }

        // 5. Si se indica un referrer, se registra en la estructura (Paso 5 del documento)
        if (referrer != address(0) && userData.referrer == address(0)) {
            // Validar que el referente sea válido (no ciclos)
            if (_isValidReferrer(user, referrer)) {
                userData.referrer = referrer;
                referralInfo[referrer].referrals.push(user);

                // Inicializar timestamp del referente si es primera vez
                if (referralInfo[referrer].lastUpdateTime == 0) {
                    referralInfo[referrer].lastUpdateTime = block.timestamp;
                }

                emit ReferrerAssigned(user, referrer);
            }
        }

        // Al hacer deposit para sí, también debo modificar los datos de sus referentes
        // haciendo también una recolección de la ganancia (especificación del documento)
        if (userData.referrer != address(0)) {
            _updateReferralEarnings(userData.referrer);
        }

        emit Deposited(
            user,
            amount,
            extraAPY,
            expirationTime,
            userData.referrer
        );
    }

    // ============ WITHDRAW & CLAIM FUNCTIONS ============

    /**
     * @notice Retira fondos acumulando ganancias primero
     * @dev Sigue especificación: primero acumular ganancias antes de retirar
     * @param amount Cantidad a retirar
     */
    function withdraw(
        uint256 amount
    ) external nonReentrant validAmount(amount) {
        address user = msg.sender;
        UserInfo storage userData = userInfo[user];

        // Acumular ganancias pendientes para el usuario (como deposit)
        uint256 pendingEarnings = getPendingEarnings(user);
        if (pendingEarnings > 0) {
            userData.accumulatedEarnings += pendingEarnings;
            userData.lastUpdateTime = block.timestamp;
        }

        if (userData.balance < amount) revert InsufficientBalance();
        userData.balance -= amount;

        if (!token.transfer(user, amount)) revert TransferFailed();
        emit Withdrawn(user, amount);

        // Al hacer withdraw para sí, también debo modificar los datos de sus referentes
        // haciendo también una recolección de la ganancia (especificación del documento)
        if (userData.referrer != address(0)) {
            _updateReferralEarnings(userData.referrer);
        }
    }

    /**
     * @notice Reclama ganancias acumuladas
     * @dev Acumula ganancias pendientes antes de transferir
     */
    function claimEarnings() external nonReentrant {
        address user = msg.sender;
        UserInfo storage userData = userInfo[user];

        // Acumular ganancias pendientes
        uint256 pendingEarnings = getPendingEarnings(user);
        if (pendingEarnings > 0) {
            userData.accumulatedEarnings += pendingEarnings;
            userData.lastUpdateTime = block.timestamp;
        }

        uint256 totalEarnings = userData.accumulatedEarnings;
        if (totalEarnings > 0) {
            userData.accumulatedEarnings = 0;
            if (!token.transfer(user, totalEarnings)) revert TransferFailed();
            emit EarningsClaimed(user, totalEarnings);
        }

        // Al hacer claim para sí, también debo modificar los datos de sus referentes
        // haciendo también una recolección de la ganancia (especificación del documento)
        if (userData.referrer != address(0)) {
            _updateReferralEarnings(userData.referrer);
        }
    }

    // ============ VIEW FUNCTIONS ============

    /**
     * @notice Calcula ganancias desde última actualización (getLastEarnings del documento)
     * @dev Implementa fórmula exacta: (APY/365 days) * deltaTiempo
     * @param user Address del usuario
     * @return pendingEarnings Ganancia generada desde última actualización
     */
    function getPendingEarnings(
        address user
    ) public view returns (uint256 pendingEarnings) {
        UserInfo storage userData = userInfo[user];

        // No revertir - devolver 0 si condiciones no favorables (corrección del documento)
        if (!apyEnabled || userData.extraAPY == 0 || userData.balance == 0) {
            return 0;
        }

        // Determinar calculationTime según especificación del documento
        uint256 calculationTime = block.timestamp;
        if (
            userData.expirationTime != 0 &&
            block.timestamp > userData.expirationTime
        ) {
            calculationTime = userData.expirationTime; // Usar tiempo expiración si ya expiró
        }

        // Garantizar que no sea negativo (especificación del documento)
        if (calculationTime < userData.lastUpdateTime) {
            calculationTime = userData.lastUpdateTime;
        }

        uint256 timeDelta = calculationTime - userData.lastUpdateTime;
        if (timeDelta == 0) return 0;

        // Fórmula optimizada: (balance * extraAPY * timeDelta) / (APY_SCALE * 365 days)
        return
            (userData.balance * userData.extraAPY * timeDelta) /
            (APY_SCALE * YEAR);
    }

    /**
     * @notice Calcula ganancias totales (getTotalEarnings del documento)
     * @param user Address del usuario
     * @return totalEarnings Ganancia total (pendiente + acumulada)
     */
    function getTotalEarnings(
        address user
    ) public view returns (uint256 totalEarnings) {
        return getPendingEarnings(user) + userInfo[user].accumulatedEarnings;
    }

    /**
     * @notice Obtiene balance total de referidos (getReferidosBalance del documento)
     * @param referrer Address del referente
     * @return totalBalance Balance total de todos los referidos
     */
    function getReferralsBalance(
        address referrer
    ) public view returns (uint256 totalBalance) {
        address[] storage referrals = referralInfo[referrer].referrals;
        totalBalance = 0;

        for (uint i = 0; i < referrals.length; i++) {
            totalBalance += userInfo[referrals[i]].balance;
        }

        return totalBalance;
    }

    /**
     * @notice Calcula ganancias de referidos (getReferidosEarnings del documento)
     * @dev Usa referralAPY global y no expira (expirationTime no aplica para referidos)
     * @param referrer Address del referente
     * @return referralEarnings Ganancias generadas por referidos
     */
    function getReferralsEarnings(
        address referrer
    ) public view returns (uint256 referralEarnings) {
        ReferralInfo storage refData = referralInfo[referrer];

        // No revertir - devolver 0 si condiciones no favorables
        if (!apyEnabled || referralAPY == 0) return 0;

        uint256 totalRefBalance = getReferralsBalance(referrer);
        if (totalRefBalance == 0) return 0;

        // calculationTime nunca expira para referidos (expirationTime no aplica según documento)
        uint256 calculationTime = block.timestamp;
        if (calculationTime <= refData.lastUpdateTime) return 0;

        uint256 timeDelta = calculationTime - refData.lastUpdateTime;
        return (totalRefBalance * referralAPY * timeDelta) / (APY_SCALE * YEAR);
    }

    /**
     * @notice Obtiene referente de un usuario (getReferente del documento)
     * @param user Address del referido
     * @return referrer Address del referente
     */
    function getReferrer(address user) public view returns (address referrer) {
        return userInfo[user].referrer;
    }

    /**
     * @notice Obtiene lista de referidos de un referente
     * @param referrer Address del referente
     * @return referrals Lista de addresses de referidos
     */
    function getReferrals(
        address referrer
    ) public view returns (address[] memory referrals) {
        return referralInfo[referrer].referrals;
    }

    /**
     * @notice Obtiene información completa del usuario
     * @param user Address del usuario
     * @return balance Balance actual del usuario
     * @return pendingEarnings Ganancias pendientes por reclamar
     * @return accumulatedEarnings Ganancias acumuladas
     * @return extraAPY APY extra asignado al usuario
     * @return expirationTime Tiempo de expiración del APY extra
     * @return referrer Address del referente
     * @return referralCount Número de referidos del usuario
     */
    function getUserInfo(
        address user
    )
        external
        view
        returns (
            uint256 balance,
            uint256 pendingEarnings,
            uint256 accumulatedEarnings,
            uint256 extraAPY,
            uint256 expirationTime,
            address referrer,
            uint256 referralCount
        )
    {
        UserInfo storage userData = userInfo[user];
        balance = userData.balance;
        pendingEarnings = getPendingEarnings(user);
        accumulatedEarnings = userData.accumulatedEarnings;
        extraAPY = userData.extraAPY;
        expirationTime = userData.expirationTime;
        referrer = userData.referrer;
        referralCount = referralInfo[user].referrals.length;
    }

    // ============ ADMIN FUNCTIONS ============

    /**
     * @notice Activa/desactiva APY global (toggleAPY del documento)
     * @dev No revierte, solo afecta cálculos futuros (corrección del documento)
     */
    function toggleAPY() external onlyRole(APY_MANAGER_ROLE) {
        apyEnabled = !apyEnabled;
        emit APYToggled(apyEnabled);
    }

    /**
     * @notice Actualiza APY de referidos
     * @param newReferralAPY Nuevo valor de APY para referidos
     */
    function updateReferralAPY(
        uint256 newReferralAPY
    ) external onlyRole(APY_MANAGER_ROLE) {
        referralAPY = newReferralAPY;
        emit ReferralAPYUpdated(newReferralAPY);
    }

    // ============ INTERNAL FUNCTIONS ============

    /**
     * @dev Actualiza ganancias de referidos para un referente
     * @param referrer Address del referente
     */
    function _updateReferralEarnings(address referrer) internal {
        uint256 pendingRefEarnings = getReferralsEarnings(referrer);
        if (pendingRefEarnings > 0) {
            referralInfo[referrer].accumulatedEarnings += pendingRefEarnings;
            referralInfo[referrer].lastUpdateTime = block.timestamp;
        }
    }

    /**
     * @dev Valida referente evitando ciclos y auto-referencia
     * @param user Address del usuario
     * @param referrer Address del referente propuesto
     * @return isValid true si el referente es válido
     */
    function _isValidReferrer(
        address user,
        address referrer
    ) internal view returns (bool isValid) {
        if (referrer == address(0) || referrer == user) return false;

        // Prevenir ciclos en el árbol de referidos
        address current = referrer;
        while (current != address(0)) {
            if (current == user) return false;
            current = userInfo[current].referrer;
        }

        return true;
    }
}
