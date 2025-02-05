// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract RewardPool is Ownable, ReentrancyGuard, EIP712 {
    // Struct to store information about token balance and its state
    struct TokenBalance {
        address token; // Address of the token
        uint256 balance; // Balance of the token
        address merchant; // Address of the merchant
        bool isActive; // Whether the ID is actively in use
    }

    mapping(uint256 => TokenBalance) public idBalances; // Mapping from ID to TokenBalance
    mapping(address => mapping(address => uint256)) public totalClaims; // Mapping from user -> token -> claimed amount
    mapping(address => uint256) public userNonces; // Mapping from user to their current nonce value
    mapping(address => bool) public tokenWhitelist; // Mapping to check if a token is whitelisted
    address[] public whitelistedTokens; // Array to store all whitelisted tokens

    address public signer; // Address of the authorized signer

    string internal constant name = "Reward"; // EIP712 domain name
    string internal constant version = "1"; // EIP712 domain version

    // EIP712 typehash for claim verification
    bytes32 public constant REWARD_TYPEHASH =
        keccak256(
            "getSigner(address _account,uint256[] _ids,address[] _tokens,uint256[] _amounts,uint256 _nonce)"
        );

    using SafeERC20 for IERC20;

    // Event emitted when rewards are claimed
    event RewardClaimed(
        uint256[] ids,
        address[] tokens,
        uint256[] amounts,
        address indexed user
    );

    // Event emitted when tokens are deposited
    event TokenDeposited(
        uint256 indexed id,
        address token,
        uint256 amount,
        address merchant
    );

    // Event emitted when tokens are withdrawn by the merchant
    event TokensWithdrawn(
        uint256 indexed id,
        address token,
        uint256 amount,
        address merchant
    );

    // Constructor to initialize the contract with the signer address
    constructor(address _signer) Ownable(msg.sender) EIP712(name, version) {
        signer = _signer;
    }

    // Modifier to restrict access to only the signer
    modifier onlySigner() {
        require(msg.sender == signer, "Caller is not the signer");
        _;
    }

    /**
     * @dev Set the authorized signer for the contract.
     * @param _signer The new signer address.
     */
    function setSigner(address _signer) external onlyOwner {
        signer = _signer;
    }

    /**
     * @dev Deposit tokens into the contract and associate them with a unique ID.
     * @param token The address of the token being deposited.
     * @param amount The amount of tokens being deposited.
     * @param id The unique ID associated with the deposit.
     */
    function deposit(address token, uint256 amount, uint256 id) external {
        require(amount > 0, "Amount must be greater than zero");
        require(tokenWhitelist[token], "Token not whitelisted");
        require(!idBalances[id].isActive, "ID already used");

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        idBalances[id] = TokenBalance({
            token: token,
            balance: amount,
            merchant: msg.sender,
            isActive: true
        });

        emit TokenDeposited(id, token, amount, msg.sender);
    }

    /**
     * @dev Withdraw the balance associated with a specific ID back to the merchant.
     * @param id The unique ID associated with the deposit.
     */
    function withdrawMerchantBalance(
        uint256 id
    ) external nonReentrant onlySigner {
        TokenBalance storage balanceInfo = idBalances[id];
        require(balanceInfo.isActive, "ID is not active");
        require(balanceInfo.balance > 0, "Insufficient ID balance");

        uint256 amount = balanceInfo.balance;
        balanceInfo.balance = 0;

        IERC20(balanceInfo.token).safeTransfer(balanceInfo.merchant, amount);

        emit TokensWithdrawn(
            id,
            balanceInfo.token,
            amount,
            balanceInfo.merchant
        );
    }

    /**
     * @dev Internal function to recover the signer from the provided signature.
     */
    function getSigner(
        address _account,
        uint256[] memory _ids,
        address[] memory _tokens,
        uint256[] memory _amounts,
        uint256 _nonce,
        bytes memory signature
    ) internal view returns (address) {
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    REWARD_TYPEHASH,
                    _account,
                    _ids,
                    _tokens,
                    _amounts,
                    _nonce
                )
            )
        );
        return ECDSA.recover(digest, signature);
    }

    /**
     * @dev Internal function to verify the EIP712 signature.
     */
    function verify(
        address _account,
        uint256[] memory _ids,
        address[] memory _tokens,
        uint256[] memory _amounts,
        uint256 _nonce,
        bytes memory signature
    ) internal view returns (bool) {
        address _signer = getSigner(
            _account,
            _ids,
            _tokens,
            _amounts,
            _nonce,
            signature
        );
        return _signer == signer;
    }

    /**
     * @dev Internal function to process a claim for a specific ID and token.
     */
    function processClaim(
        uint256 id,
        address token,
        uint256 amount,
        address account
    ) internal {
        TokenBalance storage balanceInfo = idBalances[id];
        require(balanceInfo.token == token, "Token mismatch");
        require(balanceInfo.balance >= amount, "Insufficient ID balance");

        balanceInfo.balance -= amount;
        IERC20(token).safeTransfer(account, amount);

        totalClaims[account][token] += amount;
    }

    /**
     * @dev Claim rewards using a valid signature.
     * @param account The account claiming the rewards.
     * @param ids The list of IDs being claimed.
     * @param tokens The list of token addresses being claimed.
     * @param amounts The list of amounts being claimed.
     * @param signature The EIP712 signature to verify.
     */
    function claim(
        address account,
        uint256[] calldata ids,
        address[] calldata tokens,
        uint256[] calldata amounts,
        bytes calldata signature
    ) external nonReentrant {
        require(account == msg.sender, "Invalid account");
        require(
            tokens.length == amounts.length,
            "Mismatched tokens and amounts"
        );
        require(ids.length == tokens.length, "Mismatched ids and tokens");

        uint256 currentNonce = userNonces[account];
        require(
            verify(account, ids, tokens, amounts, currentNonce, signature),
            "Invalid signature"
        );
        userNonces[account]++;

        for (uint256 i = 0; i < tokens.length; i++) {
            processClaim(ids[i], tokens[i], amounts[i], account);
        }

        emit RewardClaimed(ids, tokens, amounts, account);
    }

    /**
     * @dev Add or remove tokens from the whitelist.
     * @param token The token address to update.
     * @param status Whether to whitelist or remove the token.
     */
    function setTokenWhitelist(address token, bool status) external onlyOwner {
        if (status && !tokenWhitelist[token]) {
            tokenWhitelist[token] = true;
            whitelistedTokens.push(token);
        } else if (!status && tokenWhitelist[token]) {
            tokenWhitelist[token] = false;
            for (uint256 i = 0; i < whitelistedTokens.length; i++) {
                if (whitelistedTokens[i] == token) {
                    whitelistedTokens[i] = whitelistedTokens[
                        whitelistedTokens.length - 1
                    ];
                    whitelistedTokens.pop();
                    break;
                }
            }
        }
    }

    /**
     * @dev Get the list of whitelisted tokens.
     * @return The array of whitelisted token addresses.
     */
    function getWhitelistedTokens() external view returns (address[] memory) {
        return whitelistedTokens;
    }
}
