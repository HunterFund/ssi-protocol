// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.25;
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {AccessControlEnumerableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

// import "forge-std/console.sol";

contract USSILPToken is Initializable, UUPSUpgradeable, AccessControlEnumerableUpgradeable, ERC20Upgradeable, PausableUpgradeable {
    // libraries
    using SafeERC20 for IERC20;
    // errors
    error InvalidLP();
    error InvalidVault();
    error InvalidQuoteToken();
    error InvalidTVL();
    error InvalidNAV();
    error InvalidIssueFee();
    error InvalidUpdateID();
    error MissMatchBufferTVL();
    error InvalidTVLSignature();
    error MintSlippageTooLarge();
    error RedeemSlippageTooLarge();
    error InvalidRedeemAmount();
    error InvalidWithdrawer();
    error InvalidWithdrawAmount();
    error InvalidWithdrawal();
    error InvalidLPConfigSignature();
    error InvalidRedeemRequestNonce();
    error InvalidRedeemRequestStatus();
    error InvalidRedeemRequestDeadline();
    // events
    event LPUpdated(address oldLP, address newLP);
    event VaultUpdated(address oldVault, address newVault);
    event QuoteTokenUpdated(address oldQuoteToken, address newQuoteToken);
    event TVLUpdated(uint256 oldTVL, uint256 newTVL, bytes32 oldUpdateID, bytes32 newUpdateID);
    event NAVUpdated(uint256 oldNAV, uint256 newNAV);
    event IssueFeeUpdated(uint24 oldIssueFee, uint24 newIssueFee);
    event Withdrawal(uint256 amount);
    event RedeemRequestAdded(RedeemRequest request);
    event RedeemRequestConfirmed(RedeemRequest request);
    event RedeemRequestCanceled(RedeemRequest request);
    event RedeemCooldownUpdated(uint256 oldRedeemCooldown, uint256 newRedeemCooldown);
    // constants
    bytes32 public constant ISSUER = keccak256("ISSUER");
    uint24 public constant FEE_DENOMINATOR = 100000;
    // enums
    enum RedeemRequestStatus { NONE, PENDING, DONE, CANCELED }
    // structs
    struct RedeemRequest {
        uint256 nonce;
        RedeemRequestStatus status;
        address requester;
        uint256 amount;
        uint256 quoteAmount;
        uint256 deadline;
    }
    // state
    address public lp;
    address public vault;
    address public quoteToken;
    uint256 public tvl;
    uint256 public nav;
    bytes32 public lastUpdateID;
    uint24 public issueFee;
    uint256 public redeemCooldown;
    RedeemRequest[] public redeemRequests;


    function initialize(address _owner, string memory _name, string memory _symbol, address _quoteToken, address _issuer, address _lp, address _vault, uint24 _issueFee, uint256 _redeemCooldown) external initializer {
        __UUPSUpgradeable_init();
        __AccessControlEnumerable_init();
        __ERC20_init(_name, _symbol);
        __Pausable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, _owner);
        _grantRole(ISSUER, _issuer);
        _updateQuoteToken(_quoteToken);
        _updateLP(_lp);
        _updateVault(_vault);
        _updateIssueFee(_issueFee);
        _updateTVL(lastUpdateID, 0);
        _updateNAV(10**decimals());
        _updateRedeemCooldown(_redeemCooldown);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function decimals() public view override(ERC20Upgradeable) returns (uint8) {
        return IERC20Metadata(quoteToken).decimals();
    }

    function _updateLP(address _lp) internal {
        require(_lp != address(0), InvalidLP());
        emit LPUpdated(lp, _lp);
        lp = _lp;
    }

    function _updateVault(address _vault) internal {
        require(_vault != address(0), InvalidVault());
        emit VaultUpdated(vault, _vault);
        vault = _vault;
    }

    function _updateQuoteToken(address _quoteToken) internal {
        require(_quoteToken != address(0), InvalidQuoteToken());
        emit QuoteTokenUpdated(quoteToken, _quoteToken);
        quoteToken = _quoteToken;
    }

    function _updateTVL(bytes32 _lastUpdateID, uint256 _tvl) internal {
        require(_lastUpdateID == lastUpdateID, InvalidUpdateID());
        bytes32 updateID = keccak256(abi.encode(lastUpdateID, tvl, block.timestamp));
        emit TVLUpdated(tvl, _tvl, lastUpdateID, updateID);
        lastUpdateID = updateID;
        tvl = _tvl;
        if (totalSupply() > 0) {
            _updateNAV(tvl * 10**decimals() / totalSupply());
        }
    }

    function _updateNAV(uint256 _nav) internal {
        require(_nav > 0, InvalidNAV());
        emit NAVUpdated(nav, _nav);
        nav = _nav;
    }

    function _updateIssueFee(uint24 _issueFee) internal {
        require(_issueFee <= FEE_DENOMINATOR, InvalidIssueFee());
        emit IssueFeeUpdated(issueFee, _issueFee);
        issueFee = _issueFee;
    }

    function _updateRedeemCooldown(uint256 _redeemCooldown) internal {
        emit RedeemCooldownUpdated(redeemCooldown, _redeemCooldown);
        redeemCooldown = _redeemCooldown;
    }

    function updateLPConfig(address _lp, address _vault, uint24 _issueFee, uint256 _redeemCooldown, bytes calldata _signature) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(SignatureChecker.isValidSignatureNow(lp, keccak256(abi.encode(lp, vault, issueFee, redeemCooldown)), _signature), InvalidLPConfigSignature());
        _updateLP(_lp);
        _updateVault(_vault);
        _updateIssueFee(_issueFee);
        _updateRedeemCooldown(_redeemCooldown);
    }

    function quoteMint(uint256 quoteAmount) public view returns (uint256) {
        if (tvl == 0) {
            return quoteAmount * 10**decimals() * (FEE_DENOMINATOR - issueFee) / (nav * FEE_DENOMINATOR);
        } else {
            return quoteAmount * totalSupply() * (FEE_DENOMINATOR - issueFee) / (tvl * FEE_DENOMINATOR);
        }
    }

    function quoteRedeem(uint256 amount) public view returns (uint256) {
        require(totalSupply() >= amount, InvalidRedeemAmount());
        return amount * tvl * (FEE_DENOMINATOR - issueFee) / (totalSupply() * FEE_DENOMINATOR);
    }

    function mint(uint256 quoteAmount, uint256 minAmount) external onlyRole(ISSUER) returns (uint256) {
        uint256 amount = quoteMint(quoteAmount);
        require(amount >= minAmount, MintSlippageTooLarge());
        _mint(msg.sender, amount);
        _updateTVL(lastUpdateID, tvl + quoteAmount);
        IERC20(quoteToken).safeTransferFrom(msg.sender, address(this), quoteAmount);
        return amount;
    }

    function redeem(uint256 amount, uint256 minQuoteAmount) external onlyRole(ISSUER) returns (uint256) {
        require(amount > 0, InvalidRedeemAmount());
        uint256 quoteAmount = quoteRedeem(amount);
        require(quoteAmount >= minQuoteAmount, RedeemSlippageTooLarge());
        _burn(msg.sender, amount);
        _updateTVL(lastUpdateID, tvl - quoteAmount);
        IERC20(quoteToken).safeTransfer(msg.sender, quoteAmount);
        return quoteAmount;
    }

    function addRedeemRequest(uint256 amount, uint256 minQuoteAmount) external onlyRole(ISSUER) returns (RedeemRequest memory request) {
        uint256 quoteAmount = quoteRedeem(amount);
        require(quoteAmount >= minQuoteAmount, RedeemSlippageTooLarge());
        request = RedeemRequest({
            nonce: redeemRequests.length,
            status: RedeemRequestStatus.PENDING,
            requester: msg.sender,
            amount: amount,
            quoteAmount: quoteAmount,
            deadline: block.timestamp + redeemCooldown
        });
        redeemRequests.push(request);
        emit RedeemRequestAdded(request);
        _transfer(msg.sender, address(this), amount);
    }

    function getRedeemRequest(uint256 nonce) external view returns (RedeemRequest memory request) {
        require(redeemRequests.length > nonce, InvalidRedeemRequestNonce());
        request = redeemRequests[nonce];
    }

    function getRedeemRequestLength() external view returns (uint256) {
        return redeemRequests.length;
    }

    function _getAndValidateRedeemRequest(uint256 nonce) internal view returns (RedeemRequest memory request) {
        require(redeemRequests.length > nonce, InvalidRedeemRequestNonce());
        request = redeemRequests[nonce];
        require(request.status == RedeemRequestStatus.PENDING, InvalidRedeemRequestStatus());
        require(request.deadline < block.timestamp, InvalidRedeemRequestDeadline());
    }

    function confirmRedeemRequest(uint256 nonce) external onlyRole(ISSUER) returns (RedeemRequest memory request) {
        request = _getAndValidateRedeemRequest(nonce);
        request.status = RedeemRequestStatus.DONE;
        redeemRequests[nonce].status = RedeemRequestStatus.DONE;
        _burn(address(this), request.amount);
        _updateTVL(lastUpdateID, tvl - request.quoteAmount);
        IERC20(quoteToken).safeTransfer(request.requester, request.quoteAmount);
        emit RedeemRequestConfirmed(request);
        return request;
    }

    function cancelRedeemRequest(uint256 nonce) external onlyRole(ISSUER) returns (RedeemRequest memory request) {
        request = _getAndValidateRedeemRequest(nonce);
        request.status = RedeemRequestStatus.CANCELED;
        redeemRequests[nonce].status = RedeemRequestStatus.CANCELED;
        _transfer(address(this), request.requester, request.amount);
        emit RedeemRequestCanceled(request);
        return request;
    }

    function withdraw(uint256 quoteAmount) external {
        require(msg.sender == lp, InvalidWithdrawer());
        require(quoteAmount > 0, InvalidWithdrawAmount());
        require(quoteAmount <= IERC20(quoteToken).balanceOf(address(this)), InvalidWithdrawal());
        IERC20(quoteToken).safeTransfer(vault, quoteAmount);
        emit Withdrawal(quoteAmount);
    }

    function withdrawAll() external returns (uint256 withdrawAmount) {
        require(msg.sender == lp, InvalidWithdrawer());
        require(IERC20(quoteToken).balanceOf(address(this)) > 0, InvalidWithdrawal());
        withdrawAmount = IERC20(quoteToken).balanceOf(address(this));
        IERC20(quoteToken).safeTransfer(vault, withdrawAmount);
        emit Withdrawal(withdrawAmount);
    }

    function updateTVL(bytes32 _lastUpdateID, uint256 _bufferTVL, uint256 _tvl, bytes calldata _signature) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_bufferTVL == IERC20(quoteToken).balanceOf(address(this)), MissMatchBufferTVL());
        require(_tvl >= _bufferTVL + IERC20(quoteToken).balanceOf(vault), InvalidTVL());
        require(SignatureChecker.isValidSignatureNow(lp, keccak256(abi.encode(_lastUpdateID, _bufferTVL, _tvl)), _signature), InvalidTVLSignature());
        _updateTVL(_lastUpdateID, _tvl);
    }
}