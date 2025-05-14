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
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {USSILPToken} from "./USSILPToken.sol";

// import "forge-std/console.sol";

contract USSIV2 is Initializable, UUPSUpgradeable, AccessControlEnumerableUpgradeable, ERC20Upgradeable, PausableUpgradeable {
    // libraries
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using SafeERC20 for IERC20;
    // errors
    error InvalidQuoteToken();
    error InvalidLPTokenOwner();
    error InvalidIssueFee();
    error InvalidMaxFeeRate();
    error InvalidFeeRate();
    error MintSlippageTooLarge();
    error RedeemSlippageTooLarge();
    error InvalidMintToken();
    error InvalidMintQuoteAmount();
    error InvalidRedeemToken();
    error InvalidRedeemAmount();
    error InvalidBurnAmount();
    error InvalidFeeRecipient();
    error InvalidFeeCollectInterval();
    error InvalidRedeemRequestNonce();
    error InvalidRedeemRequestStatus();
    error InvalidRedeemRequestDeadline();
    // events
    event QuoteTokenUpdated(address oldQuoteToken, address newQuoteToken);
    event LPTokenCreated(address lpToken, address lpTokenOwner);
    event IssueFeeUpdated(uint24 oldIssueFee, uint24 newIssueFee);
    event NAVUpdated(uint256 oldNAV, uint256 newNAV);
    event MaxFeeRateUpdated(uint24 oldMaxFeeRate, uint24 newMaxFeeRate);
    event FeeRateUpdated(uint24 oldFeeRate, uint24 newFeeRate);
    event FeeCollected(address[] tokens, uint256[] amounts);
    event FeeBurned(address[] tokens, uint256[] amounts, uint256 fee);
    event LPTokenMinted(address[] tokens, uint256[] amounts, uint256[] mintAmounts);
    event LPTokenRedeemRequested(address[] tokens, USSILPToken.RedeemRequest[] lpTokenRedeemRequests);
    event LPTokenRedeemConfirmed(address[] tokens, USSILPToken.RedeemRequest[] lpTokenRedeemRequests);
    event LPTokenRedeemCanceled(address[] tokens, USSILPToken.RedeemRequest[] lpTokenRedeemRequests);
    event FeeRecipientUpdated(address oldFeeRecipient, address newFeeRecipient);
    event RedeemCooldownUpdated(uint256 oldRedeemCooldown, uint256 newRedeemCooldown);
    event RedeemRequestAdded(RedeemRequest redeemRequest);
    event RedeemRequestConfirmed(RedeemRequest redeemRequest);
    event RedeemRequestCanceled(RedeemRequest redeemRequest);
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
    address public quoteToken;
    address public feeRecipient;
    uint24 public issueFee;
    uint24 public maxFeeRate;
    uint24 public feeRate;
    uint256 public lastFeeCollectTimestamp;
    uint256 private _nav;
    uint256 public redeemCooldown;
    EnumerableSet.AddressSet private lpTokens;
    mapping(address token => uint256 amount) public underlyings;
    mapping(address token => uint256 amount) public fees;
    RedeemRequest[] public redeemRequests;
    uint256 public redeemingQuoteAmount;
    uint256 public redeemingAmount;
    mapping(address token => uint256 amount) public lpTokenRedeemingQuoteAmounts;
    mapping(address token => uint256 amount) public lpTokenRedeemingAmounts;

    function initialize(address _owner, address _feeRecipient, address _quoteToken, uint24 _issueFee, uint24 _maxFeeRate, uint24 _feeRate, uint256 _redeemCooldown) external initializer {
        __UUPSUpgradeable_init();
        __AccessControlEnumerable_init();
        __ERC20_init("USSI", "USSI");
        __Pausable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, _owner);
        _updateFeeRecipient(_feeRecipient);
        _updateQuoteToken(_quoteToken);
        _updateIssueFee(_issueFee);
        _updateMaxFeeRate(_maxFeeRate);
        _updateFeeRate(_feeRate);
        _updateRedeemCooldown(_redeemCooldown);
        lastFeeCollectTimestamp = block.timestamp;
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

    function _updateQuoteToken(address _quoteToken) internal {
        require(_quoteToken != address(0), InvalidQuoteToken());
        emit QuoteTokenUpdated(quoteToken, _quoteToken);
        quoteToken = _quoteToken;
    }

    function _updateIssueFee(uint24 _issueFee) internal {
        require(_issueFee <= FEE_DENOMINATOR, InvalidIssueFee());
        emit IssueFeeUpdated(issueFee, _issueFee);
        issueFee = _issueFee;
    }

    function _updateMaxFeeRate(uint24 _maxFeeRate) internal {
        require(_maxFeeRate <= FEE_DENOMINATOR, InvalidMaxFeeRate());
        emit MaxFeeRateUpdated(maxFeeRate, _maxFeeRate);
        maxFeeRate = _maxFeeRate;
    }

    function _updateFeeRate(uint24 _feeRate) internal {
        require(_feeRate <= maxFeeRate, InvalidFeeRate());
        emit FeeRateUpdated(feeRate, _feeRate);
        feeRate = _feeRate;
    }

    function _updateFeeRecipient(address _feeRecipient) internal {
        require(_feeRecipient != address(0), InvalidFeeRecipient());
        emit FeeRecipientUpdated(feeRecipient, _feeRecipient);
        feeRecipient = _feeRecipient;
    }

    function _updateRedeemCooldown(uint256 _redeemCooldown) internal {
        emit RedeemCooldownUpdated(redeemCooldown, _redeemCooldown);
        redeemCooldown = _redeemCooldown;
    }

    function nav() public view returns (uint256) {
        if (totalSupply() > 0) {
            return tvl() * 10**decimals() / totalSupply();
        } else if (_nav > 0) {
            return _nav;
        } else {
            return 10**decimals();
        }
    }

    function updateConfig(uint24 _feeRate, uint24 _issueFee, address _feeRecipient, uint256 _redeemCooldown) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _updateFeeRate(_feeRate);
        _updateIssueFee(_issueFee);
        _updateFeeRecipient(_feeRecipient);
        _updateRedeemCooldown(_redeemCooldown);
    }

    function getLPTokens() external view returns (address[] memory) {
        return lpTokens.values();
    }

    function getLPTokensLength() external view returns (uint256) {
        return lpTokens.length();
    }

    function getLPTokensAt(uint256 _index) external view returns (address) {
        return lpTokens.at(_index);
    }

    function getUnderlyings() external view returns (address[] memory tokens, uint256[] memory amounts) {
        tokens = new address[](lpTokens.length() + 1);
        amounts = new uint256[](lpTokens.length() + 1);
        tokens[lpTokens.length()] = quoteToken;
        amounts[lpTokens.length()] = underlyings[quoteToken];
        for (uint256 i = 0; i < lpTokens.length(); i++) {
            tokens[i] = lpTokens.at(i);
            amounts[i] = underlyings[lpTokens.at(i)];
        }
    }

    function getFees() external view returns (address[] memory tokens, uint256[] memory amounts) {
        tokens = new address[](lpTokens.length() + 1);
        amounts = new uint256[](lpTokens.length() + 1);
        tokens[lpTokens.length()] = quoteToken;
        amounts[lpTokens.length()] = fees[quoteToken];
        for (uint256 i = 0; i < lpTokens.length(); i++) {
            tokens[i] = lpTokens.at(i);
            amounts[i] = fees[lpTokens.at(i)];
        }
    }

    function createLPToken(address _lpTokenOwner, address _lp, address _vault, uint24 _issueFee, uint256 _redeemCooldown) external onlyRole(DEFAULT_ADMIN_ROLE) {
        string memory _name = string.concat("USSI LP ", Strings.toString(lpTokens.length()));
        string memory _symbol = string.concat("USSILP", Strings.toString(lpTokens.length()));
        require(hasRole(DEFAULT_ADMIN_ROLE, _lpTokenOwner), InvalidLPTokenOwner());
        ERC1967Proxy _lpToken = new ERC1967Proxy(
            address(new USSILPToken()),
            abi.encodeCall(USSILPToken.initialize, (_lpTokenOwner, _name, _symbol, quoteToken, address(this), _lp, _vault, _issueFee, _redeemCooldown))
        );
        lpTokens.add(address(_lpToken));
        emit LPTokenCreated(address(_lpToken), _lpTokenOwner);
    }

    function tvl() public view returns (uint256) {
        uint256 _tvl = underlyings[quoteToken];
        for (uint256 i = 0; i < lpTokens.length(); i++) {
            USSILPToken _lpToken = USSILPToken(lpTokens.at(i));
            if (_lpToken.totalSupply() > 0) {
                _tvl += _lpToken.tvl() * underlyings[lpTokens.at(i)] / _lpToken.totalSupply();
            }
        }
        return _tvl;
    }

    function mint(uint256 quoteAmount, uint256 minAmount) external onlyRole(ISSUER) returns (uint256 amount) {
        _collectFee();
        if (tvl() == 0) {
            amount = quoteAmount * 10**decimals() * (FEE_DENOMINATOR - issueFee) / (nav() * FEE_DENOMINATOR);
        } else {
            amount = quoteAmount * totalSupply() * (FEE_DENOMINATOR - issueFee) / (tvl() * FEE_DENOMINATOR);
        }
        require(amount >= minAmount, MintSlippageTooLarge());
        _mint(msg.sender, amount);
        underlyings[quoteToken] += quoteAmount;
        IERC20(quoteToken).safeTransferFrom(msg.sender, address(this), quoteAmount);
    }

    function addRedeemRequest(uint256 amount, uint256 minQuoteAmount) external onlyRole(ISSUER) returns (RedeemRequest memory request) {
        require(totalSupply() >= amount, InvalidRedeemAmount());
        _collectFee();
        uint256 quoteAmount = amount * tvl() * (FEE_DENOMINATOR - issueFee) / (totalSupply() * FEE_DENOMINATOR);
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
        redeemingAmount += amount;
        redeemingQuoteAmount += quoteAmount;
        _transfer(msg.sender, address(this), amount);
        emit RedeemRequestAdded(request);
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
        if (request.amount == totalSupply()) {
            _nav = tvl() * 10**decimals() / totalSupply();
        }
        _burn(address(this), request.amount);
        underlyings[quoteToken] -= request.quoteAmount;
        redeemingAmount -= request.amount;
        redeemingQuoteAmount -= request.quoteAmount;
        IERC20(quoteToken).safeTransfer(request.requester, request.quoteAmount);
        emit RedeemRequestConfirmed(request);
    }

    function cancelRedeemRequest(uint256 nonce) external onlyRole(ISSUER) returns (RedeemRequest memory request) {
        request = _getAndValidateRedeemRequest(nonce);
        request.status = RedeemRequestStatus.CANCELED;
        redeemRequests[nonce].status = RedeemRequestStatus.CANCELED;
        redeemingAmount -= request.amount;
        redeemingQuoteAmount -= request.quoteAmount;
        _transfer(address(this), request.requester, request.amount);
        emit RedeemRequestCanceled(request);
    }

    function mintLPTokens(address[] calldata mintTokens, uint256[] calldata mintQuoteAmounts, uint256[] calldata minAmounts) external onlyRole(DEFAULT_ADMIN_ROLE) returns (uint256[] memory mintAmounts) {
        _collectFee();
        mintAmounts = new uint256[](mintTokens.length);
        for (uint256 i = 0; i < mintTokens.length; i++) {
            require(lpTokens.contains(mintTokens[i]), InvalidMintToken());
            require(mintQuoteAmounts[i] <= underlyings[quoteToken], InvalidMintQuoteAmount());
            underlyings[quoteToken] -= mintQuoteAmounts[i];
            IERC20(quoteToken).forceApprove(mintTokens[i], mintQuoteAmounts[i]);
            mintAmounts[i] = USSILPToken(mintTokens[i]).mint(mintQuoteAmounts[i], minAmounts[i]);
            underlyings[mintTokens[i]] += mintAmounts[i];
        }
        emit LPTokenMinted(mintTokens, mintQuoteAmounts, mintAmounts);
    }

    function requestRedeemLPTokens(address[] calldata redeemTokens, uint256[] calldata redeemAmounts, uint256[] calldata minQuoteAmounts) external onlyRole(DEFAULT_ADMIN_ROLE) returns (USSILPToken.RedeemRequest[] memory lpTokenRedeemRequests) {
        _collectFee();
        lpTokenRedeemRequests = new USSILPToken.RedeemRequest[](redeemTokens.length);
        for (uint256 i = 0; i < redeemTokens.length; i++) {
            require(lpTokens.contains(redeemTokens[i]), InvalidRedeemToken());
            require(redeemAmounts[i] <= underlyings[redeemTokens[i]], InvalidRedeemAmount());
            lpTokenRedeemRequests[i] = USSILPToken(redeemTokens[i]).addRedeemRequest(redeemAmounts[i], minQuoteAmounts[i]);
            lpTokenRedeemingAmounts[redeemTokens[i]] += lpTokenRedeemRequests[i].amount;
            lpTokenRedeemingQuoteAmounts[redeemTokens[i]] += lpTokenRedeemRequests[i].quoteAmount;
        }
        emit LPTokenRedeemRequested(redeemTokens, lpTokenRedeemRequests);
    }

    function confirmRedeemLPTokens(address[] calldata redeemTokens, uint256[] calldata nonces) external onlyRole(DEFAULT_ADMIN_ROLE) returns (USSILPToken.RedeemRequest[] memory lpTokenRedeemRequests) {
        lpTokenRedeemRequests = new USSILPToken.RedeemRequest[](redeemTokens.length);
        for (uint256 i = 0; i < redeemTokens.length; i++) {
            USSILPToken.RedeemRequest memory request = USSILPToken(redeemTokens[i]).confirmRedeemRequest(nonces[i]);
            lpTokenRedeemingAmounts[redeemTokens[i]] -= request.amount;
            lpTokenRedeemingQuoteAmounts[redeemTokens[i]] -= request.quoteAmount;
            underlyings[quoteToken] += request.quoteAmount;
            underlyings[redeemTokens[i]] -= request.amount;
            lpTokenRedeemRequests[i] = request;
        }
        emit LPTokenRedeemConfirmed(redeemTokens, lpTokenRedeemRequests);
    }

    function cancelRedeemLPTokens(address[] calldata redeemTokens, uint256[] calldata nonces) external onlyRole(DEFAULT_ADMIN_ROLE) returns (USSILPToken.RedeemRequest[] memory lpTokenRedeemRequests) {
        lpTokenRedeemRequests = new USSILPToken.RedeemRequest[](redeemTokens.length);
        for (uint256 i = 0; i < redeemTokens.length; i++) {
            USSILPToken.RedeemRequest memory request = USSILPToken(redeemTokens[i]).cancelRedeemRequest(nonces[i]);
            lpTokenRedeemingAmounts[redeemTokens[i]] -= request.amount;
            lpTokenRedeemingQuoteAmounts[redeemTokens[i]] -= request.quoteAmount;
            lpTokenRedeemRequests[i] = request;
        }
        emit LPTokenRedeemCanceled(redeemTokens, lpTokenRedeemRequests);
    }

    function collectFee() external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(block.timestamp - lastFeeCollectTimestamp >= 1 days, InvalidFeeCollectInterval());
        _collectFee();
    }

    function _collectFee() internal {
        if (block.timestamp - lastFeeCollectTimestamp >= 1 days) {
            uint256 collect_times = (block.timestamp - lastFeeCollectTimestamp) / 1 days;
            lastFeeCollectTimestamp = lastFeeCollectTimestamp + collect_times * 1 days;
            address[] memory feeTokens = new address[](lpTokens.length() + 1);
            uint256[] memory feeAmounts = new uint256[](lpTokens.length() + 1);
            address feeToken = quoteToken;
            uint256 feeAmount = underlyings[feeToken] * feeRate * collect_times / FEE_DENOMINATOR;
            fees[feeToken] += feeAmount;
            underlyings[feeToken] -= feeAmount;
            feeTokens[0] = feeToken;
            feeAmounts[0] = feeAmount;
            for (uint256 i = 0; i < lpTokens.length(); i++) {
                feeToken = lpTokens.at(i);
                feeAmount = (underlyings[feeToken] - lpTokenRedeemingAmounts[feeToken]) * feeRate * collect_times / FEE_DENOMINATOR;
                fees[feeToken] += feeAmount;
                underlyings[feeToken] -= feeAmount;
                feeTokens[i + 1] = feeToken;
                feeAmounts[i + 1] = feeAmount;
            }
            emit FeeCollected(feeTokens, feeAmounts);
        }
    }

    function burnFee(address[] calldata burnTokens, uint256[] calldata burnAmounts, uint256[] calldata minQuoteAmounts) external onlyRole(DEFAULT_ADMIN_ROLE) returns (uint256 fee) {
        for (uint256 i = 0; i < burnTokens.length; i++) {
            require(fees[burnTokens[i]] >= burnAmounts[i], InvalidBurnAmount());
            fees[burnTokens[i]] -= burnAmounts[i];
            if (burnTokens[i] == quoteToken) {
                fee += burnAmounts[i];
            } else {
                fee += USSILPToken(burnTokens[i]).redeem(burnAmounts[i], minQuoteAmounts[i]);
            }
        }
        IERC20(quoteToken).safeTransfer(feeRecipient, fee);
        emit FeeBurned(burnTokens, burnAmounts, fee);
    }
}