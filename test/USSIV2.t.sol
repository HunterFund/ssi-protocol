// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {USSIV2, USSILPToken} from "../src/USSIV2.sol";
import {Test, console} from "forge-std/Test.sol";
import {MockToken} from "./MockToken.sol";

contract USSIV2Test is Test {
    USSIV2 ussi;
    address owner = vm.addr(0x1);
    address issuer = vm.addr(0x2);
    address lp = vm.addr(0x3);
    address feeRecipient = vm.addr(0x4);
    address lpVault = vm.addr(0x5);
    MockToken quoteToken;

    function setUp() public {
        quoteToken = new MockToken("USDC", "USDC", 6);
        deal(address(quoteToken), issuer, 100000 * 10**6);
        
        ussi = USSIV2(address(
            new ERC1967Proxy(
                address(new USSIV2()),
                abi.encodeCall(
                    USSIV2.initialize,
                    (
                        owner,      // owner
                        feeRecipient,      // feeRecipient
                        address(quoteToken), // quoteToken
                        100,         // issueFee
                        100,       // maxFeeRate
                        10,        // feeRate
                        1 days     // redeemCooldown
                    )
                )
            )
        ));

        vm.startPrank(owner);
        ussi.grantRole(ussi.ISSUER(), issuer);
        vm.stopPrank();
    }

    function test_initialize() public view {
        assertEq(ussi.hasRole(ussi.DEFAULT_ADMIN_ROLE(), owner), true);
        assertEq(ussi.hasRole(ussi.ISSUER(), issuer), true);
        assertEq(ussi.name(), "USSI");
        assertEq(ussi.symbol(), "USSI");
        assertEq(ussi.quoteToken(), address(quoteToken));
        assertEq(ussi.feeRecipient(), feeRecipient);
        assertEq(ussi.issueFee(), 100);
        assertEq(ussi.maxFeeRate(), 100);
        assertEq(ussi.feeRate(), 10);
        assertEq(ussi.nav(), 10**6);
        assertEq(ussi.decimals(), 6);
        assertEq(ussi.redeemCooldown(), 1 days);
    }

    function test_createLPToken() public returns (USSILPToken lpToken) {
        vm.startPrank(owner);
        ussi.createLPToken(
            owner,          // lpTokenOwner
            lp,            // lp
            lpVault,         // vault
            100,            // issueFee
            1 days // redeemCooldown
        );
        vm.stopPrank();

        assertEq(ussi.getLPTokensLength(), 1);
        lpToken = USSILPToken(ussi.getLPTokensAt(0));
        assertEq(lpToken.name(), "USSI LP 0");
        assertEq(lpToken.symbol(), "USSILP0");
        assertEq(lpToken.hasRole(lpToken.DEFAULT_ADMIN_ROLE(), owner), true);
        assertEq(lpToken.vault(), lpVault);
        assertEq(lpToken.quoteToken(), address(quoteToken));
        assertEq(lpToken.issueFee(), 100);
        assertEq(lpToken.redeemCooldown(), 1 days);
    }

    function test_mint() public returns (uint256 mintAmount) {
        USSILPToken lpToken = test_createLPToken();
        uint256 quoteAmount = 10000 * 10**6;
        uint256 beforeBalance = quoteToken.balanceOf(issuer);

        vm.startPrank(issuer);
        quoteToken.approve(address(ussi), quoteAmount);
        mintAmount = ussi.mint(quoteAmount, 0);
        vm.stopPrank();

        assertEq(quoteToken.balanceOf(issuer), beforeBalance - quoteAmount);
        assertEq(ussi.balanceOf(issuer), mintAmount);
        assertEq(ussi.tvl(), quoteAmount);
        assertEq(ussi.nav(), 10**6 * uint256(ussi.FEE_DENOMINATOR()) / (uint256(ussi.FEE_DENOMINATOR()) - uint256(ussi.issueFee())));
        (address[] memory underlyings, uint256[] memory amounts) = ussi.getUnderlyings();
        assertEq(underlyings.length, 2);
        assertEq(underlyings[0], address(lpToken));
        assertEq(amounts[0], 0);
        assertEq(underlyings[1], address(quoteToken));
        assertEq(amounts[1], quoteAmount);
        assertEq(lpToken.totalSupply(), 0);
        assertEq(lpToken.tvl(), 0);
        assertEq(lpToken.nav(), 10**6);
    }

    function test_mintLPTokens() public {
        test_mint();

        uint256 beforeTVL = ussi.tvl();
        uint256 beforeNav = ussi.nav();
        uint256 beforeSupply = ussi.totalSupply();
        vm.startPrank(owner);
        address[] memory mintTokens = ussi.getLPTokens();
        uint256[] memory mintQuoteAmounts = new uint256[](1);
        (address[] memory underlyings, uint256[] memory amounts) = ussi.getUnderlyings();
        mintQuoteAmounts[0] = amounts[1] / 2;
        uint256[] memory minAmounts = new uint256[](1);
        minAmounts[0] = USSILPToken(underlyings[0]).quoteMint(mintQuoteAmounts[0]);
        uint256[] memory mintAmounts = ussi.mintLPTokens(mintTokens, mintQuoteAmounts, minAmounts);
        vm.stopPrank();

        USSILPToken lpToken = USSILPToken(mintTokens[0]);
        assertEq(lpToken.totalSupply(), mintAmounts[0]);
        assertEq(lpToken.tvl(), mintQuoteAmounts[0]);
        assertEq(lpToken.nav(), 10**6 * uint256(lpToken.FEE_DENOMINATOR()) / (uint256(lpToken.FEE_DENOMINATOR()) - uint256(lpToken.issueFee())));

        assertEq(ussi.totalSupply(), beforeSupply);
        assertEq(ussi.tvl(), beforeTVL);
        assertEq(ussi.nav(), beforeNav);
        (address[] memory underlyingsAfter, uint256[] memory amountsAfter) = ussi.getUnderlyings();
        assertEq(underlyingsAfter.length, 2);
        assertEq(underlyingsAfter[0], address(lpToken));
        assertEq(amountsAfter[0], mintAmounts[0]);
        assertEq(underlyingsAfter[1], address(quoteToken));
        assertEq(amountsAfter[1], amounts[1] - mintQuoteAmounts[0]);
    }

    function test_addRedeemRequest() public {
        test_mintLPTokens();

        uint256 amount = 6000 * 10**6;
        vm.startPrank(issuer);
        USSIV2.RedeemRequest memory request = ussi.addRedeemRequest(amount, 0);
        vm.stopPrank();

        assertEq(ussi.getRedeemRequestLength(), 1);
        USSIV2.RedeemRequest memory savedRequest = ussi.getRedeemRequest(0);
        assertEq(savedRequest.nonce, request.nonce);
        assertTrue(savedRequest.status == request.status);
        assertEq(savedRequest.requester, request.requester);
        assertEq(savedRequest.amount, request.amount);
        assertEq(savedRequest.quoteAmount, request.quoteAmount);
        assertEq(savedRequest.deadline, request.deadline);

        assertEq(request.nonce, 0);
        assertTrue(request.status == USSIV2.RedeemRequestStatus.PENDING);
        assertEq(request.requester, issuer);
        assertEq(request.amount, amount);
        assertEq(request.quoteAmount, amount * ussi.tvl() * (uint256(ussi.FEE_DENOMINATOR()) - uint256(ussi.issueFee())) / (ussi.totalSupply() * uint256(ussi.FEE_DENOMINATOR())));
        assertEq(request.deadline, block.timestamp + ussi.redeemCooldown());
    }

    function test_requestRedeemLPTokens() public returns (address[] memory redeemTokens, USSILPToken.RedeemRequest[] memory lpTokenRedeemRequests) {
        test_addRedeemRequest();

        uint256 targetQuoteAmount = ussi.redeemingQuoteAmount();
        uint256 liquidity = ussi.underlyings(address(quoteToken));
        uint256 redeemingLiquidity = 0;
        for (uint256 i = 0; i < ussi.getLPTokensLength(); i++) {
            redeemingLiquidity += ussi.lpTokenRedeemingQuoteAmounts(ussi.getLPTokensAt(i));
        }
        liquidity += redeemingLiquidity;
        if (liquidity < targetQuoteAmount) {
            targetQuoteAmount -= liquidity;
            address[] memory previewRedeemTokens = ussi.getLPTokens();
            uint256[] memory previewRedeemAmounts = new uint256[](previewRedeemTokens.length);
            uint256[] memory previewMinQuoteAmounts = new uint256[](previewRedeemTokens.length);
            uint256 actualRedeemTokenLength = 0;
            for (uint256 i = 0; i < ussi.getLPTokensLength(); i++) {
                actualRedeemTokenLength += 1;
                USSILPToken lpToken = USSILPToken(ussi.getLPTokensAt(i));
                previewRedeemAmounts[i] = ussi.underlyings(address(lpToken)) - ussi.lpTokenRedeemingAmounts(address(lpToken));
                previewMinQuoteAmounts[i] = lpToken.quoteRedeem(previewRedeemAmounts[i]);
                if (previewMinQuoteAmounts[i] > targetQuoteAmount) {
                    previewRedeemAmounts[i] = targetQuoteAmount * previewRedeemAmounts[i] / previewMinQuoteAmounts[i];
                    previewMinQuoteAmounts[i] = targetQuoteAmount;
                    break;
                }
                targetQuoteAmount -= previewMinQuoteAmounts[i];
            }
            redeemTokens = new address[](actualRedeemTokenLength);
            uint256[] memory redeemAmounts = new uint256[](actualRedeemTokenLength);
            uint256[] memory minQuoteAmounts = new uint256[](actualRedeemTokenLength);
            for (uint256 i = 0; i < actualRedeemTokenLength; i++) {
                redeemTokens[i] = previewRedeemTokens[i];
                redeemAmounts[i] = previewRedeemAmounts[i];
                minQuoteAmounts[i] = previewMinQuoteAmounts[i];
            }
            uint256 beforeTVL = ussi.tvl();
            vm.startPrank(owner);
            lpTokenRedeemRequests = ussi.requestRedeemLPTokens(redeemTokens, redeemAmounts, minQuoteAmounts);
            vm.stopPrank();
            uint256 redeemingLiquidityAdded = 0;
            for (uint256 i = 0; i < lpTokenRedeemRequests.length; i++) {
                assertTrue(lpTokenRedeemRequests[i].status == USSILPToken.RedeemRequestStatus.PENDING);
                assertEq(lpTokenRedeemRequests[i].requester, address(ussi));
                assertEq(lpTokenRedeemRequests[i].amount, redeemAmounts[i]);
                assertEq(lpTokenRedeemRequests[i].quoteAmount, minQuoteAmounts[i]);
                assertEq(lpTokenRedeemRequests[i].deadline, block.timestamp + USSILPToken(redeemTokens[i]).redeemCooldown());
                redeemingLiquidityAdded += lpTokenRedeemRequests[i].quoteAmount;
            }
            uint256 redeemingLiquidityAfter = 0;
            for (uint256 i = 0; i < ussi.getLPTokensLength(); i++) {
                redeemingLiquidityAfter += ussi.lpTokenRedeemingQuoteAmounts(ussi.getLPTokensAt(i));
            }
            assertEq(redeemingLiquidityAfter, redeemingLiquidity + redeemingLiquidityAdded);
            assertEq(ussi.tvl(), beforeTVL);
        }
    }

    function test_confirmRedeemLPTokens() public {
        (address[] memory redeemTokens, USSILPToken.RedeemRequest[] memory lpTokenRedeemRequests) = test_requestRedeemLPTokens();

        uint256[] memory nonces = new uint256[](lpTokenRedeemRequests.length);
        for (uint256 i = 0; i < lpTokenRedeemRequests.length; i++) {
            nonces[i] = lpTokenRedeemRequests[i].nonce;
        }
        vm.startPrank(owner);
        vm.expectRevert(USSILPToken.InvalidRedeemRequestDeadline.selector);
        ussi.confirmRedeemLPTokens(redeemTokens, nonces);
        vm.stopPrank();

        uint256 redeemingLiquidityBefore = 0;
        for (uint256 i = 0; i < redeemTokens.length; i++) {
            redeemingLiquidityBefore += ussi.lpTokenRedeemingQuoteAmounts(redeemTokens[i]);
        }
        uint256 beforeTVL = ussi.tvl();

        uint256 maxRedeemCooldown = 0;
        for (uint256 i = 0; i < redeemTokens.length; i++) {
            uint256 redeemCooldown = USSILPToken(redeemTokens[i]).redeemCooldown();
            if (redeemCooldown > maxRedeemCooldown) {
                maxRedeemCooldown = redeemCooldown;
            }
        }

        vm.warp(block.timestamp + maxRedeemCooldown + 1);
        vm.startPrank(owner);
        lpTokenRedeemRequests = ussi.confirmRedeemLPTokens(redeemTokens, nonces);
        vm.stopPrank();

        uint256 redeemingLiquidityAfter = 0;
        uint256 redeemingLiquidityRemoved = 0;
        for (uint256 i = 0; i < lpTokenRedeemRequests.length; i++) {
            assertTrue(lpTokenRedeemRequests[i].status == USSILPToken.RedeemRequestStatus.DONE);
            redeemingLiquidityAfter += ussi.lpTokenRedeemingQuoteAmounts(redeemTokens[i]);
            redeemingLiquidityRemoved += lpTokenRedeemRequests[i].quoteAmount;
        }
        assertEq(redeemingLiquidityAfter, redeemingLiquidityBefore - redeemingLiquidityRemoved);
        assertEq(ussi.tvl(), beforeTVL);
    }

    function test_cancelRedeemLPTokens() public {
        (address[] memory redeemTokens, USSILPToken.RedeemRequest[] memory lpTokenRedeemRequests) = test_requestRedeemLPTokens();

        uint256[] memory nonces = new uint256[](lpTokenRedeemRequests.length);
        for (uint256 i = 0; i < lpTokenRedeemRequests.length; i++) {
            nonces[i] = lpTokenRedeemRequests[i].nonce;
        }
        vm.startPrank(owner);
        vm.expectRevert(USSILPToken.InvalidRedeemRequestDeadline.selector);
        lpTokenRedeemRequests = ussi.cancelRedeemLPTokens(redeemTokens, nonces);
        vm.stopPrank();

        uint256 redeemingLiquidityBefore = 0;
        for (uint256 i = 0; i < redeemTokens.length; i++) {
            redeemingLiquidityBefore += ussi.lpTokenRedeemingQuoteAmounts(redeemTokens[i]);
        }
        uint256 beforeTVL = ussi.tvl();

        uint256 maxRedeemCooldown = 0;
        for (uint256 i = 0; i < redeemTokens.length; i++) {
            uint256 redeemCooldown = USSILPToken(redeemTokens[i]).redeemCooldown();
            if (redeemCooldown > maxRedeemCooldown) {
                maxRedeemCooldown = redeemCooldown;
            }
        }

        vm.warp(block.timestamp + maxRedeemCooldown + 1);
        vm.startPrank(owner);
        lpTokenRedeemRequests = ussi.cancelRedeemLPTokens(redeemTokens, nonces);
        vm.stopPrank(); 

        uint256 redeemingLiquidityAfter = 0;
        uint256 redeemingLiquidityRemoved = 0;
        for (uint256 i = 0; i < lpTokenRedeemRequests.length; i++) {
            assertTrue(lpTokenRedeemRequests[i].status == USSILPToken.RedeemRequestStatus.CANCELED);
            redeemingLiquidityAfter += ussi.lpTokenRedeemingQuoteAmounts(redeemTokens[i]);
            redeemingLiquidityRemoved += lpTokenRedeemRequests[i].quoteAmount;
        }
        assertEq(redeemingLiquidityAfter, redeemingLiquidityBefore - redeemingLiquidityRemoved);
        assertEq(ussi.tvl(), beforeTVL);
    }

    function test_confirmRedeemRequest() public {
        test_confirmRedeemLPTokens();

        uint256 beforeBalance = quoteToken.balanceOf(issuer);
        uint256 beforeUSSIBalance = ussi.balanceOf(address(ussi));
        uint256 beforeTVL = ussi.tvl();
        uint256 beforeTotalSupply = ussi.totalSupply();

        vm.startPrank(issuer);
        ussi.confirmRedeemRequest(0);
        vm.stopPrank();

        USSIV2.RedeemRequest memory redeemRequest = ussi.getRedeemRequest(0);
        assertTrue(redeemRequest.status == USSIV2.RedeemRequestStatus.DONE);
        assertEq(quoteToken.balanceOf(issuer), beforeBalance + redeemRequest.quoteAmount);
        assertEq(ussi.balanceOf(address(ussi)), beforeUSSIBalance - redeemRequest.amount);
        assertEq(ussi.totalSupply(), beforeTotalSupply - redeemRequest.amount);
        assertEq(ussi.tvl(), beforeTVL - redeemRequest.quoteAmount);
    }

    function test_cancelRedeemRequest() public {
        test_confirmRedeemLPTokens();

        uint256 beforeBalance = quoteToken.balanceOf(issuer);
        uint256 beforeUSSIBalance = ussi.balanceOf(issuer);
        uint256 beforeTVL = ussi.tvl();
        uint256 beforeTotalSupply = ussi.totalSupply();

        vm.startPrank(issuer);
        ussi.cancelRedeemRequest(0);
        vm.stopPrank();

        USSIV2.RedeemRequest memory redeemRequest = ussi.getRedeemRequest(0);
        assertTrue(redeemRequest.status == USSIV2.RedeemRequestStatus.CANCELED);
        assertEq(quoteToken.balanceOf(issuer), beforeBalance);
        assertEq(ussi.balanceOf(issuer), beforeUSSIBalance + redeemRequest.amount);
        assertEq(ussi.totalSupply(), beforeTotalSupply);
        assertEq(ussi.tvl(), beforeTVL);
    }

    function test_collectFee() public {
        test_mintLPTokens();

        vm.startPrank(owner);
        vm.expectRevert(USSIV2.InvalidFeeCollectInterval.selector);
        ussi.collectFee();
        vm.stopPrank();

        (address[] memory underlyings, uint256[] memory amounts) = ussi.getUnderlyings();
        uint256 beforeNav = ussi.nav();
        uint256 beforeTVL = ussi.tvl();
        vm.warp(block.timestamp + 1 days);
        vm.startPrank(owner);
        ussi.collectFee();
        vm.stopPrank();

        (address[] memory tokens, uint256[] memory feeAmounts) = ussi.getFees();
        (address[] memory underlyingsAfter, uint256[] memory amountsAfter) = ussi.getUnderlyings();
        assertEq(tokens.length, 2);
        assertEq(feeAmounts.length, 2);
        for (uint256 i = 0; i < tokens.length; i++) {
            assertEq(tokens[i], underlyings[i]);
            assertEq(feeAmounts[i], amounts[i] * ussi.feeRate() / ussi.FEE_DENOMINATOR());
            assertEq(underlyingsAfter[i], underlyings[i]);
            assertEq(amountsAfter[i], amounts[i] - feeAmounts[i]);
        }
        assertEq(ussi.nav(), beforeNav * (uint256(ussi.FEE_DENOMINATOR()) - uint256(ussi.feeRate())) / uint256(ussi.FEE_DENOMINATOR()));
        assertEq(ussi.tvl(), beforeTVL * (uint256(ussi.FEE_DENOMINATOR()) - uint256(ussi.feeRate())) / uint256(ussi.FEE_DENOMINATOR()));
    }

    function test_burnFee() public {
        test_collectFee();

        (address[] memory burnTokens, uint256[] memory burnAmounts) = ussi.getFees();
        uint256[] memory minQuoteAmounts = new uint256[](burnTokens.length);
        for (uint256 i = 0; i < burnTokens.length; i++) {
            if (burnTokens[i] == address(quoteToken)) {
                minQuoteAmounts[i] = burnAmounts[i];
            } else {
                minQuoteAmounts[i] = USSILPToken(burnTokens[i]).quoteRedeem(burnAmounts[i]);
            }
        }

        uint256 beforeBalance = quoteToken.balanceOf(feeRecipient);
        vm.startPrank(owner);
        uint256 fee = ussi.burnFee(burnTokens, burnAmounts, minQuoteAmounts);
        vm.stopPrank();

        assertEq(quoteToken.balanceOf(feeRecipient), beforeBalance + fee);
    }
}
