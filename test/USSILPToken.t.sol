// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/USSILPToken.sol";
import {Test, console} from "forge-std/Test.sol";
import {MockToken} from "./MockToken.sol";

contract USSILPTokenTest is Test {
    USSILPToken ussiLPToken;
    address owner = vm.addr(0x1);
    address issuer = vm.addr(0x2);
    address lp = vm.addr(0x3);
    address vault = vm.addr(0x4);
    MockToken quoteToken;

    function setUp() public {
        quoteToken = new MockToken("USDC", "USDC", 6);
        deal(address(quoteToken), issuer, 100000*10**6);
        ussiLPToken = USSILPToken(address(
            new ERC1967Proxy(
                address(new USSILPToken()),
                abi.encodeCall(
                    USSILPToken.initialize,
                    (
                        owner,
                        "USSI LP 1",
                        "USSILP1",
                        address(quoteToken),
                        issuer,
                        lp,
                        vault,
                        100, // issueFee
                        1 days // redeemCooldown
                    )
                )
            )
        ));
    }

    function test_initialize() public view {
        assertEq(ussiLPToken.hasRole(ussiLPToken.DEFAULT_ADMIN_ROLE(), owner), true);
        assertEq(ussiLPToken.hasRole(ussiLPToken.ISSUER(), issuer), true);
        assertEq(ussiLPToken.name(), "USSI LP 1");
        assertEq(ussiLPToken.symbol(), "USSILP1");
        assertEq(ussiLPToken.lp(), lp);
        assertEq(ussiLPToken.vault(), vault);
        assertEq(ussiLPToken.quoteToken(), address(quoteToken));
        assertEq(ussiLPToken.tvl(), 0);
        assertEq(ussiLPToken.nav(), 1 * 10**ussiLPToken.decimals());
        assertEq(ussiLPToken.issueFee(), 100);
        assertEq(ussiLPToken.decimals(), 6);
        assertEq(ussiLPToken.redeemCooldown(), 1 days);
    }

    function test_mint() public returns (uint256 mintAmount) {
        uint256 quoteAmount = 10000*10**6;
        uint256 beforeBalance = quoteToken.balanceOf(address(issuer));
        vm.startPrank(issuer);
        quoteToken.approve(address(ussiLPToken), quoteAmount);
        mintAmount = ussiLPToken.mint(quoteAmount, ussiLPToken.quoteMint(quoteAmount));
        vm.stopPrank();
        assertEq(quoteToken.balanceOf(address(issuer)), beforeBalance - quoteAmount);
        assertEq(ussiLPToken.balanceOf(address(issuer)), mintAmount);
        assertEq(ussiLPToken.tvl(), quoteAmount);
        assertEq(ussiLPToken.nav(), 10**6 * 100000 / (100000 - ussiLPToken.issueFee()));
    }

    function test_redeem() public {
        uint256 amount = test_mint();
        uint256 nav = ussiLPToken.nav();
        uint256 beforeBalance = quoteToken.balanceOf(address(issuer));
        vm.startPrank(issuer);
        uint256 quoteAmount = ussiLPToken.redeem(amount, ussiLPToken.quoteRedeem(amount));
        vm.stopPrank();
        assertEq(quoteToken.balanceOf(issuer), beforeBalance + quoteAmount);
        assertEq(ussiLPToken.balanceOf(issuer), 0);
        assertEq(nav, ussiLPToken.nav());
    }

    function test_addRedeemRequest() public {
        uint256 amount = test_mint();
        uint256 quoteAmount = ussiLPToken.quoteRedeem(amount);
        vm.startPrank(issuer);
        USSILPToken.RedeemRequest memory redeemRequest = ussiLPToken.addRedeemRequest(amount, quoteAmount);
        vm.stopPrank();
        assertEq(ussiLPToken.balanceOf(issuer), 0);
        assertEq(ussiLPToken.balanceOf(address(ussiLPToken)), amount);
        assertTrue(redeemRequest.status == USSILPToken.RedeemRequestStatus.PENDING);
        assertEq(redeemRequest.amount, amount);
        assertEq(redeemRequest.quoteAmount, quoteAmount);
        assertEq(redeemRequest.nonce, 0);
        assertEq(redeemRequest.requester, issuer);
        assertEq(redeemRequest.deadline, block.timestamp + ussiLPToken.redeemCooldown());
        assertEq(ussiLPToken.getRedeemRequestLength(), 1);
        redeemRequest = ussiLPToken.getRedeemRequest(0);
        assertTrue(redeemRequest.status == USSILPToken.RedeemRequestStatus.PENDING);
        assertEq(redeemRequest.amount, amount);
        assertEq(redeemRequest.quoteAmount, quoteAmount);
        assertEq(redeemRequest.nonce, 0);
        assertEq(redeemRequest.requester, issuer);
        assertEq(redeemRequest.deadline, block.timestamp + ussiLPToken.redeemCooldown());
    }

    function test_confirmRedeemRequest() public {
        test_addRedeemRequest();
        vm.startPrank(issuer);
        vm.expectRevert(USSILPToken.InvalidRedeemRequestDeadline.selector);
        ussiLPToken.confirmRedeemRequest(0);
        vm.stopPrank();
        vm.warp(block.timestamp + ussiLPToken.redeemCooldown() + 1);
        vm.startPrank(issuer);
        uint256 beforeBalance = quoteToken.balanceOf(address(issuer));
        uint256 beforeTVL = ussiLPToken.tvl();
        uint256 beforeNav = ussiLPToken.nav();
        ussiLPToken.confirmRedeemRequest(0);
        vm.stopPrank();
        USSILPToken.RedeemRequest memory redeemRequest = ussiLPToken.getRedeemRequest(0);
        assertTrue(redeemRequest.status == USSILPToken.RedeemRequestStatus.DONE);
        assertEq(quoteToken.balanceOf(issuer), beforeBalance + redeemRequest.quoteAmount);
        assertEq(ussiLPToken.balanceOf(issuer), 0);
        assertEq(ussiLPToken.balanceOf(address(ussiLPToken)), 0);
        assertEq(ussiLPToken.tvl(), beforeTVL - redeemRequest.quoteAmount);
        if (ussiLPToken.totalSupply() == 0) {
            assertEq(ussiLPToken.nav(), beforeNav);
        } else {
            assertEq(ussiLPToken.nav(), (beforeTVL - redeemRequest.quoteAmount) / ussiLPToken.totalSupply());
        }
    }

    function test_cancelRedeemRequest() public {
        test_addRedeemRequest();
        vm.startPrank(issuer);
        vm.expectRevert(USSILPToken.InvalidRedeemRequestDeadline.selector);
        ussiLPToken.cancelRedeemRequest(0);
        vm.stopPrank();
        vm.warp(block.timestamp + ussiLPToken.redeemCooldown() + 1);
        vm.startPrank(issuer);
        uint256 beforeBalance = quoteToken.balanceOf(address(issuer));
        ussiLPToken.cancelRedeemRequest(0);
        vm.stopPrank();
        USSILPToken.RedeemRequest memory redeemRequest = ussiLPToken.getRedeemRequest(0);
        assertTrue(redeemRequest.status == USSILPToken.RedeemRequestStatus.CANCELED);
        assertEq(ussiLPToken.balanceOf(issuer), redeemRequest.amount);
        assertEq(ussiLPToken.balanceOf(address(ussiLPToken)), 0);
        assertEq(quoteToken.balanceOf(issuer), beforeBalance);
    }

    function test_withdrawAll() public {
        test_mint();
        uint256 beforeBalance = quoteToken.balanceOf(address(vault));
        vm.startPrank(lp);
        uint256 withdrawAmount = ussiLPToken.withdrawAll();
        vm.stopPrank();
        assertEq(quoteToken.balanceOf(address(vault)), beforeBalance + withdrawAmount);
    }

    function test_updateTVL() public {
        test_withdrawAll();
        vm.startPrank(owner);
        deal(address(quoteToken), address(vault), quoteToken.balanceOf(address(vault)) - 10*10**6);
        bytes32 lastUpdateID = ussiLPToken.lastUpdateID();
        uint256 bufferTVL = quoteToken.balanceOf(address(ussiLPToken));
        uint256 tvl = bufferTVL + quoteToken.balanceOf(address(vault));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0x3, keccak256(abi.encode(lastUpdateID, bufferTVL, tvl)));
        bytes memory signature = abi.encodePacked(r, s, v);
        ussiLPToken.updateTVL(lastUpdateID, bufferTVL, tvl, signature);
        vm.stopPrank();
        assertEq(ussiLPToken.tvl(), tvl);
        assertEq(ussiLPToken.nav(), 10**6);
    }
}