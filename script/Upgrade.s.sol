// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {Swap} from "../src/Swap.sol";
import {AssetToken} from "../src/AssetToken.sol";
import {AssetFactory} from "../src/AssetFactory.sol";
import {AssetIssuer} from "../src/AssetIssuer.sol";
import {AssetRebalancer} from "../src/AssetRebalancer.sol";
import {AssetFeeManager} from "../src/AssetFeeManager.sol";
import {StakeFactory} from "../src/StakeFactory.sol";
import {StakeToken} from "../src/StakeToken.sol";
import {AssetLocking} from "../src/AssetLocking.sol";
import {USSI} from "../src/USSI.sol";
import {Upgrades} from "../lib/openzeppelin-foundry-upgrades/src/Upgrades.sol";
import {Options} from "../lib/openzeppelin-foundry-upgrades/src/Options.sol";

contract UpgradeScript is Script {
    function setUp() public {}

    function run() public {
        address owner = vm.envAddress("OWNER");
        string memory chain = vm.envString("CHAIN_CODE");
        address factory = vm.envAddress("ASSET_FACTORY");
        string memory referenceBuildInfoDir = vm.envString("REFER_BUILD_DIR");
        vm.startBroadcast();
        // controller
        Swap swap = new Swap(owner, chain);
        AssetIssuer issuer = new AssetIssuer(owner, address(factory));
        AssetRebalancer rebalancer = new AssetRebalancer(owner, address(factory));
        AssetFeeManager feeManager = new AssetFeeManager(owner, address(factory));
        // impl
        Options memory options;
        options.referenceBuildInfoDir = referenceBuildInfoDir;
        options.referenceContract = "build-info-v1:AssetToken";
        address tokenImpl = Upgrades.deployImplementation("AssetToken.sol:AssetToken", options);
        options.referenceContract = "build-info-v1:AssetFactory";
        address factoryImpl = Upgrades.deployImplementation("AssetFactory.sol:AssetFactory", options);
        options.referenceContract = "build-info-v1:StakeToken";
        address stakeTokenImpl = Upgrades.deployImplementation("StakeToken.sol:StakeToken", options);
        options.referenceContract = "build-info-v1:StakeFactory";
        address stakeFactoryImpl = Upgrades.deployImplementation("StakeFactory.sol:StakeFactory", options);
        options.referenceContract = "build-info-v1:AssetLocking";
        address assetLockingImpl = Upgrades.deployImplementation("AssetLocking.sol:AssetLocking", options);
        options.referenceContract = "build-info-v1:USSI";
        address uSSIImpl = Upgrades.deployImplementation("USSI.sol:USSI", options);
        vm.stopBroadcast();
        // controller
        console.log(string.concat("swap=", vm.toString(address(swap))));
        console.log(string.concat("issuer=", vm.toString(address(issuer))));
        console.log(string.concat("rebalancer=", vm.toString(address(rebalancer))));
        console.log(string.concat("feeManager=", vm.toString(address(feeManager))));
        // impl
        console.log(string.concat("tokenImpl=", vm.toString(address(tokenImpl))));
        console.log(string.concat("factoryImpl=", vm.toString(address(factoryImpl))));
        console.log(string.concat("stakeTokenImpl=", vm.toString(address(stakeTokenImpl))));
        console.log(string.concat("stakeFactoryImpl=", vm.toString(address(stakeFactoryImpl))));
        console.log(string.concat("assetLockingImpl=", vm.toString(address(assetLockingImpl))));
        console.log(string.concat("uSSIImpl=", vm.toString(address(uSSIImpl))));
    }
}
