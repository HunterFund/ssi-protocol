// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.25;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/// @custom:oz-upgrades-from LayoutV1
contract LayoutV2 is Initializable {
    struct Account {
        uint balance;
        string name;
        uint points;
    }

    mapping (address => Account) public accounts;

    function initialize() public initializer {}

    function setAccount(address account, Account memory accountInfo) public {
        accounts[account].balance = accountInfo.balance;
        accounts[account].name = accountInfo.name;
        accounts[account].points = accountInfo.points;
    }
}