// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/FakeVault.sol";

contract FakeVaultHarness {
    FakeVault public vault;

    constructor() {
        vault = new FakeVault();
    }

    function fakeInvariantDescription() external pure returns (string memory) {
        return "withdraw should update accounting before handing control away";
    }
}
