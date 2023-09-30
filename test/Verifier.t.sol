// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {Verifier} from "../src/Verifier.sol";

contract CounterTest is Test {
    Verifier public verifier;

    function setUp() public {
        verifier = new Verifier();
    }

    function test_VerifyExp() public {
        bytes memory q = hex"02";
        bytes memory l = hex"03";
        bytes memory g = hex"02";
        bytes memory r = hex"01";
        bytes memory acc = hex"10";
        bytes memory n = hex"11";

        assertEq(verifier.verifyExp(q, l, g, r, acc, n), true);
    }
}
