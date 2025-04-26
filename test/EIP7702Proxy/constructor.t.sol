// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EIP7702Proxy} from "../../src/EIP7702Proxy.sol";
import {NonceTracker} from "../../src/NonceTracker.sol";
import {DefaultReceiver} from "../../src/DefaultReceiver.sol";

import {EIP7702ProxyBase} from "../base/EIP7702ProxyBase.sol";

contract ConstructorTest is EIP7702ProxyBase {
    function test_succeeds_whenAllArgumentsValid() public {
        new EIP7702Proxy(address(_nonceTracker), address(_receiver));
    }

    function test_reverts_whenNonceTrackerAddressZero() public {
        vm.expectRevert(EIP7702Proxy.ZeroAddress.selector);
        new EIP7702Proxy(address(0), address(_receiver));
    }

    function test_reverts_whenReceiverAddressZero() public {
        vm.expectRevert(EIP7702Proxy.ZeroAddress.selector);
        new EIP7702Proxy(address(_nonceTracker), address(0));
    }
}
