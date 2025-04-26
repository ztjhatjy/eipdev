// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IAccountStateValidator} from "../../src/interfaces/IAccountStateValidator.sol";

/// @title MockInvalidValidator
/// @dev Mock validator that returns an invalid magic value for testing
contract MockInvalidValidator is IAccountStateValidator {

    function isValidSignature(bytes32 hash, bytes calldata signature) external returns (bytes4) {
        // Delegatecall to implementation with received data
        (bool success, bytes memory result) = _implementation().delegatecall(msg.data);

        // Early return magic value if delegatecall returned magic value
        if (success && result.length == 32 && bytes4(result) == _ERC1271_MAGIC_VALUE) {
            return _ERC1271_MAGIC_VALUE;
        }

        // Validate signature against EOA as fallback
        (address recovered, ECDSA.RecoverError error,) = ECDSA.tryRecover(hash, signature);
        if (error == ECDSA.RecoverError.NoError && recovered == address(this)) {
            return _ERC1271_MAGIC_VALUE;
        }

        // Default return failure value
        return _ERC1271_FAIL_VALUE;
    }
}
