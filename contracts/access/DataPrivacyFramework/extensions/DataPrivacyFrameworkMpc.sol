// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../DataPrivacyFramework.sol";
import "../../../utils/mpc/MpcCore.sol";

abstract contract DataPrivacyFrameworkMpc is DataPrivacyFramework {

    constructor(bool addressDefaultPermission_, bool operationDefaultPermission_) DataPrivacyFramework(addressDefaultPermission_, operationDefaultPermission_) {}
    
    // 8-bit operations

    function add(
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_add", uintParameter, addressParameter, stringParameter)
        returns (gtUint8)
    {
        return MpcCore.add(a, b);
    }

    function sub(
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_sub", uintParameter, addressParameter, stringParameter)
        returns (gtUint8)
    {
        return MpcCore.sub(a, b);
    }

    function mul(
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_mul", uintParameter, addressParameter, stringParameter)
        returns (gtUint8)
    {
        return MpcCore.mul(a, b);
    }

    function div(
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_div", uintParameter, addressParameter, stringParameter)
        returns (gtUint8)
    {
        return MpcCore.div(a, b);
    }

    function rem(
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_rem", uintParameter, addressParameter, stringParameter)
        returns (gtUint8)
    {
        return MpcCore.rem(a, b);
    }

    function and(
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_and", uintParameter, addressParameter, stringParameter)
        returns (gtUint8)
    {
        return MpcCore.and(a, b);
    }

    function or(
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_or", uintParameter, addressParameter, stringParameter)
        returns (gtUint8)
    {
        return MpcCore.or(a, b);
    }

    function xor(
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_xor", uintParameter, addressParameter, stringParameter)
        returns (gtUint8)
    {
        return MpcCore.xor(a, b);
    }

    function shl(
        gtUint8 a,
        uint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_shl", uintParameter, addressParameter, stringParameter)
        returns (gtUint8)
    {
        return MpcCore.shl(a, b);
    }

    function shr(
        gtUint8 a,
        uint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_shr", uintParameter, addressParameter, stringParameter)
        returns (gtUint8)
    {
        return MpcCore.shr(a, b);
    }

    function eq(
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_eq", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.eq(a, b);
    }

    function ne(
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_ne", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.ne(a, b);
    }

    function ge(
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_ge", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.ge(a, b);
    }

    function gt(
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_gt", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.gt(a, b);
    }

    function le(
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_le", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.le(a, b);
    }

    function lt(
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_lt", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.lt(a, b);
    }

    function min(
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_min", uintParameter, addressParameter, stringParameter)
        returns (gtUint8)
    {
        return MpcCore.min(a, b);
    }

    function max(
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_max", uintParameter, addressParameter, stringParameter)
        returns (gtUint8)
    {
        return MpcCore.max(a, b);
    }

    function decrypt(
        gtUint8 a,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_decrypt", uintParameter, addressParameter, stringParameter)
        returns (uint8)
    {
        return MpcCore.decrypt(a);
    }

    function mux(
        gtBool bit,
        gtUint8 a,
        gtUint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_mux", uintParameter, addressParameter, stringParameter)
        returns (gtUint8)
    {
        return MpcCore.mux(bit, a, b);
    }

    // 16-bit operations

    function add(
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_add", uintParameter, addressParameter, stringParameter)
        returns (gtUint16)
    {
        return MpcCore.add(a, b);
    }

    function sub(
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_sub", uintParameter, addressParameter, stringParameter)
        returns (gtUint16)
    {
        return MpcCore.sub(a, b);
    }

    function mul(
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_mul", uintParameter, addressParameter, stringParameter)
        returns (gtUint16)
    {
        return MpcCore.mul(a, b);
    }

    function div(
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_div", uintParameter, addressParameter, stringParameter)
        returns (gtUint16)
    {
        return MpcCore.div(a, b);
    }

    function rem(
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_rem", uintParameter, addressParameter, stringParameter)
        returns (gtUint16)
    {
        return MpcCore.rem(a, b);
    }

    function and(
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_and", uintParameter, addressParameter, stringParameter)
        returns (gtUint16)
    {
        return MpcCore.and(a, b);
    }

    function or(
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_or", uintParameter, addressParameter, stringParameter)
        returns (gtUint16)
    {
        return MpcCore.or(a, b);
    }

    function xor(
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_xor", uintParameter, addressParameter, stringParameter)
        returns (gtUint16)
    {
        return MpcCore.xor(a, b);
    }

    function shl(
        gtUint16 a,
        uint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_shl", uintParameter, addressParameter, stringParameter)
        returns (gtUint16)
    {
        return MpcCore.shl(a, b);
    }

    function shr(
        gtUint16 a,
        uint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_shr", uintParameter, addressParameter, stringParameter)
        returns (gtUint16)
    {
        return MpcCore.shr(a, b);
    }

    function eq(
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_eq", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.eq(a, b);
    }

    function ne(
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_ne", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.ne(a, b);
    }

    function ge(
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_ge", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.ge(a, b);
    }

    function gt(
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_gt", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.gt(a, b);
    }

    function le(
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_le", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.le(a, b);
    }

    function lt(
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_lt", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.lt(a, b);
    }

    function min(
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_min", uintParameter, addressParameter, stringParameter)
        returns (gtUint16)
    {
        return MpcCore.min(a, b);
    }

    function max(
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_max", uintParameter, addressParameter, stringParameter)
        returns (gtUint16)
    {
        return MpcCore.max(a, b);
    }

    function decrypt(
        gtUint16 a,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_decrypt", uintParameter, addressParameter, stringParameter)
        returns (uint16)
    {
        return MpcCore.decrypt(a);
    }

    function mux(
        gtBool bit,
        gtUint16 a,
        gtUint16 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_mux", uintParameter, addressParameter, stringParameter)
        returns (gtUint16)
    {
        return MpcCore.mux(bit, a, b);
    }

    // 32-bit operations

    function add(
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_add", uintParameter, addressParameter, stringParameter)
        returns (gtUint32)
    {
        return MpcCore.add(a, b);
    }

    function sub(
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_sub", uintParameter, addressParameter, stringParameter)
        returns (gtUint32)
    {
        return MpcCore.sub(a, b);
    }

    function mul(
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_mul", uintParameter, addressParameter, stringParameter)
        returns (gtUint32)
    {
        return MpcCore.mul(a, b);
    }

    function div(
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_div", uintParameter, addressParameter, stringParameter)
        returns (gtUint32)
    {
        return MpcCore.div(a, b);
    }

    function rem(
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_rem", uintParameter, addressParameter, stringParameter)
        returns (gtUint32)
    {
        return MpcCore.rem(a, b);
    }

    function and(
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_and", uintParameter, addressParameter, stringParameter)
        returns (gtUint32)
    {
        return MpcCore.and(a, b);
    }

    function or(
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_or", uintParameter, addressParameter, stringParameter)
        returns (gtUint32)
    {
        return MpcCore.or(a, b);
    }

    function xor(
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_xor", uintParameter, addressParameter, stringParameter)
        returns (gtUint32)
    {
        return MpcCore.xor(a, b);
    }

    function shl(
        gtUint32 a,
        uint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_shl", uintParameter, addressParameter, stringParameter)
        returns (gtUint32)
    {
        return MpcCore.shl(a, b);
    }

    function shr(
        gtUint32 a,
        uint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_shr", uintParameter, addressParameter, stringParameter)
        returns (gtUint32)
    {
        return MpcCore.shr(a, b);
    }

    function eq(
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_eq", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.eq(a, b);
    }

    function ne(
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_ne", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.ne(a, b);
    }

    function ge(
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_ge", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.ge(a, b);
    }

    function gt(
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_gt", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.gt(a, b);
    }

    function le(
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_le", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.le(a, b);
    }

    function lt(
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_lt", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.lt(a, b);
    }

    function min(
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_min", uintParameter, addressParameter, stringParameter)
        returns (gtUint32)
    {
        return MpcCore.min(a, b);
    }

    function max(
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_max", uintParameter, addressParameter, stringParameter)
        returns (gtUint32)
    {
        return MpcCore.max(a, b);
    }

    function decrypt(
        gtUint32 a,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_decrypt", uintParameter, addressParameter, stringParameter)
        returns (uint32)
    {
        return MpcCore.decrypt(a);
    }

    function mux(
        gtBool bit,
        gtUint32 a,
        gtUint32 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_mux", uintParameter, addressParameter, stringParameter)
        returns (gtUint32)
    {
        return MpcCore.mux(bit, a, b);
    }

    // 64-bit operations

    function add(
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_add", uintParameter, addressParameter, stringParameter)
        returns (gtUint64)
    {
        return MpcCore.add(a, b);
    }

    function sub(
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_sub", uintParameter, addressParameter, stringParameter)
        returns (gtUint64)
    {
        return MpcCore.sub(a, b);
    }

    function mul(
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_mul", uintParameter, addressParameter, stringParameter)
        returns (gtUint64)
    {
        return MpcCore.mul(a, b);
    }

    function div(
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_div", uintParameter, addressParameter, stringParameter)
        returns (gtUint64)
    {
        return MpcCore.div(a, b);
    }

    function rem(
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_rem", uintParameter, addressParameter, stringParameter)
        returns (gtUint64)
    {
        return MpcCore.rem(a, b);
    }

    function and(
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_and", uintParameter, addressParameter, stringParameter)
        returns (gtUint64)
    {
        return MpcCore.and(a, b);
    }

    function or(
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_or", uintParameter, addressParameter, stringParameter)
        returns (gtUint64)
    {
        return MpcCore.or(a, b);
    }

    function xor(
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_xor", uintParameter, addressParameter, stringParameter)
        returns (gtUint64)
    {
        return MpcCore.xor(a, b);
    }

    function shl(
        gtUint64 a,
        uint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_shl", uintParameter, addressParameter, stringParameter)
        returns (gtUint64)
    {
        return MpcCore.shl(a, b);
    }

    function shr(
        gtUint64 a,
        uint8 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_shr", uintParameter, addressParameter, stringParameter)
        returns (gtUint64)
    {
        return MpcCore.shr(a, b);
    }

    function eq(
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_eq", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.eq(a, b);
    }

    function ne(
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_ne", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.ne(a, b);
    }

    function ge(
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_ge", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.ge(a, b);
    }

    function gt(
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_gt", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.gt(a, b);
    }

    function le(
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_le", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.le(a, b);
    }

    function lt(
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_lt", uintParameter, addressParameter, stringParameter)
        returns (gtBool)
    {
        return MpcCore.lt(a, b);
    }

    function min(
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_min", uintParameter, addressParameter, stringParameter)
        returns (gtUint64)
    {
        return MpcCore.min(a, b);
    }

    function max(
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_max", uintParameter, addressParameter, stringParameter)
        returns (gtUint64)
    {
        return MpcCore.max(a, b);
    }

    function decrypt(
        gtUint64 a,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_decrypt", uintParameter, addressParameter, stringParameter)
        returns (uint64)
    {
        return MpcCore.decrypt(a);
    }

    function mux(
        gtBool bit,
        gtUint64 a,
        gtUint64 b,
        uint256 uintParameter,
        address addressParameter,
        string calldata stringParameter
    )
        internal
        onlyAllowedUserOperation("op_mux", uintParameter, addressParameter, stringParameter)
        returns (gtUint64)
    {
        return MpcCore.mux(bit, a, b);
    }
}