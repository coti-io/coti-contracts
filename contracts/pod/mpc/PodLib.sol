// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "./PodLib64.sol";
import "./PodLib128.sol";
import "./PodLib256.sol";

/// @title PodLib
/// @notice Combined 64-, 128-, and 256-bit POD MPC helpers (linearized via {PodLib64}, {PodLib128}, {PodLib256}).
abstract contract PodLib is PodLib64, PodLib128, PodLib256 {}
