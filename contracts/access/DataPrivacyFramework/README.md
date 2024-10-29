# DataPrivacyFramework

## Overview

The `DataPrivacyFramework` is an abstract Solidity contract designed to manage conditions and operations related to data privacy. The contract handles operations such as user permissions, time-bound constraints, and condition validation based on various keys and parameters.

## Prerequisites

- **Solidity Version:** `^0.8.19`
- **License:** MIT

## Table of Contents
- [Data Structures](#data-structures)
  - [InputData Struct](#inputdata-struct)
  - [Condition Struct](#condition-struct)
- [Functions](#functions)
  - [Abstract Functions](#abstract-functions)

## Data Structures

### InputData Struct

The `InputData` struct is a data holder that encapsulates the details of a particular operation or action requested by the caller. This struct helps in preventing the "stack too deep" error, which occurs when a function has too many local variables. 

#### Fields:
- **`caller`**: (`address`) The address of the user or contract initiating the operation.
- **`operation`**: (`string`) The name or type of the operation being executed.
- **`active`**: (`bool`) A boolean flag indicating whether the operation is currently active.
- **`timestampBefore`**: (`uint256`) The operation must be executed before this timestamp.
- **`timestampAfter`**: (`uint256`) The operation must be executed after this timestamp.
- **`falseKey`**: (`bool`) A boolean flag that, if true, makes the condition unsatisfiable.
- **`trueKey`**: (`bool`) A boolean flag that, if true, makes the condition always satisfied (unless `falseKey` is true).
- **`uintParameter`**: (`uint256`) A numerical parameter relevant to the operation.
- **`addressParameter`**: (`address`) An address that may be used as a parameter for the operation.
- **`stringParameter`**: (`string`) A string-based parameter used for additional details in the operation.

### Condition Struct

The `Condition` struct represents a privacy-related condition that can either permit or deny an operation based on various factors, such as the caller, timing constraints, and control flags (`falseKey`, `trueKey`).

#### Fields:
- **`id`**: (`uint256`) A unique identifier for the condition.
- **`caller`**: (`address`) The address associated with the condition.
- **`operation`**: (`string`) The type of operation the condition governs.
- **`active`**: (`bool`) Indicates if the condition is currently valid or active.
- **`falseKey`**: (`bool`) If set to `true`, the condition will never be satisfied.
- **`trueKey`**: (`bool`) If set to `true`, the condition will always be satisfied (unless `falseKey` is also true).
- **`timestampBefore`**: (`uint256`) The condition is only valid before this timestamp.
- **`timestampAfter`**: (`uint256`) The condition is only valid after this timestamp.

## Functions

### Abstract Functions

The contract is abstract, so the following functions are likely declared but not implemented within this contract. They need to be implemented in derived contracts.

#### `checkCondition`
This function checks whether the conditions of a specific operation are met, based on the values in the `Condition` struct.

```solidity
function checkCondition(uint256 conditionId) public view virtual returns (bool);
```

- **Parameters**: 
  - `conditionId`: The unique ID of the condition to check.
  
- **Returns**: 
  - `bool`: `true` if the condition is satisfied, `false` otherwise.