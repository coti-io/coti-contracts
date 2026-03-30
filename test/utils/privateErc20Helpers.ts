import { expect } from "chai"
import type { BaseContract, ContractTransactionResponse } from "ethers"
import { prepareIT256, decryptUint256 } from "@coti-io/coti-sdk-typescript"
import type { ctUint256, itUint256 } from "@coti-io/coti-sdk-typescript"

/** Normalize ethers Result / tuple ctUint256 for the SDK. */
function toCtUint256(
    ct: ctUint256 | readonly [bigint, bigint] | { ciphertextHigh: bigint; ciphertextLow: bigint }
): ctUint256 {
    if (Array.isArray(ct)) {
        return { ciphertextHigh: BigInt(ct[0]), ciphertextLow: BigInt(ct[1]) }
    }
    return {
        ciphertextHigh: BigInt(ct.ciphertextHigh),
        ciphertextLow: BigInt(ct.ciphertextLow)
    }
}

/** Canonical empty ciphertext reads as numeric zero on-chain (see IPrivateERC20). */
function isZeroCt(ct: ctUint256): boolean {
    return ct.ciphertextHigh === 0n && ct.ciphertextLow === 0n
}
import type { Wallet } from "@coti-io/coti-ethers"

/** Gas limit for COTI testnet txs (MPC-heavy). */
export const GAS_LIMIT = 12_000_000

export const txOpts = { gasLimit: GAS_LIMIT }

/** EIP-165 `type(IPrivateERC20).interfaceId` (XOR of function selectors in `IPrivateERC20.sol`). */
export const IPRIVATE_ERC20_INTERFACE_ID = "0x479eaff4"

export async function mintPublic(
    contract: BaseContract,
    signer: Wallet,
    to: string,
    amount: bigint
) {
    return contract
        .connect(signer)
        .getFunction("mint(address,uint256)")(to, amount, txOpts)
}

export async function burnPublic(
    contract: BaseContract,
    signer: Wallet,
    from: string,
    amount: bigint
) {
    return contract
        .connect(signer)
        .getFunction("burn(address,uint256)")(from, amount, txOpts)
}

/** Encrypted uint256 input text for `itUint256` calldata (PrivateERC20). Uses `prepareIT256`, not 64-bit `Wallet.encryptValue`. */
export async function encryptItUint256(
    wallet: Wallet,
    plaintext: bigint,
    contractAddress: string,
    functionSelector: string
): Promise<itUint256> {
    const info = wallet.getUserOnboardInfo()
    if (!info?.aesKey) {
        throw new Error("Wallet not onboarded: missing aesKey")
    }
    return prepareIT256(plaintext, { wallet, userKey: info.aesKey }, contractAddress, functionSelector)
}

/** Decrypt `ctUint256` from `balanceOf` / allowance views. */
export function decryptCtUint256(
    wallet: Wallet,
    ct: ctUint256 | readonly [bigint, bigint] | { ciphertextHigh: bigint; ciphertextLow: bigint }
): bigint {
    const info = wallet.getUserOnboardInfo()
    if (!info?.aesKey) {
        throw new Error("Wallet not onboarded: missing aesKey")
    }
    const normalized = toCtUint256(ct)
    if (isZeroCt(normalized)) {
        return 0n
    }
    return decryptUint256(normalized, info.aesKey)
}

/**
 * COTI testnet often omits revert data on eth_call; Hardhat custom-error matchers also fail when
 * sendTransaction receipts lack data. Use this for "must revert" smoke checks.
 */
export async function expectTxFails(txPromise: Promise<ContractTransactionResponse>): Promise<void> {
    try {
        const tx = await txPromise
        await tx.wait()
        expect.fail("expected transaction to revert")
    } catch (e) {
        expect(e).to.be.ok
    }
}
