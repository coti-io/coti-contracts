import crypto from "crypto"
import { itUint, Wallet } from "@coti-io/coti-ethers"
import { CtUint128Struct, ItUint128Struct } from "../../../typechain-types/contracts/mocks/utils/mpc/Miscellaneous128BitTestsContract"
import { CtUint256Struct, ItUint256Struct } from "../../../typechain-types/contracts/mocks/utils/mpc/Miscellaneous256BitTestsContract"

export function generateRandomNumber(numBytes: number): bigint {
    const bytes = crypto.randomBytes(numBytes)
    // Convert bytes to BigInt
    return BigInt('0x' + bytes.toString('hex'))
}
  
export async function encryptUint128(number: bigint, account: Wallet, contractAddress: string, functionSelector: string): Promise<ItUint128Struct> {
    // Convert to hex string and ensure it is 32 characters (16 bytes)
    const hexString = number.toString(16).padStart(32, '0');

    // Split into two 8-byte (16-character) segments
    const high = hexString.slice(0, 16);
    const low = hexString.slice(16, 32);

    const itHigh = await account.encryptValue(
        BigInt(`0x${high}`),
        contractAddress,
        functionSelector
    ) as itUint

    const itLow = await account.encryptValue(
        BigInt(`0x${low}`),
        contractAddress,
        functionSelector
    ) as itUint

    return {
        ciphertext: { high: itHigh.ciphertext, low: itLow.ciphertext },
        signature: [itHigh.signature, itLow.signature]
    }
}
  
export async function decryptUint128(ctNumber: CtUint128Struct, account: Wallet): Promise<bigint> {
    const high = await account.decryptValue(ctNumber.high as bigint)
    const low = await account.decryptValue(ctNumber.low as bigint)
  
    // Convert both high and low parts to hex strings, ensuring they are 16 characters (8 bytes) long
    let highHex = high.toString(16).padStart(16, '0');
    let lowHex = low.toString(16).padStart(16, '0');
  
    // Concatenate and convert back to a single bigint
    return BigInt(`0x${highHex + lowHex}`);
}

export async function encryptUint256(number: bigint, account: Wallet, contractAddress: string, functionSelector: string): Promise<ItUint256Struct> {
    // Convert to hex string and ensure it is 64 characters (32 bytes)
    const hexString = number.toString(16).padStart(64, '0');
  
    // Split into two 16-byte (-character) segments
    const high = hexString.slice(0, 32);
    const low = hexString.slice(32, 64);
  
    const itHigh = await encryptUint128(BigInt(`0x${high}`), account, contractAddress, functionSelector)
    const itLow = await encryptUint128(BigInt(`0x${low}`), account, contractAddress, functionSelector)
  
    return {
      ciphertext: { high: itHigh.ciphertext, low: itLow.ciphertext },
      signature: [itHigh.signature, itLow.signature]
    }
}
  
export async function decryptUint256(ctNumber: CtUint256Struct, account: Wallet): Promise<bigint> {
    const high = await decryptUint128(ctNumber.high, account)
    const low = await decryptUint128(ctNumber.low, account)
  
    // Convert both high and low parts to hex strings, ensuring they are 16 characters (8 bytes) long
    let highHex = high.toString(16).padStart(32, '0');
    let lowHex = low.toString(16).padStart(32, '0');
  
    // Concatenate and convert back to a single bigint
    return BigInt(`0x${highHex + lowHex}`);
}