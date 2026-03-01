import crypto from "crypto"

export const gasOptions = {
	gasLimit: 15000000,
	gasPrice: 1000000000,
}

export function generateRandomNumber(numBytes: number): bigint {
    const bytes = crypto.randomBytes(numBytes)
    // Convert bytes to BigInt
    return BigInt('0x' + bytes.toString('hex'))
}
