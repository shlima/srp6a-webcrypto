import {BigInteger} from "jsbn";

let crypt: Crypto;

if (typeof window !== 'undefined') {
    crypt = window.crypto
} else if (typeof WorkerGlobalScope !== 'undefined' ) {
    crypt = require("crypto")
} else {
    crypt = require("crypto")
}

export function BigIntFromUint8Array(input: Uint8Array): BigInteger {
    return new BigInteger(Uint8Array2Hex(input), 16)
}

export function BigIntFromInt(input: number): BigInteger {
    return new BigInteger(input.toString(), 10)
}

// convert to big-endian byte array
export function BigInt2Uint8Array(input: BigInteger): Uint8Array {
    let array = input.toByteArray()
    // Java, GO anf etc. BigInteger math will trim leading zeros so we do likewise
    // @refs https://github.com/simbo1905/thinbus-srp-npm/blob/master/client.js#L111
    while (array[0] === 0) {
        array = array.slice(1, array.length)
    }
    return new Uint8Array(array)
}

export function Uint8Array2Hex(input: Uint8Array): string {
    const out: Array<string> = []
    input.forEach((n: number, ix: number) => out[ix] = n.toString(16).padStart(2, '0'))
    return out.join('')
}

// Uint8ArrayFromHex parses HEX to binary array.
// allows grouping by 4 bytes and new lines
export function Uint8ArrayFromHex(input: string): Uint8Array {
    const matched = input.match(/[A-F0-9]{2}/g)
    if (matched == null) {
        return new Uint8Array(0)
    }

    return new Uint8Array(matched.map(byte => parseInt(byte, 16)))
}

export async function SecureRandom(length: number): Promise<Uint8Array> {
    const out = new Uint8Array(length)
    await crypt.getRandomValues(out)
    return out
}

export async function Hash(name: string, ...inputs: (Uint8Array)[]): Promise<Uint8Array> {
    let data = new Uint8Array()

    for (let input of inputs) {
        data = new Uint8Array([...data, ...input])
    }

    return new Uint8Array(await crypt.subtle.digest(name, data))
}
