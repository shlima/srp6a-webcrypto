import bigInt from "big-integer"

export function BigIntFromUint8Array(input: Uint8Array): bigInt.BigInteger {
    return bigInt.fromArray(Array.from(input), 256)
}

export function BigIntFromInt(input: number): bigInt.BigInteger {
    return bigInt(input)
}

// @refs https://github.com/peterolson/BigInteger.js/issues/46
export function EuclideanModPow(a: bigInt.BigInteger, b: bigInt.BigInteger, m: bigInt.BigInteger): bigInt.BigInteger {
    const res = bigInt(a).modPow(b, m)
    return res.isNegative() ? res.add(m) : res
}

// convert to big-endian byte array
// Java, GO anf etc. BigInteger math will trim leading zeros so we do likewise
// @refs https://github.com/simbo1905/thinbus-srp-npm/blob/master/client.js#L111
// while (array[0] === 0) {
//     array = array.slice(1, array.length)
// }
// the code above was used with "jsbn"
export function BigInt2Uint8Array(input: bigInt.BigInteger): Uint8Array {
    let array = input.toArray(256).value
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
    const matched = input.match(/[A-Fa-f\d]{2}/g)
    if (matched == null) {
        return new Uint8Array(0)
    }

    return new Uint8Array(matched.map(byte => parseInt(byte, 16)))
}

export function SecureEqual(uno: Uint8Array, dos: Uint8Array): boolean {
    if (uno.length != dos.length) {
        return false
    }

    let same = true

    for (let i = 0; i < uno.length; i++) {
        const u = uno[i]
        const d = dos[i]
        if (u !== d) same = false
    }

    return same
}

export async function SecureRandom(length: number): Promise<Uint8Array> {
    const out = new Uint8Array(length)
    await crypto.getRandomValues(out)
    return out
}

export async function Hash(name: string, ...inputs: (Uint8Array)[]): Promise<Uint8Array> {
    let data = new Uint8Array()

    for (let input of inputs) {
        data = new Uint8Array([...data, ...input])
    }

    return new Uint8Array(await crypto.subtle.digest(name, data))
}
