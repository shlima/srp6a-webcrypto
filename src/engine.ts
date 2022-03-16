import {BigInteger} from "jsbn"
import {Params} from "./rfc5054"
import {BigInt2Uint8Array, BigIntFromInt, BigIntFromUint8Array, Hash} from "./util"

export class Engine {
    readonly N: BigInteger;
    readonly g: BigInteger;
    readonly hash: string;

    public get N_SIZE(): number {
        return this.N.bitLength() >> 3
    }

    constructor(params: Params) {
        this.N = BigIntFromUint8Array(params.N)
        this.g = BigIntFromInt(params.g)
        this.hash = params.hash
    }

    async k(): Promise<BigInteger> {
        return BigIntFromUint8Array(await this.HASH(BigInt2Uint8Array(this.N), this.PAD(BigInt2Uint8Array(this.g))))
    }

    isModZero(a: BigInteger, b: BigInteger): boolean {
        return a.mod(b).signum() == 0
    }

    async HASH(...inputs: (Uint8Array)[]): Promise<Uint8Array> {
        return await Hash(this.hash, ...inputs)
    }

    // Conversion between integers and byte-strings assumes the most
    // significant bytes are stored first, as per [TLS] and [SRP-RFC].  In
    // the following text, if a conversion from integer to byte-string is
    // implicit, the most significant byte in the resultant byte-string MUST
    // be non-zero.  If a conversion is explicitly specified with the
    // operator PAD(), the integer will first be implicitly converted, then
    // the resultant byte-string will be left-padded with zeros (if
    // necessary) until its length equals the implicitly-converted length of
    // N.
    //
    // In other words RFC5054 specifies that number should be
    // left-padded with zeros to be the same length as N.
    PAD(input: Uint8Array) {
        if (input.length >= this.N_SIZE) {
            return input
        }

        const diff = this.N_SIZE - input.length
        return new Uint8Array([...new Uint8Array(diff), ...input])
    }

    async HASHED_CRED(username: string, password: string): Promise<Uint8Array> {
        const credentials = new TextEncoder().encode(username + ":" + password)
        return await this.HASH(credentials)
    }
}
