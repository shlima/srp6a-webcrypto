import {Params} from "./rfc5054"
import {Engine} from "./engine"
import {BigInt2Uint8Array, BigIntFromUint8Array, SecureRandom} from "./util"

// @refs RFC-5054 https://datatracker.ietf.org/doc/html/rfc5054
// @refs RFC-2945 https://datatracker.ietf.org/doc/html/rfc2945
//
// @refs https://github.com/simbo1905/thinbus-srp-npm/blob/master/server.js
// @refs https://github.com/grempe/sirp
// @refs https://github.com/opencoff/go-srp
//
// N, g: group parameters (prime and generator)
// s: salt
// B, b: server's public and private values
// A, a: client's public and private values
// I: user name (aka "identity")
// P: password
// v: verifier
// k: SRP-6 multiplier (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
// S: pre-master secret
// K = SHA_Interleave(S) shared secret key
export class Client {
    private readonly e: Engine
    private readonly username: string
    private readonly password: string
    private readonly s: Uint8Array

    // @test
    public _a: Uint8Array | null

    constructor(username: string, password: string, s: Uint8Array, params: Params) {
        this.e = new Engine(params)
        this.username = username
        this.password = password
        this.s = s

        // @test
        this._a = null
    }


    // The verifier (v) is computed based on the salt (s), user name (I),
    // password (P), and group parameters (N, g).  The computation uses the
    // [SHA1] hash algorithm:
    //
    // x = SHA1(s | SHA1(I | ":" | P))
    // v = g^x % N
    async verifier(): Promise<Uint8Array> {
        const hashed = await this.e.HASHED_CRED(this.username, this.password)
        const x = BigIntFromUint8Array(await this.e.HASH(this.s, hashed))
        const v = this.e.g.modPow(x, this.e.N)
        return BigInt2Uint8Array(v)
    }

    // The pre-master secret is calculated by the client as follows:
    //
    // I, P = <read from user>
    // N, g, s, B = <read from server>
    // a = random()
    // A = g^a % N
    // u = SHA1(PAD(A) | PAD(B))
    // k = SHA1(N | PAD(g))
    // x = SHA1(s | SHA1(I | ":" | P))
    // <pre-master secret> = (B - (k * g^x)) ^ (a + (u * x)) % N
    //
    // The pre-master secret is calculated by the server as follows:
    //
    // N, g, s, v = <read from password file>
    // b = random()
    // k = SHA1(N | PAD(g))
    // B = k*v + g^b % N
    // A = <read from client>
    // u = SHA1(PAD(A) | PAD(B))
    // <pre-master secret> = (A * v^u) ^ b  % N
    //
    // To verify that the client has generated the same key "K or S", the client sends
    // "M'" -- a hash of all the data it has and it received from the server. To
    // validate that the server also has the same value, it requires the server to send
    // its own proof. In the SRP paper [1], the authors use:
    //     M = H(H(N) xor H(g), H(I), s, A, B, S) => from server
    //     M' = H(A, B, S) => from client
    async setServerPublicKey(B: Uint8Array): Promise<ClientChallenge> {
        const a = this._a ? BigIntFromUint8Array(this._a) : BigIntFromUint8Array(await SecureRandom(this.e.N_SIZE))
        const A = this.e.g.modPow(a, this.e.N)
        const k = await this.e.k()
        const u = BigIntFromUint8Array(await this.e.HASH(this.e.PAD(BigInt2Uint8Array(A)), this.e.PAD(B)))
        const x = BigIntFromUint8Array(await this.e.HASH(this.s, await this.e.HASHED_CRED(this.username, this.password)))

        // (B - (k * g^x)) ^ (a + (u * x)) % N
        const _exp = u.multiply(x).add(a);
        const _tmp = this.e.g.modPow(x, this.e.N).multiply(k)
        const S = BigIntFromUint8Array(B).subtract(_tmp).modPow(_exp, this.e.N)

        // H(A, M, K)
        const M = await this.e.HASH(BigInt2Uint8Array(A), B, BigInt2Uint8Array(S))

        const ch = new ClientChallenge()
        ch.k = BigInt2Uint8Array(k)
        ch.x = BigInt2Uint8Array(x)
        ch.a = BigInt2Uint8Array(a)
        ch.A = BigInt2Uint8Array(A)
        ch.u = BigInt2Uint8Array(u)
        ch.S = BigInt2Uint8Array(S)
        ch.M = M

        // @refs https://go.dev/play/p/21hj3bfDs8U
        return ch
    }
}

export class ClientChallenge {
    public k: Uint8Array
    public x: Uint8Array
    public a: Uint8Array
    public A: Uint8Array
    public u: Uint8Array
    public S: Uint8Array
    public M: Uint8Array

    constructor() {
        this.k = new Uint8Array(0)
        this.x = new Uint8Array(0)
        this.a = new Uint8Array(0)
        this.A = new Uint8Array(0)
        this.u = new Uint8Array(0)
        this.S = new Uint8Array(0)
        this.M = new Uint8Array(0)
    }

    get secretKey(): Uint8Array {
        return this.S
    }

    get publicKey(): Uint8Array {
        return this.A
    }

    get proof(): Uint8Array {
        return this.M
    }
}

