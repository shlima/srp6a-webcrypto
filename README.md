# srp6a-webcrypto

[![Test](https://github.com/oka-is/srp6a-webcrypto/actions/workflows/test.yml/badge.svg)](https://github.com/oka-is/srp6a-webcrypto/actions/workflows/test.yml)

This is tiny Javascript SRP6a implementation
fully complies with the RFC-5054/RFC-2945.

It uses built-in crypto primitives from Web crypto 
API in node and in a browser (cryptographically strong 
random number generator and hash functions).

This client is used with [golang](https://github.com/oka-is/srp6ago) 
SRP6a server implementation.


## Installation

```bash
yarn add @oka-is/srp6a-webcrypto
```

## Usage

All internal operations are made with byte sequence 
(build in type `Uint8Array`), all returned values are also
bytes, so it's up to you how to encode the communication 
between client and server (protobuf or HEX representation with JSON).

### Registration flow

```js
import {SrpClient, RFC5054b1024Sha1} from "@oka-is/srp6a-webcrypto"

const client = new SrpClient("login", "password", RFC5054b1024Sha1)

client.seed(await client.randomSalt())
const verifier = await client.verifier()
const identifier = client.username
const salt = client.salt
// send identifier, verifier and salt to the server
```

### Login flow

```js
import {SrpClient, RFC5054b1024Sha1} from "@oka-is/srp6a-webcrypto"

const client = new SrpClient("login", "password", RFC5054b1024Sha1)

// 1) send user identifier to the server
// 2) get a salt and server public key from server response
const {salt, serverPublickKey} = await fetch(`?username=${identifier}`)
client.seed(salt)

const challenge = await client.setServerPublicKey(serverPublickKey)

// 3) send client's public key and proof to the server
const proof = challenge.proof
const publicKey = challenge.publicKey
const {serverProof} = await fetch(`?proof=${proof}&publicKey=${publicKey}`)

// 4) get server proof and validate it
challenge.isProofValid(serverProof)
// 5) now you have identical session key with server
challenge.secretKey()
```

## SRP Group Parameters

Preconfigured RFC-5054 SRP Group Parameters:

```js
// RFC-5054 complicated params set:
import {
  RFC5054b1024Sha1,
  RFC5054b1536Sha1,
  RFC5054b2048Sha1,
  RFC5054b3072Sha1,
  RFC5054b4096Sha1,
  RFC5054b6144Sha1,
  RFC5054b8192Sha1,
} from "@oka-is/srp6a-webcrypto"

// RFC-5054 complicated set,
// with non-standart hash function SHA-256
import {
  RFC5054b8192Sha256,
  RFC5054b6144Sha256,
  RFC5054b4096Sha256,
  RFC5054b1024Sha256,
  RFC5054b1536Sha256,
  RFC5054b2048Sha256,
  RFC5054b3072Sha256
} from "@oka-is/srp6a-webcrypto"
```
