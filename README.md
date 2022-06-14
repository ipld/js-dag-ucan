# @ipld/dag-ucan

An implementation of [UCAN][]s in [IPLD][] via [Advanced Data Layout (ADL)](ADL), designed for use with [multiformats][].

## Overview

This library implements [ADL][] for representing [UCAN]s natively in [IPLD][]. It uses [DAG-CBOR][] as a primary encoding, which is hash consistent and more compact than a secondary RAW JWT encoding. Every UCAN in either encoding can be formatted into a valid JWT string and consumed by other spec compliant [UCAN][] implementations. However [UCAN][]s issued by other libraries may end up in represented in secondory RAW JWT encoding, that is because whitespaces and key order in JWT affects signatures and there for can't be represented accurately in CBOR. When parsing UCANs library will use CBOR representation and fallback to RAW JWT, which allows interop with all existing tokens in the wild.

### Primary Representation

UCANs in primary representation are encoded in [DAG-CBOR][] and have following
[IPLD schema][]:

```ipldsch
type UCAN struct {
  version String

  issuer SigningKey
  audience SigningKey
  signature Signature

  capabilities [Capability]
  proofs [&UCAN]
  expiration Int

  facts [Fact]
  nonce optional String
  notBefore optional Int
} representation map {
  field facts default []
  field proofs default []
}


type Capability struct {
  with Resource
  can Ability
  -- can have arbitrary other fields
}

type Fact { String: Any }


-- The resource pointer in URI format
type Resource = String

-- Must be all lower-case `/` delimeted with at least one path segment
type Ability = String

-- Signature is computed by seralizing header & body
-- into corresponding JSON with DAG-JSON (to achieve
-- for hash consitency) then encoded into base64 and
-- then signed by issuers private key
type Signature = Bytes

-- multicodec tagged public key
-- 0xed       Ed25519
-- 0x1205     RSA
type SigningKey = Bytes
```

## API

```ts
import * as UCAN from "@ipld/dag-ucan"
```

#### `UCAN.parse(jwt: string): UCAN.View`

Parses UCAN formatted as JWT string into a representatino that can be encoded, formatted and queried.

```ts
const ucan = UCAN.parse(jwt)
ucan.issuer.did() // did:key:z6Mkk89bC3JrVqKie71YEcc5M1SMVxuCgNx6zLZ8SYJsxALi
```

#### `UCAN.format(ucan: UCAN.UCAN): string`

Formats UCAN into a JWT string.

```ts
UCAN.format(UCAN.parse(jwt)) === jwt // true
```

#### `UCAN.encode(ucan: UCAN.UCAN): Uint8Array`

Encodes UCAN into a binary representation.

```ts
UCAN.encode(UCAN.parse(jwt)) // Uint8Array(679)
```

#### `UCAN.decode(bytes: Uint8Array): UCAN.UCAN`

Decodes UCAN from binary representation into object representation.

```ts
UCAN.decode(UCAN.encode(ucan))
```

#### `UCAN.issue(options: UCAN.UCANOptions): Promise<UCAN.UCAN>`

Issues a signed UCAN.

> Please note that no capability or time bound validation takes place.

```ts
const ucan = await UCAN.issue({
  issuer: alice,
  audience: bob,
  capabilities: [
    {
      can: "fs/read",
      with: `storage://${alice.did()}/public/photos/`,
    },
    {
      can: "pin/add",
      with: alice.did(),
    },
  ],
})
```

### Embedding Proofs

While not recommended, it is possible to inline proofs inside a single UCAN using CIDs with identity
multihash:

```ts
import { identity } from "multiformats/hashes/identity"
const proof = await UCAN.issue({
  issuer: alice,
  audience: bob,
  capabilities: [{ can: "store/add", with: alice.did() }],
})

const delegation = await UCAN.issue({
  issuer: bob,
  audience: mallory,
  capabilities: proof.capabilities,
  proofs: [await UCAN.link(proof, {hasher: identity})]
})
```

[ipld]: https://ipld.io/
[ucan]: https://github.com/ucan-wg/spec/
[ipld schema]: https://ipld.io/docs/schemas/using/authoring-guide/
[dag-cbor]: https://ipld.io/docs/codecs/known/dag-cbor/
[multiformats]: https://github.com/multiformats/js-multiformats
[adl]: https://ipld.io/docs/advanced-data-layouts/
