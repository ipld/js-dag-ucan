# @ipld/dag-ucan

An implementation of [UCAN][]s with [IPLD][] representation, designed to be used with [multiformats][].

## Overview

This library implements multicodec for represenating [UCAN]s natively in [IPLD][]. It uses [DAG-CBOR][] encoding as a primary representation, which is more compact and has better hash consitency than secondary representation which is raw bytes of JWT. Every UCAN in primary representation can be formatted as JWT and used by any spec compliant [UCAN][] implementation, however not every [UCAN][] can be represented by primary representation _(loss of whitespaces and key order would lead to different signatures)_. Such [UCAN][]s are parsed into a secondary "JWT" representation, which allows interop with all existing tokens in the wild.

### Primary Representation

UCANs in primary representation are encoded in [DAG-CBOR][] and have following
[IPLD schema][]:

```ipldsch
type UCAN struct {
  header Heder
  body Body
  signature Signature
}

type Header struct {
  version String
  algorithm Algorithm
}

type Body struct {
  issuer String
  audience String,
  capabilities [Capability]
  expiration Int
  proofs [&UCAN]
  -- If empty omitted
  facts optional [Fact]
  nonce optional String
  notBefore optional Int
}

type Capability struct {
  with String
  -- Must be all lowercase
  can String
  -- can have other fields
}

type Fact { String: Any }

enum Algorithm {
  EdDSA (237)           -- 0xed   Ed25519 multicodec
  RS256 (4613)          -- 0x1205 RSA multicodec
} representation int

-- Signature is computed by seralizing header & body
-- into corresponding JSON with DAG-JSON (to achieve
-- for hash consitency) then encoded into base64 and
-- then signed by issuers private key
type Signature = Bytes
```

## API

```ts
import * as UCAN from "@ipld/dag-ucan"
```

#### `UCAN.parse(jwt: string): UCAN.UCAN`

Parses UCAN JWT string and returns `UCAN` object which can be encoded, formatted or queried.

```ts
const ucan = UCAN.parse(jwt)
ucan.issuer // did:key:zAlice
```

#### `UCAN.format(ucan: UCAN.UCAN): string`

Formats UCAN as a JWT string.

```ts
UCAN.format(UCAN.parse(jwt)) === jwt // true
```

#### `UCAN.encode(ucan: UCAN.UCAN): Uint8Array`

Encodes UCAN into binary representation.

#### `UCAN.decode(bytes: Uint8Array): UCAN.UCAN`

Decodes UCAN in binary representation into object representation.

#### `UCAN.issue(options: UCAN.UCANOptions): Promise<UCAN.UCAN>`

Issues or derives a UCAN. Returns promise for UCAN in IPLD representation.

> Please note that no capability or time bound validation takes place

```ts
const ucan = await UCAN.issue({
  issuer: boris,
  audience: 'did:key:z6MkffDZCkCTWreg8868fG1FGFogcJj5X6PY93pPcWDn9bob'
  capabilities: [
    {
      with: "wnfs://boris.fission.name/public/photos/",
      can: "wnfs/append",
    },
    {
      with: "mailto:boris@fission.codes",
      can: "msg/send"
    }
  ],
})
```

[ipld]: https://ipld.io/
[ucan]: https://github.com/ucan-wg/spec/
[ipld schema]: https://ipld.io/docs/schemas/using/authoring-guide/
[dag-cbor]: https://ipld.io/docs/codecs/known/dag-cbor/
[multiformats]: https://github.com/multiformats/js-multiformats
