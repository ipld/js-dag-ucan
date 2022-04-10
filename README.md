# @ipld/dag-ucan

An implementation of [UCAN][]s representation in [IPLD][], designed for use with [multiformats][].

## Overview

This library implements multicodec for represenating [UCAN]s natively in [IPLD][]. It uses [DAG-CBOR][] as a primary encoding, which is more compact and has a better hash consitency than a secondary RAW JWT encoding. Every UCAN in primary encoding can be formatted into a JWT string and consumed by spec compliant [UCAN][] implementations. However not every [UCAN][] can be encoded in a primary CBOR representation, as loss of whitespaces and key order would lead to mismatched signature. Library issues UCANs only in primary CBOR representation. When parsing UCANs that can not have valid CBOR representation, secondary RAW representation is used, which allows interop with all existing tokens in the wild.

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

Parses UCAN formatted as JWT string into a representatino that can be encoded, formatted and queried.

```ts
const ucan = UCAN.parse(jwt)
ucan.issuer // did:key:zAlice
```

#### `UCAN.format(ucan: UCAN.UCAN): string`

Formats UCAN into a JWT string.

```ts
UCAN.format(UCAN.parse(jwt)) === jwt // true
```

#### `UCAN.encode(ucan: UCAN.UCAN): Uint8Array`

Encodes UCAN into a binary representation.

#### `UCAN.decode(bytes: Uint8Array): UCAN.UCAN`

Decodes byte encoded UCAN.

#### `UCAN.issue(options: UCAN.UCANOptions): Promise<UCAN.UCAN>`

Issues or derives a UCAN.

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
