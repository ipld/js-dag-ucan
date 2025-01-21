# @ipld/dag-ucan

![UCAN](https://img.shields.io/badge/UCAN-v0.9.1-blue)

An implementation of [UCAN][]s in [IPLD][] via [Advanced Data Layout (ADL)](ADL), designed for use with [multiformats][].

![mascot][]


## Overview

This library provides an [ADL][] for representing [UCAN]s natively in [IPLD][]. It implements [UCAN IPLD][] specification and uses [DAG-CBOR][] as a primary encoding, which is hash consistent and more compact than a secondary RAW JWT encoding. Every UCAN in either encoding can be formatted into a valid JWT string and consumed by other spec compliant [UCAN][] implementations. However [UCAN][]s issued by other libraries may end up in represented in secondory RAW JWT encoding, that is because whitespaces and key order in JWT affects signatures and there for can't be represented accurately in CBOR. When parsing UCANs library will use CBOR representation and fallback to RAW JWT, which allows interop with all existing tokens in the wild.


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
  proofs: [await UCAN.link(proof, { hasher: identity })],
})
```

## License

Licensed under either of

- Apache 2.0, ([LICENSE-APACHE](LICENSE-APACHE) / <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT ([LICENSE-MIT](LICENSE-MIT) / <http://opensource.org/licenses/MIT>)


## Contribute

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.


[ipld]: https://ipld.io/
[ucan]: https://github.com/ucan-wg/spec/
[ucan ipld]: https://github.com/ucan-wg/ucan-ipld/
[ipld schema]: https://ipld.io/docs/schemas/using/authoring-guide/
[dag-cbor]: https://ipld.io/docs/codecs/known/dag-cbor/
[multiformats]: https://github.com/multiformats/js-multiformats
[adl]: https://ipld.io/docs/advanced-data-layouts/
[mascot]:https://bafybeiap2x7s5hjxdghbpfzd7kkc6l5vqgbwnj4tjbcivnfjfcobwuqo44.ipfs.w3s.link/UCAN%20IPLD%20Mascot.png
