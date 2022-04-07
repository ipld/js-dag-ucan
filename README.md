# @ipld/dag-ucan

> UCAN codec for IPLD

This package provides an [IPLD][] representation of the [UCAN][]s. It encodes
UCAN as a [DAG-CBOR][] block with a following [IPLD schema][]:

```ipldsch
type UCAN struct {
  header Heder
  body Body
  signature Signature
}

-- Represents json encoded UCAN header { alg: string, ucv: string, typ "JWT" }
type Header = Bytes
-- Represents json encoded UCAN body { iss: string, aud: string, att, exp: number, .. }
type Body = Bytes
-- Represents UCAN signature
type Signature = Bytes
```

## API

```ts
import * as UCAN from "@ipld/dag-ucan"
```

### `UCAN.parse(jwt: string): UCAN.UCAN`

Parses UCAN represented as a JWT into an IPLD representation and wraps it in
a view that provides JS Object interface, e.g.

```ts
const ucan = UCAN.parse(jwt)
ucan.issuer // did:key:zAlice
```

### `UCAN.format(ucan: UCAN.IR): string`

Seralizes UCAN in IPLD representation into a JWT. It is guaranteed that
`UCAN.format(UCAN.parse(jwt)) === jwt`.

### `UCAN.encode(ucan: UCAN.IR): Uint8Array`

Encodes UCAN IPLD object into binary representation.

### `UCAN.decode(bytes: Uint8Array): UCAN.UCAN`

Decodes UCAN in binary representation into IPLD object representation.

### `UCAN.issue(options: UCAN.UCANOptions): Promise<UCAN.UCAN>`

Issues or derives a UCAN. Returns promise for UCAN in IPLD object representation. Please note that no validation takes place ensuring that no capabilitise are escalated.

> Operation is async as it performs crytpographic signing which in browsers is async.

[ipld]: https://ipld.io/
[ucan]: https://github.com/ucan-wg/spec/
[ipld schema]: https://ipld.io/docs/schemas/using/authoring-guide/
[dag-cbor]: https://ipld.io/docs/codecs/known/dag-cbor/
