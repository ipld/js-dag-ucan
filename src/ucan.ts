import type {
  MultihashDigest,
  MultihashHasher,
} from "multiformats/hashes/interface"
import type { MultibaseEncoder } from "multiformats/bases/interface"
import type { code as RAW_CODE } from "multiformats/codecs/raw"
import type { code as CBOR_CODE } from "@ipld/dag-cbor"
import type * as Crypto from "./crypto.js"
import type { Phantom, ByteView, ToString } from "./marker.js"
import type { CID as MultiformatsCID } from "multiformats/cid"

export * from "./crypto.js"
export * from "./marker.js"

export type Code = typeof CBOR_CODE | typeof RAW_CODE

export type { MultihashDigest, MultibaseEncoder, MultihashHasher }

/**
 * This utility type can be used in place of `T[]` where you
 * want TS to infer things as tuples as opposed to array.
 * Also note that `T[]` could be empty, wheres  `Tuple<T>`
 * will contain at least one `T`.
 */
export type Tuple<T = unknown> = [T, ...T[]]

/**
 * A string-encoded decentralized identity document (DID).
 */
export type DID = `did:${string}`

/**
 * DID object representation with a `did` accessor for the {@link DID}.
 */
export interface Principal {
  did(): DID
}

/**
 * A byte-encoded {@link DID} that provides a `did` accessor method (see {@link Principal}).
 */
export interface DIDView extends ByteView<DID>, Principal {}

/**
 * Entity that can verify UCAN signatures against a {@link Principal} produced with the algorithm `A` (see {@link Crypto.Verifier}).
 */
export interface Verifier<A extends number = number>
  extends Crypto.Verifier<A>,
    Principal {}

/**
 * Entity that can sign UCANs with keys from a {@link Principal} using the signing algorithm A
 */
export interface Issuer<A extends number = number>
  extends Crypto.Signer<A>,
    Principal {}

/**
 * Verifiable facts and proofs of knowledge included in a UCAN {@link Payload} in order to
 * support claimed capabilities.
 * @see https://github.com/ucan-wg/spec/#324-facts
 */
export type Fact = Record<string, unknown>

/**
 * The version of the UCAN spec used to produce a specific UCAN.
 */
export type Version = `${number}.${number}.${number}`

/**
 * A UCAN header, in the format used by the JWT encoding.
 * @see https://github.com/ucan-wg/spec/#31-header
 */
export interface Header {
  ucv: Version
  alg: "EdDSA" | "RS256"
  typ: "JWT"
}

/**
 * A UCAN payload, in the format used by the JWT encoding.
 * @see https://github.com/ucan-wg/spec/#32-payload
 */
export interface Payload<C extends Capabilities = Capabilities> {
  iss: DID
  aud: DID
  exp: number | null
  att: C
  nnc?: string
  nbf?: number
  fct?: Fact[]
  prf?: ToString<Link>
}

/**
 * Represents a UCAN encoded as a JWT string.
 */
export type JWT<C extends Capabilities = Capabilities> = string &
  Phantom<Model<C>>

/**
 * A signed UCAN in either IPLD or JWT format.
 */
export type UCAN<C extends Capabilities = Capabilities> = Model<C> | JWT<C>

/**
 * IPLD representation of an unsigned UCAN.
 */
export interface Data<C extends Capabilities = Capabilities> {
  v: Version
  iss: DIDView
  aud: DIDView
  att: C
  exp: number | null
  nbf?: number
  nnc?: string
  fct: Fact[]
  prf: Link[]
}

/**
 * IPLD representation of a signed UCAN.
 */
export interface Model<C extends Capabilities = Capabilities> extends Data<C> {
  s: Crypto.Signature<string>
}

export type View<C extends Capabilities = Capabilities> =
  | CBORView<C>
  | JWTView<C>

export interface CBORView<C extends Capabilities = Capabilities>
  extends UCANView<C> {
  readonly code: typeof CBOR_CODE
}

/**
 * A {@link View} of a UCAN that has been encoded as a JWT string.
 */
export interface JWTView<C extends Capabilities = Capabilities>
  extends UCANView<C> {
  readonly code: typeof RAW_CODE
  readonly bytes: ByteView<JWT<C>>
}

/**
 * Represents a decoded "view" of a UCAN as a JS object that can be used in your domain logic, etc.
 */
export interface UCANView<C extends Capabilities = Capabilities> {
  readonly model: Model<C>

  readonly issuer: DIDView
  readonly audience: DIDView

  readonly version: Version

  readonly capabilities: C
  readonly expiration: number
  readonly notBefore?: number
  readonly nonce?: string
  readonly facts: Fact[]
  readonly proofs: Link[]

  readonly signature: Crypto.Signature<string>
}

/**
 * Options used when issuing a new UCAN.
 *
 * @template C - {@link Capability}
 * @template A - Signing algorithm
 */
export interface UCANOptions<
  C extends Capabilities = Capabilities,
  A extends number = number
> {
  issuer: Issuer<A>
  audience: Principal
  capabilities: C
  lifetimeInSeconds?: number
  expiration?: number
  notBefore?: number

  nonce?: string

  facts?: Fact[]
  proofs?: Link[]
}

/**
 * Represents a UCAN {@link IPLDLink} in either IPLD or JWT format
 *
 * @template Cap - {@link Capability}
 * @template Alg - multicodec code corresponding to the hashing algorithm of the CID
 */
export type Link<
  Cap extends Capabilities = Capabilities,
  Alg extends number = number
> =
  | IPLDLink<Model<Cap>, typeof CBOR_CODE, Alg>
  | IPLDLink<JWT<Cap>, typeof RAW_CODE, Alg>

/**
 * Represents a UCAN IPLD block
 *
 * Note: once we change the Capability generic to an array we can merge this with ucanto transport block
 *
 * @template C - {@link Capability}
 * @template A - Multicodec code corresponding to the hashing algorithm of the {@link Link}
 */
export interface Block<C extends Capabilities, A extends number> {
  bytes: ByteView<UCAN<C>>
  cid: Link<C, A>
  data?: UCAN<C>
}

/**
 * A string that represents some action that a UCAN holder can do.
 */
export type Ability = `${string}/${string}` | "*"

/**
 * A string that represents resource a UCAN holder can act upon.
 */
export type Resource = `${string}:${string}`

/**
 * Represents an {@link Ability} that a UCAN holder `Can` perform `With` some {@link Resource}.
 *
 * @template Can - the {@link Ability} (action/verb) the UCAN holder can perform
 * @template With - the {@link Resource} (thing/noun) the UCAN holder can perform their `Ability` on / with
 *
 */
export interface Capability<
  Can extends Ability = Ability,
  With extends Resource = Resource,
  Caveats extends unknown = unknown
> {
  with: With
  can: Can
  nb?: Caveats
}

export type Capabilities = Tuple<Capability>

export type CIDVersion = 0 | 1

/**
 * Represents an IPLD link to a specific data of type `T`.
 *
 * Note: this extends MultiformatsCID until multiformats 10 is shipped
 *
 * @template Data - Logical type of the data being linked to.
 * @template Format - multicodec code corresponding to a codec linked data is encoded with
 * @template Alg - multicodec code corresponding to the hashing algorithm of the CID
 * @template V - CID version
 */
export interface IPLDLink<
  Data extends unknown = unknown,
  Format extends number = number,
  Alg extends number = number,
  V extends CIDVersion = 1
> extends Phantom<Data>,
    MultiformatsCID {
  readonly version: V
  readonly code: Format
  readonly multihash: MultihashDigest<Alg>

  readonly byteOffset: number
  readonly byteLength: number
  readonly bytes: ByteView<IPLDLink<Data, Format, Alg, V>>

  equals(other: unknown): other is IPLDLink<Data, Format, Alg, CIDVersion>
  toString<Prefix extends string>(
    base?: MultibaseEncoder<Prefix>
  ): ToString<IPLDLink<Data, Format, Alg, CIDVersion>, Prefix>
}
