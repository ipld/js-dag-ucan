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

export type { MultihashDigest, MultibaseEncoder, MultihashHasher }

/**
 * A string-encoded decentralized identity document (DID).
 */
export type DID = `did:${string}`

/**
 * DID object representation with a `did` accessor for the {@link DID}.
 */
export interface Agent {
  did(): DID
}

/**
 * Same as {@link Agent} as compatibility layer
 * @deprecated
 */
export type Identity = Agent

/**
 * A byte-encoded {@link DID} that provides a `did` accessor method (see {@link Agent}).
 */
export interface DIDView extends ByteView<DID>, Agent{}

/**
 * Entity that can verify UCAN signatures against a {@link Agent} produced with the algorithm `A` (see {@link Crypto.Verifier}).
 */
export interface Verifier<A extends number = number>
  extends Crypto.Verifier<A>, Agent {}

/** 
 * Entity that can sign UCANs with keys from a {@link Agent} using the signing algorithm A 
 */
export interface Signer<A extends number = number>
  extends Crypto.Signer<A>, Agent {}

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
export interface Payload<C extends Capability = Capability> {
  iss: DID
  aud: DID
  exp: number
  att: C[]
  nnc?: string
  nbf?: number
  fct?: Fact[]
  prf?: ToString<Link>
}

/**
 * Represents a UCAN encoded as a JWT string.
 */
export type JWT<C extends Capability = Capability> = string & Phantom<C>

/**
 * A signed UCAN in either IPLD or JWT format.
 */
export type UCAN<C extends Capability = Capability> = Model<C> | RAW<C>

/**
 * IPLD representation of an unsigned UCAN.
 */
export interface Data<C extends Capability = Capability> {
  version: Version
  issuer: DIDView
  audience: DIDView
  capabilities: C[]
  expiration: number
  notBefore?: number
  nonce?: string
  facts: Fact[]
  proofs: Link[]
}

/**
 * IPLD representation of a signed UCAN.
 */
export interface Model<C extends Capability = Capability> extends Data<C> {
  signature: Crypto.Signature<string>
}

/**
 * The UTF-8 {@link ByteView} of a UCAN encoded as a JWT string.
 */
export interface RAW<C extends Capability = Capability>
  extends ByteView<JWT<C>> {}

/** 
 * A {@link View} of a UCAN that has been encoded as a JWT string. 
 */
export interface JWTView<C extends Capability = Capability>
  extends ByteView<JWT<C>>, View<C> {}

/**
 * Represents a decoded "view" of a UCAN as a JS object that can be used in your domain logic, etc.
 */
export interface View<C extends Capability = Capability> extends Model<C> {
  readonly model: Model<C>

  issuer: DIDView
  audience: DIDView
}

/**
 * Options used when issuing a new UCAN.
 * 
 * @template C - {@link Capability}
 * @template A - Signing algorithm
 */
export interface UCANOptions<
  C extends Capability = Capability,
  A extends number = number
> {
  issuer: Signer<A>
  audience: Identity
  capabilities: C[]
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
  Cap extends Capability = Capability,
  Alg extends number = number
> = IPLDLink<Model<Cap>, typeof CBOR_CODE, Alg, 1> | IPLDLink<JWT<Cap>,typeof RAW_CODE, Alg, 1>

/**
 * Represents a UCAN IPLD block
 * 
 * Note: once we change the Capability generic to an array we can merge this with ucanto transport block
 * 
 * @template C - {@link Capability} 
 * @template A - Multicodec code corresponding to the hashing algorithm of the {@link Link}
 */
export interface Block<
  C extends Capability,
  A extends number
> {
  bytes: ByteView<UCAN<C>>
  cid: Link<C,A>
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
  With extends Resource = Resource
> {
  with: With
  can: Can
}

/**
 * Utility type for capturing capability constraints that is fields other than
 * "can" and "with".
 */
export type Constraints<C extends Capability> = Omit<C, "can" | "with">

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
  > extends Phantom<Data>, MultiformatsCID {
  readonly version: V
  readonly code: Format
  readonly multihash: MultihashDigest<Alg>

  readonly byteOffset: number
  readonly byteLength: number
  readonly bytes: ByteView<IPLDLink<Data, Format, Alg, V>>


  equals(other: unknown): other is IPLDLink<Data, Format, Alg, CIDVersion>
  toString<Prefix extends string>(base?: MultibaseEncoder<Prefix>): ToString<IPLDLink<Data, Format, Alg, CIDVersion>, Prefix>
}
