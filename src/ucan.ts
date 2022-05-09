import type {
  MultihashDigest,
  MultihashHasher,
} from "multiformats/hashes/interface"
import type { MultibaseEncoder } from "multiformats/bases/interface"
import type { code as RAW_CODE } from "multiformats/codecs/raw"
import type { code as CBOR_CODE } from "@ipld/dag-cbor"
import type { Signer, Verifier, Signature } from "./crypto.js"

export * from "./crypto.js"

export type { MultihashDigest, MultibaseEncoder, MultihashHasher }

export type Fact = Record<string, unknown>

export interface Identity {
  did(): DID
}

export interface Audience extends Identity {}

export interface Authority<A extends number = number>
  extends Identity,
    Verifier<A> {}

export interface Issuer<A extends number = number>
  extends Signer<A>,
    Identity {}

export type Version = `${number}.${number}.${number}`

export interface Header {
  algorithm: number
  version: Version
}

export interface Body<C extends Capability = Capability> {
  audience: DID
  issuer: DID
  capabilities: C[]
  expiration: number
  notBefore?: number
  nonce?: string

  facts: Fact[]
  proofs: Proof[]
}
export type JWT<C extends Capability = Capability> = ToString<
  [Head, Payload<C>, Signature<`${ToString<Head>}.${ToString<Payload<C>>}>`>],
  `${ToString<Head>}.${ToString<Payload<C>>}.${ToString<
    Signature<`${ToString<Head>}.${ToString<Payload<C>>}>`>
  >}`
>

interface Head {
  ucv: Version
  alg: "EdDSA" | "RS256"
  typ: "JWT"
}

export interface Payload<C extends Capability> {
  iss: DID
  aud: DID
  exp: number
  att: C[]
  nnc?: string
  nbf?: number
  fct?: Fact[]
  prf?: ToString<Proof<C>>
}

export type UCAN<C extends Capability = Capability> = Model<C> | RAW<C>

export interface Input<C extends Capability = Capability> {
  version: Version
  issuer: ByteView<DID>
  audience: ByteView<DID>
  capabilities: C[]
  expiration: number
  notBefore?: number
  nonce?: string
  facts: Fact[]
  proofs: Proof[]
}

export interface Model<C extends Capability = Capability> extends Input<C> {
  signature: Signature<C>
}

export interface RAW<C extends Capability = Capability>
  extends ByteView<JWT<C>> {}

export interface JWTView<C extends Capability = Capability>
  extends ByteView<JWT<C>>,
    View<C> {}

export interface View<C extends Capability = Capability> extends Model<C> {
  readonly model: Model<C>

  issuer: DIDView
  audience: DIDView
}

export interface UCANOptions<
  C extends Capability = Capability,
  A extends number = number
> {
  issuer: Issuer<A>
  audience: Identity
  capabilities: C[]
  lifetimeInSeconds?: number
  expiration?: number
  notBefore?: number

  nonce?: string

  facts?: Fact[]
  proofs?: Array<Proof>
}

export type Proof<
  C extends Capability = Capability,
  A extends number = number
> = Link<Model<C>, 1, typeof CBOR_CODE, A> | Link<JWT<C>, 1, typeof RAW_CODE, A>

export interface Block<
  T extends unknown = unknown,
  C extends number = number,
  A extends number = number
> {
  bytes: ByteView<T>
  cid: Link<T, 1, C, A>
}

export type Ability = `${string}/${string}` | "*"
export type Resource = `${string}:${string}`

export interface Capability<
  Can extends Ability = Ability,
  With extends Resource = Resource
> {
  with: With
  can: Can
}

export type DID<T = unknown> = ToString<T, `did:${string}`>
export interface DIDView extends ByteView<DID>, Identity {}

/**
 * Represents an IPLD link to a specific data of type `T`.
 */

export interface Link<
  T extends unknown = unknown,
  V extends 0 | 1 = 0 | 1,
  C extends number = number,
  A extends number = number
> extends CID<V, C, A>,
    Phantom<T> {}

/**
 * Logical representation of *C*ontent *Id*entifier, where `C` is a logical
 * representation of the content it identifies.
 *
 * Note: This is not an actual definition from multiformats because that one
 * refers to a specific class and there for is problematic.
 *
 * @see https://github.com/multiformats/js-multiformats/pull/161
 */
export interface CID<
  V extends 0 | 1 = 0 | 1,
  C extends number = number,
  A extends number = number
> {
  readonly version: V
  readonly code: C
  readonly multihash: MultihashDigest<A>
  readonly bytes: Uint8Array

  toString<Prefix extends string>(encoder?: MultibaseEncoder<Prefix>): string
}

/**
 * Represents byte encoded representation of the `Data`. It uses type parameter
 * to capture the structure of the data it encodes.
 */
export interface ByteView<Data> extends Uint8Array, Phantom<Data> {}

/**
 * Utility type that retains type information about data of type `In` encoded
 * as `Out`.
 */
export type Encoded<In, Out> = Out & Phantom<In>

/**
 * String encoded `In`.
 */
export type ToString<In, Out extends string = string> = Encoded<In, Out>

/**
 * JSON string encoded `In`.
 */
export type ToJSONString<In, Out extends string = string> = Encoded<In, Out>

/**
 * This is an utility type to retain unused type parameter `T`. It can be used
 * as nominal type e.g. to capture semantics not represented in actual type strucutre.
 */
export interface Phantom<T> {
  // This field can not be represented because field name is non-existings
  // unique symbol. But given that field is optional any object will valid
  // type contstraint.
  [PhantomKey]?: T
}

declare const PhantomKey: unique symbol
