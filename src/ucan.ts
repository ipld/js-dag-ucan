import type {
  MultihashDigest,
  MultihashHasher,
} from "multiformats/hashes/interface"
import type { MultibaseEncoder } from "multiformats/bases/interface"
import type { code as RAW_CODE } from "multiformats/codecs/raw"
import type { Signer, Signature } from "./crypto.js"

export * from "./crypto.js"

export type { MultihashDigest, MultibaseEncoder, MultihashHasher }

export const code = 0x78c0
export type Fact = Record<string, unknown>

export interface Issuer<A extends number = number> extends Signer<A> {
  did(): DID
}

export interface Audience {
  did(): DID
}

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
export type JWT<T> = ToString<T>

export type UCAN<C extends Capability = Capability> = CBOR<C> | RAW<C>

export interface Data<C extends Capability = Capability> {
  readonly header: Header
  readonly body: Body<C>
  readonly signature: Signature<[Header, Body<C>]>
}
export interface CBOR<C extends Capability = Capability> extends Data<C> {
  readonly code: typeof code
}

export interface RAW<C extends Capability = Capability> {
  readonly code: typeof RAW_CODE
  readonly jwt: JWT<RAW<C>>
}

export type View<C extends Capability = Capability> = UCAN<C> &
  Data<C> &
  Header &
  Body<C>

export interface UCANOptions<
  C extends Capability = Capability,
  A extends number = number
> {
  issuer: Issuer<A>
  audience: DID
  capabilities: C[]
  lifetimeInSeconds?: number
  expiration?: number
  notBefore?: number

  nonce?: string

  facts?: Fact[]
  proofs?: Array<Proof>
}

export type Proof<C extends Capability = Capability> =
  | Link<Data<C>, 1, typeof code>
  | Link<JWT<Data<C>>, 1, typeof RAW_CODE>

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
