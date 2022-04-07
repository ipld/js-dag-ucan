import type { MultihashDigest } from "multiformats/hashes/interface"
import type { MultibaseEncoder } from "multiformats/bases/interface"
import type { sha256 } from "multiformats/hashes/sha2"
import type { Signer, Signature } from "./crypto.js"

export * from "./crypto.js"

export type { MultihashDigest, MultibaseEncoder }
import { code } from "./lib.js"

export { code }
export type Fact = Record<string, unknown>

export interface Issuer<A extends number = number> extends Signer<A> {
  did(): DID
}

export type Audience = DID

export interface Header {
  algorithm: string
  version: string
}

export interface Body<C extends Capability = Capability> {
  audience: DID
  issuer: DID
  capabilities: C[]
  expiration: number
  notBefore?: number
  nonce?: string

  facts?: Fact[]
  proofs: Link<UCAN, 1, typeof code>[]
}
export type JWT<T> = ToString<T>

export interface UCAN<C extends Capability = Capability>
  extends View<C>,
    IR<C> {}
export interface View<C extends Capability = Capability> {
  readonly version: string
  readonly issuer: DID
  readonly audience: DID
  readonly capabilities: C[]
  readonly expiration: number
  readonly notBefore?: number
  readonly nonce?: string

  readonly facts?: Fact[]
  readonly proofs: Link<UCAN, 1, typeof code>[]
}

export interface IR<C extends Capability = Capability> {
  readonly header: ByteView<Header>
  readonly body: ByteView<Body<C>>

  readonly signature: Signature<UCAN<C>>
}

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
  proofs?: Array<Link<UCAN, 1, typeof code>>
}

export interface Capability<
  Can extends `${string}/${string}` = `${string}/${string}`,
  With extends `${string}:${string}` = `${string}:${string}`
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
