import type {
  MultihashDigest,
  MultihashHasher,
} from "multiformats/hashes/interface"
import type { MultibaseEncoder } from "multiformats/bases/interface"
import type { code as RAW_CODE } from "multiformats/codecs/raw"
import type { code as CBOR_CODE } from "@ipld/dag-cbor"
import type { Signer, Verifier, Signature } from "./crypto.js"
import type { Phantom, ByteView, ToString } from "./marker.js"

export * from "./crypto.js"

export type { MultihashDigest, MultibaseEncoder, MultihashHasher }

/**
 * Verifiable facts and proofs of knowledge included in a UCAN {@link Body} in order to
 * support claimed capabilities.
 * @see https://github.com/ucan-wg/spec/#324-facts
 */
export type Fact = Record<string, unknown>

/**
 * A participant in the UCAN system that can be identified by {@link DID}.
 */
export interface Identity {
  did(): DID
}

/**
 * The intended recipient of a given UCAN.
 */
export interface Audience extends Identity {}

/**
 * An {@link Identity} that can verify signatures produced with the algorithm `A` (see {@link Verifier}).
 */
export interface Authority<A extends number = number>
  extends Identity,
    Verifier<A> {}

/** The {@link Identity} that can issue / delegate UCAN by signing */
export interface Issuer<A extends number = number>
  extends Signer<A>,
    Identity {}

/** The version of the UCAN spec used to produce a specific UCAN. */
export type Version = `${number}.${number}.${number}`

/**
 * Represents the body of a UCAN.
 */
export interface Body<C extends Capability = Capability> {
  /** Identifies the intended recipient of the UCAN */
  audience: DID

  /** Identifies the creator and signer of the UCAN */
  issuer: DID

  /** The {@link Capability} set that this UCAN allows. */
  capabilities: C[]

  /**
   * UNIX epoch timestamp of the UCAN's expiration date.
   */
  expiration: number

  /** Optional UNIX epoch timestamp that sets the start of the UCAN's validity period. If not set, anything before {@link expiration} is considered valid. */
  notBefore?: number

  /** Optional nonce to include, e.g. for replay attack prevention. */
  nonce?: string

  /**
   * Set of {@link Fact}s to include in the UCAN body.
   */
  facts: Fact[]

  /** Chain of {@link Proof}s that can be used to validate the claims and scope of this UCAN. */
  proofs: Proof[]
}

/**
 * Represents a UCAN encoded as a JWT string.
 */
export type JWT<C extends Capability = Capability> = ToString<
  [
    Header,
    Payload<C>,
    Signature<`${ToString<Header>}.${ToString<Payload<C>>}>`>
  ],
  `${ToString<Header>}.${ToString<Payload<C>>}.${ToString<
    Signature<`${ToString<Header>}.${ToString<Payload<C>>}>`>
  >}`
>

/** A UCAN {@link Header} in the format used by the JWT encoding. */
export interface Header {
  ucv: Version
  alg: "EdDSA" | "RS256"
  typ: "JWT"
}

/** A UCAN {@link Body}, in the format used by the JWT encoding. */
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

/**
 * A signed UCAN in either IPLD or JWT format.
 */
export type UCAN<C extends Capability = Capability> = Model<C> | RAW<C>

/**
 * IPLD representation of an unsigned UCAN.
 */
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

/**
 * IPLD representation of a signed UCAN.
 */
export interface Model<C extends Capability = Capability> extends Input<C> {
  signature: Signature<C>
}

/**
 * The UTF-8 {@link ByteView} of a UCAN encoded as a JWT string.
 */
export interface RAW<C extends Capability = Capability>
  extends ByteView<JWT<C>> {}

/** A {@link View} of a UCAN that has been encoded as a JWT string. */
export interface JWTView<C extends Capability = Capability>
  extends ByteView<JWT<C>>,
    View<C> {}

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
 */
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

/**
 * Represents a {@link Link} to a UCAN (in either IPLD or JWT format) that serves as
 * proof for the capabilities claimed in another UCAN.
 */
export type Proof<
  C extends Capability = Capability,
  A extends number = number
> = Link<Model<C>, 1, typeof CBOR_CODE, A> | Link<JWT<C>, 1, typeof RAW_CODE, A>

/**
 * Represents an IPLD block (including its CID) that can be decoded to data of type `T`.
 *
 * @template T logical type of the data encoded in the block. This is distinct from the multicodec code of the block's {@link CID}, which is represented by `C`.
 * @template C - multicodec code corresponding to codec used to encode the block
 * @template A - multicodec code corresponding to the hashing algorithm used in creating CID
 */
export interface Block<
  T extends unknown = unknown,
  C extends number = number,
  A extends number = number
> {
  bytes: ByteView<T>
  cid: Link<T, 1, C, A>
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
 * A string-endcoded decentralized identity document (DID).
 */
export type DID<T = unknown> = ToString<T, `did:${string}`>

/**
 * A byte-encoded {@link DID} that provides a `did` accessor method (see {@link Identity}).
 */
export interface DIDView extends ByteView<DID>, Identity {}

/**
 * Represents an IPLD link to a specific data of type `T`.
 *
 * @template T logical type of the data being linked to. This is distinct from the multicodec code of the underlying {@link CID}, which is represented by `C`.
 * @template V - CID version
 * @template C - multicodec code corresponding to a codec linked data is encoded with
 * @template A - multicodec code corresponding to the hashing algorithm of the CID
 */

export interface Link<
  T extends unknown = unknown,
  V extends 0 | 1 = 0 | 1,
  C extends number = number,
  A extends number = number
> extends CID<V, C, A>,
    Phantom<T> {}

/**
 * Logical representation of *C*ontent *Id*entifier with optional type parameters
 * to capture the CID version, hash algorithm, and content encoding (multicodec) of the
 * identified content.
 *
 * Note: This is not an actual definition from js-multiformats because that one
 * refers to a specific class and therefore is problematic.
 *
 * @see https://github.com/multiformats/js-multiformats/pull/161  which will likely
 * replace this definition once merged.
 *
 * @template V - CID version
 * @template C - multicodec code corresponding to a codec content was encoded in
 * @template A - multicodec code corresponding to the hashing algorithm used to derive CID
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
