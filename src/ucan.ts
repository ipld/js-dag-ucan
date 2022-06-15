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
export * from "./marker.js"

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

export type SignPayload<C extends Capability> = ToString<
  ByteView<[Headers, Payload<C>]>,
  `${ToString<Header>}.${ToString<Payload<C>>}`
>

/**
 * Represents a UCAN encoded as a JWT string.
 */
export type JWT<C extends Capability = Capability> = ToString<
  [Header, Payload<C>, Signature<SignPayload<C>>],
  `${ToString<Header>}.${ToString<Payload<C>>}.${ToString<
    Signature<SignPayload<C>>
  >}`
>

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
  prf?: ToString<Proof<C>>
}

/**
 * A signed UCAN in either IPLD or JWT format.
 */
export type UCAN<C extends Capability = Capability> = Model<C> | RAW<C>

/**
 * IPLD representation of an unsigned UCAN.
 */
export interface Data<C extends Capability = Capability> {
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
export interface Model<C extends Capability = Capability> extends Data<C> {
  signature: Signature<SignPayload<C>>
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
> = Link<Model<C>, typeof CBOR_CODE, A> | Link<JWT<C>, typeof RAW_CODE, A>

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
  A extends number = number,
  V extends CIDVersion = 1
> {
  bytes: ByteView<T>
  cid: Link<T, C, A, V>
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

/**
 * A string-endcoded decentralized identity document (DID).
 */
export type DID<T = unknown> = ToString<T, `did:${string}`>

/**
 * A byte-encoded {@link DID} that provides a `did` accessor method (see {@link Identity}).
 */
export interface DIDView extends ByteView<DID>, Identity {}

export type CIDVersion = 0 | 1

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
  C extends number = number,
  A extends number = number,
  V extends CIDVersion = 1
> extends CID<C, A, V>,
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
 * @template C - multicodec code corresponding to a codec content was encoded in
 * @template A - multicodec code corresponding to the hashing algorithm used to derive CID
 * @template V - CID version
 */
export interface CID<
  C extends number = number,
  A extends number = number,
  V extends CIDVersion = CIDVersion
> {
  readonly version: V
  readonly code: C
  readonly multihash: MultihashDigest<A>
  readonly bytes: Uint8Array

  // readonly asCID: this

  toString<Prefix extends string>(encoder?: MultibaseEncoder<Prefix>): string
}
