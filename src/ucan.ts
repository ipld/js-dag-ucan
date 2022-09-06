import type {
  MultihashDigest,
  MultihashHasher,
} from "multiformats/hashes/interface"
import type { MultibaseEncoder } from "multiformats/bases/interface"
import type { code as RAW_CODE } from "multiformats/codecs/raw"
import type { code as CBOR_CODE } from "@ipld/dag-cbor"
import type { Signer, Verifier, Signature } from "./crypto.js"
import type { Phantom, ByteView, ToString } from "./marker.js"
import type { CID as MultiformatsCID } from "multiformats/cid"

export * from "./crypto.js"
export * from "./marker.js"

export type { MultihashDigest, MultibaseEncoder, MultihashHasher }

/**
 * A string-encoded decentralized identity document (DID).
 */
export type DIDString = `did:${string}`

/**
 * DID object representation with a `did` accessor for the {@link DIDString}.
 */
export interface DID {
  did(): DIDString
}

/**
 * Same as {@link DID} as compatibility layer
 * @deprecated
 */
export type Identity = DID

/**
 * A byte-encoded {@link DIDString} that provides a `did` accessor method (see {@link Identity}).
 */
export interface DIDView extends ByteView<DIDString>, Identity{}

/**
 * An {@link Identity} that can verify signatures produced with the algorithm `A` (see {@link Verifier}).
 */
export interface DIDVerifier<A extends number = number>
  extends Verifier<A>, Identity {}

/** 
 * The {@link Identity} that can issue (sign) UCANs using the signing algorithm A 
 */
export interface Issuer<A extends number = number>
  extends Signer<A>, Identity {}

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
  iss: DIDString
  aud: DIDString
  exp: number
  att: C[]
  nnc?: string
  nbf?: number
  fct?: Fact[]
  prf?: ToString<UCANCid>
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
  proofs: UCANCid[]
}

/**
 * IPLD representation of a signed UCAN.
 */
export interface Model<C extends Capability = Capability> extends Data<C> {
  signature: Signature<string>
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
  issuer: Issuer<A>
  audience: Identity
  capabilities: C[]
  lifetimeInSeconds?: number
  expiration?: number
  notBefore?: number

  nonce?: string

  facts?: Fact[]
  proofs?: UCANCid[]
}

/**
 * Represents a UCAN {@link CID} in either IPLD or JWT format
 */
export type UCANCid<
  C extends Capability = Capability,
  A extends number = number
> = (CID<typeof CBOR_CODE, A, 1> | CID<typeof RAW_CODE, A, 1>) & Phantom<C>

/**
 * Represents a UCAN IPLD block
 * 
 * Note: once we change the Capability generic to an array we can merge this with ucanto transport block
 * 
 * @template C - {@link Capability} 
 * @template A - Multicodec code corresponding to the hashing algorithm of the {@link UCANCid}
 */
export interface UCANBlock<
  C extends Capability,
  A extends number
> {
  bytes: ByteView<UCAN<C>>
  cid: UCANCid<C,A>
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
 * Logical representation of *C*ontent *Id*entifier with optional type parameters
 * to capture the CID version, hash algorithm, and content encoding (multicodec) of the
 * identified content.
 *
 * Note: This is not an actual definition from js-multiformats because that one
 * refers to a specific class and therefore is problematic.
 * 
 * It extends Multiformats CID to avoid type issues
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
  V extends CIDVersion = 1
> extends MultiformatsCID {
  readonly version: V
  readonly code: C
  readonly multihash: MultihashDigest<A>
  readonly bytes: Uint8Array

  // readonly asCID: this

  toString<Prefix extends string>(encoder?: MultibaseEncoder<Prefix>): string
}
