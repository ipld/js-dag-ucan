import type {
  MultibaseEncoder,
  MultibaseDecoder,
  MultihashDigest,
  MultihashHasher,
  Block as IPLDBlock,
  Link as IPLDLink,
  Version as LinkVersion,
  Phantom,
  ByteView,
} from "multiformats"
import type { code as RAW_CODE } from "multiformats/codecs/raw"
import type { code as CBOR_CODE } from "@ipld/dag-cbor"
import * as Crypto from "./crypto.js"

export * from "./crypto.js"
export type {
  MultibaseEncoder,
  MultibaseDecoder,
  MultihashDigest,
  MultihashHasher,
  IPLDBlock,
  IPLDLink,
  LinkVersion,
  Phantom,
  ByteView,
}

export type Code = typeof CBOR_CODE | typeof RAW_CODE

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
export type DID<Method extends string = string> = `did:${Method}:${string}`

/**
 * DID object representation with a `did` accessor for the {@link DID}.
 */
export interface Principal<Method extends string = string> {
  did(): DID<Method>
}

/**
 * A byte-encoded {@link DID} that provides a `did` accessor method (see {@link Principal}).
 */
export interface PrincipalView<Method extends string = string>
  extends ByteView<Principal<Method>>,
    Principal<Method> {}

/**
 * Entity that can verify UCAN signatures against a {@link Principal} produced with the algorithm `A` (see {@link CryptoVerifier}).
 */
export interface Verifier<
  Method extends string = string,
  A extends number = number
> extends Crypto.Verifier<A>,
    Principal<Method> {}

export interface Audience extends Principal<string> {}
export interface Issuer extends Principal<string> {}
/**
 * Entity that can sign UCANs with keys from a {@link Principal} using the signing algorithm A
 */
export interface Signer<
  Method extends string = string,
  A extends number = number
> extends Crypto.Signer<A>,
    Principal<Method> {
  signatureAlgorithm: string
  signatureCode: A
}

/**
 * Verifiable facts and proofs of knowledge included in a UCAN {@link JWTPayload} in order to
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
export interface JWTHeader {
  ucv: Version
  alg: "EdDSA" | "RS256"
  typ: "JWT"
}

/**
 * A UCAN payload, in the format used by the JWT encoding.
 * @see https://github.com/ucan-wg/spec/#32-payload
 */
export interface JWTPayload<C extends Capabilities = Capabilities> {
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
export type JWT<C extends Capabilities = Capabilities> = ToString<
  UCAN<C>,
  `${ToString<JWTHeader>}.${ToString<
    JWTPayload<C>
  >}.${ToString<Crypto.Signature>}`
>

export interface Header {
  v: Version
}

export interface Payload<C extends Capabilities = Capabilities> {
  iss: Issuer
  aud: Audience
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
export interface Model<C extends Capabilities = Capabilities>
  extends Header,
    Payload<C> {
  s: Crypto.Signature<string>
}

export interface FromJWT<C extends Capabilities = Capabilities>
  extends Model<C> {
  jwt: JWT<C>
}

export interface FromModel<C extends Capabilities = Capabilities>
  extends Model<C> {
  jwt?: never
}

/**
 * A signed UCAN in either IPLD or JWT format.
 */
export type UCAN<C extends Capabilities = Capabilities> =
  | FromJWT<C>
  | FromModel<C>

/**
 * Represents a decoded "view" of a UCAN as a JS object that can be used in your domain logic, etc.
 */
export interface View<C extends Capabilities = Capabilities> extends Model<C> {
  readonly code: Code
  readonly model: Model<C>

  readonly issuer: PrincipalView<string>
  readonly audience: PrincipalView<string>

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
  issuer: Signer<string, A>
  audience: Audience
  capabilities: C
  lifetimeInSeconds?: number
  expiration?: number
  notBefore?: number

  nonce?: string

  facts?: Fact[]
  proofs?: Link[]
}

/**
 * Represents an IPLD link to a UCAN in either IPLD or JWT format
 *
 * @template Cap - {@link Capability}
 * @template Alg - multicodec code corresponding to the hashing algorithm of the CID
 */
export interface Link<
  C extends Capabilities = Capabilities,
  F extends Code = Code,
  A extends number = number
> extends IPLDLink<UCAN<C>, F, A> {}

/**
 * Represents a UCAN IPLD block
 *
 * Note: once we change the Capability generic to an array we can merge this with ucanto transport block
 *
 * @template C - {@link Capabilities}
 * @template A - Multicodec code corresponding to the hashing algorithm of the {@link Link}
 */
export interface Block<
  C extends Capabilities = Capabilities,
  F extends Code = Code,
  A extends number = number
> extends IPLDBlock<UCAN<C>, F, A> {
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

/**
 * Utility type that retains type information about data of type `In`, encoded
 * as type `Out`.
 *
 * For concrete examples see {@link ToString} and {@link ToJSONString}.
 */
export type Encoded<In, Out> = Out & Phantom<In>

/**
 * Data of some type `In`, encoded as a string.
 */
export type ToString<In, Out extends string = string> = Encoded<In, Out>

/**
 * Data of some type `In`, encoded as a JSON string.
 */
export type ToJSONString<In, Out extends string = string> = Encoded<In, Out>
