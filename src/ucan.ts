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
export * as Crypto from "./crypto.js"
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

export type Code =
  | MulticodecCode<typeof CBOR_CODE, "CBOR">
  | MulticodecCode<typeof RAW_CODE, "Raw">

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
export interface Principal<ID extends DID = DID> {
  did(): ID
}

/**
 * A byte-encoded {@link DID} that provides a `did` accessor method (see {@link Principal}).
 */
export interface PrincipalView<ID extends DID = DID>
  extends ByteView<Principal<ID>>,
    Principal<ID> {}

/**
 * Entity that can verify UCAN signatures against a {@link Principal} produced
 * with the algorithm `A` (see {@link Crypto.Verifier}).
 */
export interface Verifier<
  ID extends DID = DID,
  SigAlg extends Crypto.SigAlg = Crypto.SigAlg
> extends Crypto.Verifier<SigAlg>,
    Principal<ID> {}

export interface Audience extends Principal {}
export interface Issuer extends Principal {}
/**
 * Entity that can sign UCANs with keys from a {@link Principal} using the
 * signing algorithm A
 */
export interface Signer<
  ID extends DID = DID,
  SigAlg extends Crypto.SigAlg = Crypto.SigAlg
> extends Crypto.Signer<SigAlg>,
    Principal<ID> {
  /**
   * Integer corresponding to the byteprefix of the {@link Crypto.SigAlg}. It
   * is used to tag [signature] so it can self describe what algorithm was used.
   *
   * [signature]:https://github.com/ucan-wg/ucan-ipld/#25-signature
   */
  signatureCode: SigAlg

  /**
   * Name of the signature algorithm. It is a human readable equivalent of
   * the {@link signatureCode}, however it is also used as last segment in
   * [Nonstandard Signatures], which is used as an `alg` field of JWT header
   * when UCANs are serialized to JWT.
   *
   * [Nonstandard Signatures]:https://github.com/ucan-wg/ucan-ipld/#251-nonstandard-signatures
   */
  signatureAlgorithm: string
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
  alg: "EdDSA" | "RS256" | string
  typ: "JWT"
}

/**
 * A UCAN payload, in the format used by the JWT encoding.
 * @see https://github.com/ucan-wg/spec/#32-payload
 */
export interface JWTPayload<C extends Capabilities = Capabilities> {
  iss: DID
  aud: DID
  exp: UTCUnixTimestamp | null
  att: C
  nnc?: Nonce
  nbf?: UTCUnixTimestamp
  fct?: Fact[]
  prf?: ToString<Link>[]
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
  exp: UTCUnixTimestamp | null
  nbf?: UTCUnixTimestamp
  nnc?: Nonce
  fct: Fact[]
  prf: Link[]
}

/**
 * IPLD representation of a signed UCAN.
 */
export interface Model<C extends Capabilities = Capabilities>
  extends Header,
    Payload<C> {
  s: Crypto.SignatureView
}

export type UCANJSON<T extends UCAN = UCAN> = ToJSON<
  T,
  {
    v: Version
    iss: DID
    aud: DID
    s: Crypto.SignatureJSON
    att: ToJSON<T["att"]>
    prf: { "/": ToString<Link> }[]
    exp: UTCUnixTimestamp
    fct?: ToJSON<T["fct"]>
    nnc?: Nonce
    nbf?: UTCUnixTimestamp
  }
>

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

  readonly issuer: PrincipalView
  readonly audience: PrincipalView

  readonly version: Version

  readonly capabilities: C
  readonly expiration: UTCUnixTimestamp
  readonly notBefore?: UTCUnixTimestamp
  readonly nonce?: Nonce
  readonly facts: Fact[]
  readonly proofs: Link[]

  readonly signature: Crypto.SignatureView

  encode(): ByteView<UCAN<C>>
  format(): JWT<C>
  toJSON(): UCANJSON<this>
}

/**
 * Options used when issuing a new UCAN.
 *
 * @template C - {@link Capability}
 * @template A - Signing algorithm
 */
export interface UCANOptions<
  C extends Capabilities = Capabilities,
  SigAlg extends Crypto.SigAlg = Crypto.SigAlg
> {
  issuer: Signer<DID, SigAlg>
  audience: Audience
  capabilities: C
  lifetimeInSeconds?: number
  expiration?: UTCUnixTimestamp
  notBefore?: UTCUnixTimestamp

  nonce?: Nonce

  facts?: Fact[]
  proofs?: Link[]
}

/**
 * Represents an IPLD link to a UCAN in either IPLD or JWT format
 *
 * @template Cap - {@link Capability}
 * @template Encoding - multicodec code corresponding to the encoding
 * @template SigAlg - multicodec code corresponding to the hashing algorithm of the CID
 */
export interface Link<
  C extends Capabilities = Capabilities,
  Encoding extends MulticodecCode = MulticodecCode,
  SigAlg extends Crypto.SigAlg = Crypto.SigAlg
> extends IPLDLink<UCAN<C>, Encoding, SigAlg> {}

/**
 * Represents a UCAN IPLD block
 *
 * Note: once we change the Capability generic to an array we can merge this with ucanto transport block
 *
 * @template C - {@link Capabilities}
 * @template Encoding - multicodec code corresponding to the encoding
 * @template SigAlg - Multicodec code corresponding to the hashing algorithm of the {@link Link}
 */
export interface Block<
  C extends Capabilities = Capabilities,
  Encoding extends MulticodecCode = MulticodecCode,
  SigAlg extends Crypto.SigAlg = Crypto.SigAlg
> extends IPLDBlock<UCAN<C>, Encoding, SigAlg> {
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

export type JSONScalar = null | boolean | number | string
export type JSONObject = {
  [key: string]: JSONUnknown | Phantom<unknown>
}
export type JSONUnknown = JSONScalar | JSONObject | JSONUnknown[]

/**
 * JSON representation
 */
export type ToJSON<In, Out extends JSONUnknown = IntoJSON<In>> = Encoded<
  In,
  Out
>

export type IntoJSON<T> = T extends JSONScalar
  ? T
  : T extends { toJSON(): infer U }
  ? IntoJSON<U>
  : T extends Array<infer U>
  ? IntoJSON<U>[]
  : T extends JSONObject
  ? IntoJSONObject<T>
  : never

export type IntoJSONObject<T extends JSONObject> = {
  [K in keyof T]: IntoJSON<T[K]>
}

/**
 * [Multicodec code] usually used to tag [multiformat].
 *
 * [multiformat]:https://multiformats.io/
 * [multicodec code]:https://github.com/multiformats/multicodec/blob/master/table.csv
 */
export type MulticodecCode<
  Code extends number = number,
  Name extends string = string
> = Code & Phantom<Name>

/**
 * UTC Unix Timestamp
 */
export type UTCUnixTimestamp = number
export type Nonce = string
