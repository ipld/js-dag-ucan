import * as UCAN from "./ucan.js"
import * as UTF8 from "./utf8.js"
import { base64url } from "multiformats/bases/base64"
import * as json from "@ipld/dag-json"
import { CID } from "multiformats"
import { identity } from "multiformats/hashes/identity"
import * as DID from "./did.js"
import * as raw from "multiformats/codecs/raw"

/**
 * Parse JWT formatted UCAN. Note than no validation takes place here.
 *
 * @template {UCAN.Capability} C
 * @param {UCAN.JWT<C>} input
 * @returns {UCAN.Model<C>}
 */
export const parse = input => {
  const segments = input.split(".")
  const [header, payload, signature] =
    segments.length === 3
      ? segments
      : ParseError.throw(
          `Can't parse UCAN: ${input}: Expected JWT format: 3 dot-separated base64url-encoded values.`
        )

  return {
    ...parseHeader(header),
    ...parsePayload(payload),
    signature: base64url.baseDecode(signature),
  }
}

/**
 * @param {string} header
 */
export const parseHeader = header => {
  const { ucv, alg, typ } = json.decode(base64url.baseDecode(header))

  const _type = parseJWT(typ)
  const _algorithm = parseAlgorithm(alg)

  return {
    version: parseVersion(ucv, "ucv"),
  }
}

/**
 * @template {UCAN.Capability} C
 * @param {string} input
 */
export const parsePayload = input => {
  /** @type {UCAN.Payload<C>} */
  const payload = json.decode(base64url.baseDecode(input))

  return {
    issuer: parseDID(payload.iss, "iss"),
    audience: parseDID(payload.aud, "aud"),
    expiration: parseInt(payload.exp, "exp"),
    nonce: parseOptionalString(payload.nnc, "nnc"),
    notBefore: parseOptionalInt(payload.nbf, "nbf"),
    facts: parseOptionalArray(payload.fct, parseFact, "fct") || [],
    proofs: parseProofs(payload.prf, "prf"),
    capabilities: /** @type {C[]} */ (parseCapabilities(payload.att, "att")),
  }
}

/**
 * @param {unknown} input
 * @param {string} name
 * @returns {number}
 */
export const parseInt = (input, name) =>
  Number.isInteger(input)
    ? /** @type {number} */ (input)
    : ParseError.throw(
        `Expected integer but instead got '${name}: ${JSON.stringify(input)}'`
      )

/**
 * @param {unknown} input
 * @param {string} context
 */

export const parseCapability = (input, context) =>
  parseStruct(input, asCapability, context)

/**
 * @param {unknown} input
 * @param {string} context
 */
export const parseCapabilities = (input, context) =>
  parseArray(input, parseCapability, context)
/**
 * @template {UCAN.Capability} C
 * @param {object & {can?:unknown, with?:unknown}|C} input
 * @returns {C}
 */
export const asCapability = input => {
  const capability = /** @type {C} */ ({
    ...input,
    can: parseAbility(input.can),
    with: parseResource(input.with),
  })
  const resource = capability.with

  // @see https://github.com/ucan-wg/spec/#422-action
  if (
    resource.endsWith("*") &&
    capability.can !== "*" &&
    (resource.startsWith("my:") || resource.startsWith("as:did:"))
  ) {
    return ParseError.throw(
      `Capability has invalid 'can: ${JSON.stringify(
        input.can
      )}', for all 'my:*' or 'as:<did>:*' it must be '*'.`
    )
  }

  return capability
}

/**
 * @param {unknown} input
 */
const parseAbility = input =>
  typeof input !== "string"
    ? ParseError.throw(
        `Capability has invalid 'can: ${JSON.stringify(
          input
        )}', value must be a string`
      )
    : input.slice(1, -1).includes("/")
    ? /** @type {UCAN.Ability} */ (input.toLocaleLowerCase())
    : input === "*"
    ? input
    : ParseError.throw(
        `Capability has invalid 'can: "${input}"', value must have at least one path segment`
      )

/**
 * @param {unknown} input
 */
const parseResource = input =>
  typeof input !== "string"
    ? ParseError.throw(
        `Capability has invalid 'with: ${JSON.stringify(
          input
        )}', value must be a string`
      )
    : parseURL(input) ||
      ParseError.throw(
        `Capability has invalid 'with: "${input}"', value must be a valid URI string`
      )

/**
 * @param {string} input
 */
const parseURL = input => {
  try {
    new URL(input)
    return input
  } catch (_) {
    return null
  }
}
/**
 * @template T
 * @param {unknown} input
 * @param {(input:unknown, context:string) => T} parser
 * @param {string} context
 * @returns {T[]}
 */
export const parseArray = (input, parser, context) =>
  Array.isArray(input)
    ? input.map((element, n) => parser(element, `${context}[${n}]`))
    : ParseError.throw(`${context} must be an array`)

/**
 * @template T
 * @param {unknown} input
 * @param {(input:unknown, context: string) => T} parser
 * @param {string} context
 * @returns {T[]|undefined}
 */
export const parseOptionalArray = (input, parser, context) =>
  input === undefined ? input : parseArray(input, parser, context)

/**
 * @template T
 * @param {unknown} input
 * @param {(input:object) => T} parser
 * @param {string} context
 * @returns {T}
 */
export const parseStruct = (input, parser, context) =>
  input != null && typeof input === "object"
    ? parser(input)
    : ParseError.throw(
        `${context} must be of type object, instead got ${input}`
      )

/**
 * @param {unknown} input
 * @param {string} context
 * @returns {UCAN.Fact}
 */
export const parseFact = (input, context) => parseStruct(input, Object, context)

/**
 * @param {unknown} input
 * @param {string} context
 */
const parseProofs = (input, context) =>
  Array.isArray(input)
    ? parseArray(input, parseProof, context)
    : [parseProof(input, context)]

/**
 * @param {unknown} input
 * @param {string} context
 * @returns {UCAN.Proof}
 */
const parseProof = (input, context) => {
  const proof =
    typeof input === "string"
      ? input
      : ParseError.throw(
          `${context} has invalid value ${JSON.stringify(
            input
          )}, must be a string`
        )
  try {
    return /** @type {UCAN.Proof} */ (CID.parse(proof))
  } catch (error) {
    return /** @type {UCAN.Proof} */ (
      CID.create(1, raw.code, identity.digest(UTF8.encode(proof)))
    )
  }
}

/**
 * @param {unknown} input
 * @param {string} context
 */
export const parseDID = (input, context) =>
  typeof input === "string" && input.startsWith("did:")
    ? DID.parse(/** @type {UCAN.DID} */ (input))
    : ParseError.throw(
        `DID has invalid representation '${context}: ${JSON.stringify(input)}'`
      )

/**
 * @param {unknown} input
 * @param {string} [context]
 */
export const parseOptionalString = (input, context = "Field") => {
  switch (typeof input) {
    case "string":
    case "undefined":
      return input
    default:
      return ParseError.throw(`${context} has invalid value ${input}`)
  }
}

/**
 * @param {unknown} input
 * @param {string} context
 */
export const parseOptionalInt = (input, context) => {
  switch (typeof input) {
    case "undefined":
      return undefined
    case "number":
      return parseInt(/** @type {any} */ (input), context)
    default:
      return ParseError.throw(
        `${context} has invalid value ${JSON.stringify(input)}`
      )
  }
}

/**
 * @param {unknown} input
 * @param {string} context
 * @returns {UCAN.Version}
 */
export const parseVersion = (input, context) =>
  /\d+\.\d+\.\d+/.test(/** @type {string} */ (input))
    ? /** @type {UCAN.Version} */ (input)
    : ParseError.throw(`Invalid version '${context}: ${JSON.stringify(input)}'`)

/**
 *
 * @param {unknown} input
 * @param {string} context
 * @returns {Uint8Array}
 */
export const parseBytes = (input, context) =>
  input instanceof Uint8Array
    ? input
    : ParseError.throw(
        `${context} must be Uint8Array, instead got ${JSON.stringify(input)}`
      )
/**
 * @param {unknown} input
 * @returns {"JWT"}
 */
const parseJWT = input =>
  input === "JWT"
    ? input
    : ParseError.throw(`Header has invalid type 'typ: "${input}"'`)

/**
 * @param {unknown} input
 */
const parseAlgorithm = input => {
  switch (input) {
    case "EdDSA":
      return 0xed
    case "RS256":
      return 0x1205
    default:
      return ParseError.throw(
        `Header has invalid algorithm 'alg: ${JSON.stringify(input)}'`
      )
  }
}

export class ParseError extends TypeError {
  get name() {
    return "ParseError"
  }
  /**
   * @param {string} message
   * @returns {never}
   */
  static throw(message) {
    throw new this(message)
  }
}
