import * as UCAN from "./ucan.js"
import * as UTF8 from "./utf8.js"
import { base64urlpad } from "multiformats/bases/base64"
import * as json from "@ipld/dag-json"
import { CID } from "multiformats"
import { identity } from "multiformats/hashes/identity"
import * as raw from "multiformats/codecs/raw"

/**
 * Parse JWT formatted UCAN. Note than no validation takes place here.
 *
 * @template {UCAN.Capability} C
 * @param {UCAN.JWT<UCAN.Data<C>>} input
 * @returns {UCAN.Data<C>}
 */
export const parse = input => {
  const segments = input.split(".")
  const [header, body, signature] =
    segments.length === 3
      ? segments
      : ParseError.throw(
          `Can't parse UCAN: ${input}: Expected JWT format: 3 dot-separated base64url-encoded values.`
        )

  return {
    header: parseHeader(header),
    body: parseBody(body),
    signature: base64urlpad.baseDecode(signature),
  }
}

/**
 * @param {string} header
 * @returns {UCAN.Header}
 */
export const parseHeader = header => {
  const { ucv, alg, typ } = json.decode(base64urlpad.baseDecode(header))

  const _type = parseJWT(typ)

  return {
    version: parseUCV(ucv),
    algorithm: parseAlgorithm(alg),
  }
}

/**
 * @template {UCAN.Capability} C
 * @param {string} input
 * @returns {UCAN.Body<C>}
 */
export const parseBody = input => {
  const body = json.decode(base64urlpad.baseDecode(input))

  return {
    issuer: parseDID(body.iss),
    audience: parseDID(body.aud),
    expiration: parseInt(body.exp, 10),
    nonce: parseOptionalString(body.nnc, "nnc"),
    notBefore: parseMaybeInt(body.nbf, "nbf"),
    facts: parseOptionalArray(body.fct, parseFact, "fct") || [],
    proofs: parseProofs(body.prf),
    capabilities: /** @type {C[]} */ (
      parseArray(body.att, parseCapability, "att")
    ),
  }
}

/**
 * @param {unknown} input
 */

const parseCapability = input => parseStruct(input, asCapability, "att")

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
 * @param {(input:unknown) => T} parser
 * @param {string} context
 * @returns {T[]}
 */
const parseArray = (input, parser, context) =>
  Array.isArray(input)
    ? input.map(parser)
    : ParseError.throw(`${context} must be an array`)

/**
 * @template T
 * @param {unknown} input
 * @param {(input:unknown) => T} parser
 * @param {string} context
 * @returns {T[]|undefined}
 */
const parseOptionalArray = (input, parser, context) =>
  input === undefined ? input : parseArray(input, parser, context)

/**
 * @template T
 * @param {unknown} input
 * @param {(input:object) => T} parser
 * @param {string} context
 * @returns {T}
 */
const parseStruct = (input, parser, context) =>
  input != null && typeof input === "object"
    ? parser(input)
    : ParseError.throw(`${context} must be of type object`)

/**
 * @param {unknown} input
 * @returns {UCAN.Fact}
 */
const parseFact = input => parseStruct(input, Object, "fct elements")

/**
 * @param {unknown} input
 */
const parseProofs = input =>
  Array.isArray(input)
    ? parseArray(input, parseProof, "prf")
    : [parseProof(input)]

/**
 * @param {unknown} input
 * @returns {UCAN.Proof}
 */
const parseProof = input => {
  const proof =
    typeof input === "string"
      ? input
      : ParseError.throw(
          `prf has invalid value ${JSON.stringify(input)}, must be a string`
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
 * @returns {UCAN.DID}
 */
const parseDID = input =>
  typeof input === "string" && input.startsWith("did:")
    ? /** @type {UCAN.DID} */ (input)
    : ParseError.throw(`DID has invalid representation '${input}'`)

/**
 * @param {unknown} input
 * @param {string} [context]
 */
const parseOptionalString = (input, context = "Field") => {
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
 * @param {string} [context]
 */
const parseMaybeInt = (input, context = "Field") => {
  switch (typeof input) {
    case "undefined":
      return undefined
    case "number":
      return parseInt(/** @type {any} */ (input), 10)
    default:
      return ParseError.throw(
        `${context} has invalid value ${JSON.stringify(input)}`
      )
  }
}

/**
 * @param {unknown} input
 * @returns {UCAN.Version}
 */
const parseUCV = input =>
  /\d+\.\d+\.\d+/.test(/** @type {string} */ (input))
    ? /** @type {UCAN.Version} */ (input)
    : ParseError.throw(`Header has invalid version 'ucv: "${input}"'`)

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

class ParseError extends TypeError {
  /**
   * @param {string} message
   * @returns {never}
   */
  static throw(message) {
    throw new this(message)
  }
}
