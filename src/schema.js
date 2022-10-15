import * as UCAN from "./ucan.js"
import * as UTF8 from "./utf8.js"
import * as Link from "multiformats/link"
import { identity } from "multiformats/hashes/identity"
import * as DID from "./did.js"
import * as raw from "multiformats/codecs/raw"
import * as Signature from "./signature.js"

/**
 * @template {UCAN.Capabilities} C
 * @param {Record<string, unknown>|UCAN.Payload<C>} data
 * @returns {UCAN.Payload<C>}
 */
export const readPayload = data =>
  readPayloadWith(data, {
    readPrincipal,
    readProof,
  })

/**
 * @template {UCAN.Capabilities} C
 * @param {Record<string, unknown>|UCAN.Payload<C>} data
 * @returns {UCAN.Payload<C>}
 */
export const readJWTPayload = data =>
  readPayloadWith(data, {
    readPrincipal: readStringPrincipal,
    readProof: readStringProof,
  })
/**
 *
 * @template {UCAN.Capabilities} C
 * @param {Record<string, unknown>|UCAN.Payload<C>} data
 * @param {object} readers
 * @param {(source:unknown, context:string) => UCAN.Principal} readers.readPrincipal
 * @param {(source:unknown, context:string) => UCAN.Link} readers.readProof
 * @returns {UCAN.Payload<C>}
 */
const readPayloadWith = (data, { readPrincipal, readProof }) => ({
  iss: readPrincipal(data.iss, "iss"),
  aud: readPrincipal(data.aud, "aud"),
  att: readCapabilities(data.att, "att"),
  prf: readOptionalArray(data.prf, readProof, "prf") || [],
  exp: readNullable(data.exp === Infinity ? null : data.exp, readInt, "exp"),
  nbf: readOptional(data.nbf, readInt, "nbf"),
  fct: readOptionalArray(data.fct, readFact, "fct") || [],
  nnc: readOptional(data.nnc, readString, "nnc"),
})

/**
 * @template {unknown} T
 * @template {number} A
 * @param {UCAN.ByteView<UCAN.Signature<T, A>>|unknown} source
 */
export const readSignature = source => {
  if (source instanceof Uint8Array) {
    return Signature.decode(source)
  } else {
    throw new TypeError(
      `Can only decode Uint8Array into a Signature, instead got ${JSON.stringify(
        source
      )}`
    )
  }
}

/**
 * @param {unknown} input
 * @param {string} name
 * @returns {number}
 */
export const readInt = (input, name) =>
  Number.isInteger(input)
    ? /** @type {number} */ (input)
    : ParseError.throw(
        `Expected ${name} to be integer, instead got ${JSON.stringify(input)}`
      )

/**
 * @param {unknown} input
 * @param {string} context
 */

export const readCapability = (input, context) =>
  readStruct(input, asCapability, context)

/**
 * @template {UCAN.Capabilities} C
 * @param {unknown|C} input
 * @param {string} context
 * @returns {C}
 */
export const readCapabilities = (input, context) =>
  /** @type {C} */ (readArray(input, readCapability, context))

/**
 * @template {UCAN.Capability} C
 * @param {object & {can?:unknown, with?:unknown}|C} input
 * @returns {C}
 */
export const asCapability = input =>
  /** @type {C} */ ({
    ...input,
    can: readAbility(input.can),
    with: readResource(input.with),
  })

/**
 * @param {unknown} input
 */
const readAbility = input =>
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
const readResource = input =>
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
 * @param {(input:unknown, context:string) => T} read
 * @param {string} context
 * @returns {T[]}
 */
export const readArray = (input, read, context) =>
  Array.isArray(input)
    ? input.map((element, n) => read(element, `${context}[${n}]`))
    : ParseError.throw(`${context} must be an array`)

/**
 * @template T
 * @param {unknown} input
 * @param {(input:unknown, context: string) => T} reader
 * @param {string} context
 * @returns {T[]|undefined}
 */
export const readOptionalArray = (input, reader, context) =>
  input === undefined ? input : readArray(input, reader, context)

/**
 * @template T
 * @param {unknown} input
 * @param {(input:object) => T} reader
 * @param {string} context
 * @returns {T}
 */
export const readStruct = (input, reader, context) =>
  input != null && typeof input === "object"
    ? reader(input)
    : ParseError.throw(
        `${context} must be of type object, instead got ${input}`
      )

/**
 * @param {unknown} input
 * @param {string} context
 * @returns {UCAN.Fact}
 */
export const readFact = (input, context) => readStruct(input, Object, context)

/**
 * @param {unknown} source
 * @param {string} context
 * @returns {UCAN.Link}
 */
export const readProof = (source, context) =>
  Link.isLink(source)
    ? /** @type {UCAN.Link} */ (source)
    : fail(
        `Expected ${context} to be IPLD link, instead got ${JSON.stringify(
          source
        )}`
      )

/**
 * @param {unknown} source
 * @param {string} context
 * @returns {UCAN.Link}
 */
export const readStringProof = (source, context) =>
  parseProof(readString(source, context))

/**
 * @param {string} source
 * @returns {UCAN.Link}
 */
const parseProof = source => {
  // First we attempt to read proof as CID, if we fail fallback to reading it as
  // an inline proof.
  try {
    return Link.parse(source)
  } catch (error) {
    return Link.create(raw.code, identity.digest(UTF8.encode(source)))
  }
}

/**
 * @param {unknown} input
 * @param {string} context
 */
export const readPrincipal = (input, context) =>
  DID.decode(readBytes(input, context))

/**
 * @param {unknown} source
 * @param {string} context
 */
export const readStringPrincipal = (source, context) =>
  DID.parse(readString(source, context))

/**
 * @template T
 * @param {unknown} source
 * @param {(source:unknown, context:string) => T} read
 * @param {string} [context]
 * @returns {T|undefined}
 */
export const readOptional = (source, read, context = "Field") =>
  source !== undefined ? read(source, context) : undefined

/**
 * @template T
 * @param {unknown} source
 * @param {(source:unknown, context:string) => T} read
 * @param {string} context
 * @returns {T|null}
 */
export const readNullable = (source, read, context) =>
  source === null ? null : read(source, context)

/**
 * @param {unknown} source
 * @param {string} [context]
 * @returns {string}
 */
export const readString = (source, context = "Field") =>
  typeof source === "string"
    ? source
    : fail(`${context} has invalid value ${source}`)

/**
 *
 * @param {unknown} source
 * @param {string} context
 * @returns {Uint8Array}
 */
export const readBytes = (source, context) =>
  source instanceof Uint8Array
    ? source
    : fail(
        `Expected ${context} to be Uint8Array, instead got ${JSON.stringify(
          source
        )}`
      )

/**
 * @param {unknown} input
 * @param {string} context
 * @returns {UCAN.Version}
 */
export const readVersion = (input, context) =>
  /\d+\.\d+\.\d+/.test(/** @type {string} */ (input))
    ? /** @type {UCAN.Version} */ (input)
    : ParseError.throw(`Invalid version '${context}: ${JSON.stringify(input)}'`)

/**
 * @template {string|number|boolean|null} T
 * @param {unknown} input
 * @param {T} literal
 * @param {string} context
 * @returns {T}
 */
export const readLiteral = (input, literal, context) =>
  input === literal
    ? literal
    : ParseError.throw(
        `Expected ${context} to be a ${JSON.stringify(
          literal
        )} instead got ${JSON.stringify(input)}`
      )

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

/**
 * @param {string} reason
 */
export const fail = reason => ParseError.throw(reason)

export { fail as throw }
