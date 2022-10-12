import * as UCAN from "./ucan.js"
import * as CBOR from "./codec/cbor.js"
import * as RAW from "multiformats/codecs/raw"
import * as UTF8 from "./utf8.js"
import * as View from "./view.js"
import * as Parser from "./parser.js"
import * as Formatter from "./formatter.js"
import { sha256 } from "multiformats/hashes/sha2"
import { create as createIPLDLink } from "multiformats/link"
import { format as formatDID } from "./did.js"

export * from "./ucan.js"

/** @type {UCAN.Version} */
export const VERSION = "0.9.1"
export const name = "dag-ucan"

export const code = /** @type {typeof CBOR.code|typeof RAW.code} */ (CBOR.code)

/**
 * We cast sha256 to workaround typescripts limited inference problem when using
 * sha256 as default. If hasher is omitted type `A` should match shar256.code
 * but TS fails to deduce that.
 * @type {UCAN.MultihashHasher<any>}
 */
const defaultHasher = sha256

/**
 * Encodes given UCAN (in either IPLD or JWT representation) and encodes it into
 * corresponding bytes representation. UCAN in IPLD representation is encoded as
 * DAG-CBOR which JWT representation is encoded as raw bytes of JWT string.
 *
 * @template {UCAN.Capabilities} C
 * @param {UCAN.View<C>} ucan
 * @returns {UCAN.ByteView<UCAN.UCAN<C>>}
 */
export const encode = ucan =>
  ucan.code === RAW.code ? ucan.bytes : CBOR.encode(ucan.model)
/**
 * Decodes binary encoded UCAN. It assumes UCAN is in primary IPLD
 * representation and attempts to decode it with DAG-CBOR, if that
 * fails it falls back to secondary representation and parses it as
 * a JWT.
 *
 * @template {UCAN.Capabilities} C
 * @param {UCAN.ByteView<UCAN.Model<C>|UCAN.JWT<C>>} bytes
 * @returns {UCAN.View<C>}
 */
export const decode = bytes => {
  /** @type {Uint8Array} */
  const buffer = bytes
  try {
    return View.cbor(CBOR.decode(buffer))
  } catch (error) {
    return View.jwt(Parser.parse(UTF8.decode(buffer)), buffer)
  }
}

/**
 * Convenience function to create a CID for the given UCAN. If UCAN is
 * in JWT represetation get CID with RAW multicodec, while UCANs in IPLD
 * representation get UCAN multicodec code.
 *
 * @template {UCAN.Capabilities} C
 * @param {UCAN.View<C>} ucan
 * @param {{hasher?: UCAN.MultihashHasher}} [options]
 */
export const link = async (ucan, options) => {
  const { cid } = await write(ucan, options)
  return cid
}

/**
 * @template {UCAN.Capabilities} C
 * @template {number} [A=typeof sha256.code] - Multihash code
 * @param {UCAN.View<C>} ucan
 * @param {{hasher?: UCAN.MultihashHasher<A>}} options
 * @returns {Promise<UCAN.Block<C, typeof code, A>>}
 */
export const write = async (ucan, { hasher = defaultHasher } = {}) => {
  /** @type {UCAN.ByteView<UCAN.UCAN<C>>} */
  const bytes = ucan.code === RAW.code ? ucan.bytes : CBOR.encode(ucan.model)
  const digest = await hasher.digest(bytes)
  const link = /** @type {UCAN.Link<C, typeof code, A>} */ (
    createIPLDLink(ucan.code, digest)
  )

  return {
    bytes,
    cid: link,
    data: ucan.model,
  }
}

/**
 * Parses UCAN formatted as JWT string. Returns UCAN view in IPLD representation
 * when serailazing it back would produce original string, oherwise returns UCAN
 * view in secondary JWT representation which is not as compact, but it retains
 * key order and whitespaces so it could be formatted back to same JWT string.
 * View will have `type` field with either `"IPLD"` or `"JWT"` value telling
 * in which representation UCAN is.
 *
 * Note: Parsing does not perform validation of capabilities or semantics of the
 * UCAN, it only ensures structure is spec compliant and throws `ParseError`
 * if it is not.
 *
 * @template {UCAN.Capabilities} C
 * @param {UCAN.JWT<C>} jwt
 * @returns {UCAN.View<C>}
 */
export const parse = jwt => {
  const model = Parser.parse(jwt)

  // If formatting UCAN produces same jwt string we can use IPLD representation
  // otherwise we need to fallback to raw representation. This decision will
  // affect how we `encode` the UCAN.
  return Formatter.format(model) === jwt
    ? View.cbor(model)
    : View.jwt(model, UTF8.encode(jwt))
}

/**
 * Takes UCAN object and formats it into JWT string.
 *
 * @template {UCAN.Capabilities} C
 * @param {UCAN.View<C>} ucan
 * @returns {UCAN.JWT<C>}
 */
export const format = ucan =>
  ucan.code === RAW.code
    ? UTF8.decode(ucan.bytes)
    : Formatter.format(ucan.model)

/**
 * Creates a new signed token with a given `options.issuer`. If expiration is
 * not set it defaults to 30 seconds from now. Returns UCAN in primary - IPLD
 * representation.
 *
 * @template {number} A
 * @template {UCAN.Capabilities} C
 * @param {UCAN.UCANOptions<C, A>} options
 * @returns {Promise<UCAN.View<C>>}
 */
export const issue = async ({
  issuer,
  audience,
  capabilities,
  lifetimeInSeconds = 30,
  expiration = Math.floor(Date.now() / 1000) + lifetimeInSeconds,
  notBefore,
  facts = [],
  proofs = [],
  nonce,
}) => {
  const data = CBOR.match({
    v: VERSION,
    iss: parseDID(issuer, "issuer"),
    aud: parseDID(audience, "audience"),
    att: capabilities,
    fct: facts,
    exp: expiration,
    nbf: notBefore,
    prf: proofs,
    nnc: nonce,
    // Provide fake signature to pass validation
    // we'll replace this with actual signature
    s: EMPTY,
  })

  const payload = UTF8.encode(
    Formatter.formatSignPayload(data, issuer.signatureAlgorithm)
  )

  const signature = await issuer.sign(payload)
  const model = { ...data, s: signature }

  return View.cbor(model)
}

/**
 * Verifies UCAN signature.
 *
 * @param {UCAN.View} ucan
 * @param {UCAN.Verifier} verifier
 */
export const verifySignature = (ucan, verifier) =>
  formatDID(ucan.issuer) === verifier.did() &&
  verifier.verify(
    UTF8.encode(
      Formatter.formatSignPayload(ucan.model, ucan.signature.algorithm)
    ),
    ucan.signature
  )

/**
 * Check if a UCAN is expired.
 *
 * @param {UCAN.View} ucan
 */
export const isExpired = ucan => ucan.expiration <= now()

/**
 * Check if a UCAN is not active yet.
 * @param {UCAN.View} ucan
 */
export const isTooEarly = ucan =>
  ucan.notBefore != null && now() <= ucan.notBefore

/**
 * Returns UTC Unix timestamp for comparing it against time window of the UCAN.
 */
export const now = () => Math.floor(Date.now() / 1000)

/**
 *
 * @param {unknown & {did?:unknown}} value
 * @param {string} context
 */
const parseDID = (value, context) =>
  value && typeof value.did === "function"
    ? Parser.parseDID(value.did(), `${context}.did()`)
    : Parser.ParseError.throw(
        `The ${context}.did() must be a function that returns DID`
      )

const EMPTY = new Uint8Array()
