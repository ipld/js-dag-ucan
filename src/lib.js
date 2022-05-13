import * as UCAN from "./ucan.js"
import * as CBOR from "./codec/cbor.js"
import * as RAW from "./codec/raw.js"
import * as UTF8 from "./utf8.js"
import * as View from "./view.js"
import * as Parser from "./parser.js"
import * as Formatter from "./formatter.js"
import { sha256 } from "multiformats/hashes/sha2"
import { CID } from "multiformats/cid"
import { format as formatDID } from "./did.js"

export * from "./ucan.js"

/** @type {UCAN.Version} */
export const VERSION = "0.8.1"
export const name = "dag-ucan"

/** @type {typeof CBOR.code|typeof RAW.code} */
export const code = CBOR.code

/**
 * Encodes given UCAN (in either IPLD or JWT representation) and encodes it into
 * corresponding bytes representation. UCAN in IPLD representation is encoded as
 * DAG-CBOR which JWT representation is encoded as raw bytes of JWT string.
 *
 * @template {UCAN.Capability} C
 * @param {UCAN.UCAN<C>} ucan
 * @returns {UCAN.ByteView<UCAN.UCAN<C>>}
 */
export const encode = ucan =>
  ucan instanceof Uint8Array ? RAW.encode(ucan) : CBOR.encode(ucan)

/**
 * Decodes binary encoded UCAN. It assumes UCAN is in primary IPLD
 * representation and attempts to decode it with DAG-CBOR, if that
 * fails it falls back to secondary representation and parses it as
 * a JWT.
 *
 * @template {UCAN.Capability} C
 * @param {UCAN.ByteView<UCAN.UCAN<C>>} bytes
 * @returns {UCAN.View<C>}
 */
export const decode = bytes => {
  try {
    return CBOR.decode(/** @type {UCAN.ByteView<UCAN.Model<C>>} */ (bytes))
  } catch (error) {
    const jwt = UTF8.decode(/** @type {UCAN.RAW<C>} */ (bytes))
    return parse(jwt)
  }
}

/**
 * Convenience function to create a CID for the given UCAN. If UCAN is
 * in JWT represetation get CID with RAW multicodec, while UCANs in IPLD
 * representation get UCAN multicodec code.
 *
 * @template {UCAN.Capability} C
 * @param {UCAN.UCAN<C>} ucan
 * @param {{hasher?: UCAN.MultihashHasher}} [options]
 */
export const link = async (ucan, options) => {
  const { cid } = await write(ucan, options)
  return cid
}

/**
 * @template {UCAN.Capability} C
 * @template {number} [A=number]
 * @param {UCAN.UCAN<C>} data
 * @param {{hasher?: UCAN.MultihashHasher<A>}} [options]
 * @returns {Promise<{cid:UCAN.Proof<C> & CID, bytes: UCAN.ByteView<UCAN.UCAN<C>>, data: UCAN.UCAN<C> }>}
 */
export const write = async (
  data,
  { hasher = /** @type {UCAN.MultihashHasher<any> } */ (sha256) } = {}
) => {
  const [code, bytes] =
    data instanceof Uint8Array
      ? [RAW.code, RAW.encode(data)]
      : [CBOR.code, CBOR.encode(data)]

  const cid = /** @type {CID & UCAN.Proof<C, A>} */ (
    CID.createV1(code, await hasher.digest(bytes))
  )
  return { cid, bytes, data }
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
 * @template {UCAN.Capability} C
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
 * @template {UCAN.Capability} C
 * @param {UCAN.UCAN<C>} ucan
 * @returns {UCAN.JWT<C>}
 */
export const format = ucan =>
  ucan instanceof Uint8Array ? UTF8.decode(ucan) : Formatter.format(ucan)

/**
 * Creates a new signed token with a given `options.issuer`. If expiration is
 * not set it defaults to 30 seconds from now. Returns UCAN in primary - IPLD
 * representation.
 *
 * @template {number} A
 * @template {UCAN.Capability} C
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
    version: VERSION,
    issuer: parseDID(issuer, "issuer"),
    audience: parseDID(audience, "audience"),
    capabilities,
    facts,
    expiration,
    notBefore,
    proofs,
    nonce,
    // Provide fake signature to pass validation
    // we'll replace this with actual signature
    signature: EMPTY,
  })

  const payload = UTF8.encode(Formatter.formatSignPayload(data))

  const signature = await issuer.sign(payload)

  return View.cbor({ ...data, signature })
}

/**
 * Verifies UCAN signature.
 *
 * @template {UCAN.Capability} C
 * @param {UCAN.Model<C>} ucan
 * @param {UCAN.Authority} authority
 */
export const verifySignature = (ucan, authority) =>
  formatDID(ucan.issuer) === authority.did() &&
  authority.verify(
    UTF8.encode(Formatter.formatSignPayload(ucan)),
    ucan.signature
  )

/**
 * Check if a UCAN is expired.
 *
 * @param {UCAN.Model} ucan
 */
export const isExpired = ucan => ucan.expiration <= now()

/**
 * Check if a UCAN is not active yet.
 * @param {UCAN.Model} ucan
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
