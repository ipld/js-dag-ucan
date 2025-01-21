import * as UCAN from "./ucan.js"
import * as CBOR from "./codec/cbor.js"
import * as JWT from "./codec/jwt.js"
import * as UTF8 from "./utf8.js"
import { readPayload } from "./schema.js"
import { parse as parseDID } from "./did.js"
import { parse as parseJWT } from "./parser.js"
import { formatSignPayload } from "./formatter.js"
import { sha256 } from "multiformats/hashes/sha2"
import { create as createLink } from "multiformats/link"
import { format as formatDID } from "./did.js"

export * from "./ucan.js"

export const VERSION = "0.9.1"
export const name = "dag-ucan"
export const code = /** @type {UCAN.Code} */ (CBOR.code)

/**
 * We cast sha256 to workaround typescripts limited inference problem when using
 * sha256 as default. If hasher is omitted type `A` should match sha256.code
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
 * @param {UCAN.UCAN<C>} ucan
 * @returns {UCAN.ByteView<UCAN.UCAN<C>>}
 */
export const encode = ucan => (ucan.jwt ? JWT.encode(ucan) : CBOR.encode(ucan))

/**
 * Decodes binary encoded UCAN. It assumes UCAN is in primary IPLD
 * representation and attempts to decode it with DAG-CBOR, if that
 * fails it falls back to secondary representation and parses it as
 * a JWT.
 *
 * @template {UCAN.Capabilities} C
 * @param {UCAN.ByteView<UCAN.UCAN<C>>} bytes
 * @returns {UCAN.View<C>}
 */
export const decode = bytes => {
  try {
    return CBOR.decode(bytes)
  } catch (_) {
    return JWT.decode(/** @type {UCAN.ByteView<UCAN.FromJWT<C>>} */ (bytes))
  }
}

/**
 * Convenience function to create a CID for the given UCAN. If UCAN is
 * in JWT representation get CID with RAW multicodec, while UCANs in IPLD
 * representation get UCAN multicodec code.
 *
 * @template {UCAN.Capabilities} C
 * @template {number} [A=typeof sha256.code] - Multihash code
 * @param {UCAN.View<C>} ucan
 * @param {{hasher?: UCAN.MultihashHasher<A>}} [options]
 */
export const link = async (ucan, options) => {
  const { cid } = await write(ucan, options)
  return cid
}

/**
 * @template {UCAN.Capabilities} C
 * @template {number} [A=typeof sha256.code] - Multihash code
 * @param {UCAN.UCAN<C>} ucan
 * @param {{hasher?: UCAN.MultihashHasher<A>}} options
 * @returns {Promise<UCAN.Block<C, UCAN.Code, A>>}
 */
export const write = async (ucan, { hasher = defaultHasher } = {}) => {
  const [code, bytes] = ucan.jwt
    ? [/** @type {UCAN.Code} */ (JWT.code), JWT.encode(ucan)]
    : [/** @type {UCAN.Code} */ (CBOR.code), CBOR.encode(ucan)]
  const digest = await hasher.digest(bytes)

  return {
    bytes,
    cid: createLink(code, digest),
    data: ucan,
  }
}

/**
 * Parses UCAN formatted as JWT string. Returns UCAN view in IPLD representation
 * when serializing it back would produce original string, otherwise returns UCAN
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
 * @param {UCAN.JWT<C>|string} jwt
 * @returns {UCAN.View<C>}
 */
export const parse = jwt => {
  const model = parseJWT(jwt)

  // If formatting UCAN produces same jwt string we can use IPLD representation
  // otherwise we need to fallback to raw representation. This decision will
  // affect how we `encode` the UCAN.
  return CBOR.format(model) === jwt
    ? CBOR.from(model)
    : JWT.from({ ...model, jwt: /** @type {UCAN.JWT<C>} */ (jwt) })
}

/**
 * Takes UCAN object and formats it into JWT string.
 *
 * @template {UCAN.Capabilities} C
 * @param {UCAN.UCAN<C>} ucan
 * @returns {UCAN.JWT<C>}
 */
export const format = ucan => (ucan.jwt ? JWT.format(ucan) : CBOR.format(ucan))

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
  expiration = now() + lifetimeInSeconds,
  notBefore,
  facts = [],
  proofs = [],
  nonce,
}) => {
  const v = VERSION
  const data = readPayload({
    iss: parseDID(issuer.did()),
    aud: parseDID(audience.did()),
    att: capabilities,
    fct: facts,
    exp: expiration,
    nbf: notBefore,
    prf: proofs,
    nnc: nonce,
  })
  const payload = encodeSignaturePayload(data, v, issuer.signatureAlgorithm)

  return CBOR.from({
    ...data,
    v,
    s: await issuer.sign(payload),
  })
}

/**
 *
 * @param {UCAN.Payload} payload
 * @param {UCAN.Version} version
 * @param {string} algorithm
 * @returns
 */
const encodeSignaturePayload = (payload, version, algorithm) =>
  UTF8.encode(formatSignPayload(payload, version, algorithm))

/**
 * Verifies UCAN signature.
 *
 * @param {UCAN.View} ucan
 * @param {UCAN.Verifier} verifier
 */
export const verifySignature = (ucan, verifier) =>
  formatDID(ucan.issuer) === verifier.did() &&
  verifier.verify(
    encodeSignaturePayload(ucan.model, ucan.model.v, ucan.signature.algorithm),
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
