import * as UCAN from "./ucan.js"
import * as CBOR from "@ipld/dag-cbor"
import * as RAW from "multiformats/codecs/raw"
import * as UTF8 from "./utf8.js"
import * as View from "./view.js"
import * as Parser from "./parser.js"
import * as Formatter from "./formatter.js"
import { sha256 } from "multiformats/hashes/sha2"
import { CID } from "multiformats/cid"

export * from "./ucan.js"
import { code } from "./ucan.js"

/** @type {UCAN.Version} */
export const VERSION = "0.8.1"
export const name = 'dag-ucan'

export const raw = RAW.code

/**
 * Encodes given UCAN (in either IPLD or JWT representation) and encodes it into
 * corresponding bytes representation. UCAN in IPLD representation is encoded as
 * DAG-CBOR which JWT representation is encoded as raw bytes of JWT string.
 *
 * @template {UCAN.Capability} C
 * @param {UCAN.UCAN<C>} ucan
 * @returns {UCAN.ByteView<UCAN.UCAN<C>>}
 */
export const encode = ucan => {
  switch (ucan.code) {
    case code:
      return CBOR.encode({
        header: {
          version: ucan.header.version,
          algorithm: ucan.header.algorithm,
        },
        body: {
          issuer: ucan.body.issuer,
          audience: ucan.body.audience,
          capabilities: ucan.body.capabilities.map(Parser.asCapability),
          expiration: ucan.body.expiration,
          proofs: ucan.body.proofs,
          // leave out optionals unless they are set
          ...(ucan.body.facts.length > 0 && { facts: ucan.body.facts }),
          ...(ucan.body.nonce && { nonce: ucan.body.nonce }),
          ...(ucan.body.notBefore && { notBefore: ucan.body.notBefore }),
        },
        signature: ucan.signature,
      })
    case raw:
      return /** @type {Uint8Array} */ (UTF8.encode(ucan.jwt))
    default:
      return invalidCode(ucan)
  }
}

/**
 * @param {never} ucan
 */
const invalidCode = ({ code: unknown }) => {
  throw new TypeError(
    `Provided UCAN has unsupported code: ${unknown}, it must be ${code} for CBOR representation or ${raw} for JWT representation`
  )
}

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
    const data = CBOR.decode(bytes)
    data.body.facts = data.body.facts || []
    return View.cbor(data)
  } catch (error) {
    return parse(UTF8.decode(/** @type {Uint8Array} */ (bytes)))
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
 * @returns {Promise<UCAN.Proof<C>>}
 */
export const link = async (ucan, { hasher = sha256 } = {}) => {
  const digest = await hasher.digest(encode(ucan))
  return /** @type {UCAN.Proof<C>} */ (
    CID.createV1(ucan.code === raw ? raw : code, digest)
  )
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
 * @param {UCAN.JWT<UCAN.UCAN<C>>} input
 * @returns {UCAN.View<C>}
 */
export const parse = input => {
  const ucan = Parser.parse(input)

  // If formatting UCAN produces same jwt string we can use IPLD representation
  // otherwise we need to fallback to raw representation. This decision will
  // affect how we `encode` the UCAN.
  return Formatter.format(ucan) === input
    ? View.cbor(ucan)
    : View.jwt(ucan, /** @type {UCAN.JWT<UCAN.RAW<C>>} */ (input))
}

/**
 * Takes UCAN object and formats it into JWT string.
 *
 * @template {UCAN.Capability} C
 * @param {UCAN.UCAN<C>} ucan
 * @returns {UCAN.JWT<UCAN.UCAN<C>>}
 */
export const format = ucan => {
  switch (ucan.code) {
    case code:
      return Formatter.format(ucan)
    case raw:
      return ucan.jwt
    default:
      return invalidCode(ucan)
  }
}

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
  const header = {
    version: VERSION,
    algorithm: issuer.algorithm,
  }

  // Validate
  if (!audience.startsWith("did:")) {
    throw new TypeError("The audience must be a DID")
  }

  /** @type {UCAN.Body<C>} */
  const body = {
    issuer: issuer.did(),
    audience,
    capabilities: capabilities.map(Parser.asCapability),
    facts,
    expiration,
    notBefore,
    proofs,
    nonce,
  }

  const payload = UTF8.encode(Formatter.formatPayload({ header, body }))
  /** @type {UCAN.Signature<[UCAN.Header, UCAN.Body<C>]>} */
  const signature = await issuer.sign(payload)

  return View.cbor({ header, body, signature })
}
