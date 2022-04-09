import * as UCAN from "./ucan.js"
import * as CBOR from "@ipld/dag-cbor"
import * as UTF8 from "./utf8.js"
import { jwt, view } from "./view.js"
import * as Parser from "./parser.js"
import * as Formatter from "./formatter.js"
import { sha256 } from "multiformats/hashes/sha2"
import { CID } from "multiformats/cid"
import * as RAW from "multiformats/codecs/raw"

export * from "./ucan.js"
import { code } from "./ucan.js"

/** @type {UCAN.Version} */
export const VERSION = "0.8.1"

/**
 * Encodes given UCAN (in either IPLD or JWT representation) and encodes it into
 * corresponding bytes representation. UCAN in IPLD representation is encoded as
 * DAG-CBOR which JWT representation is encoded as raw bytes of JWT string.
 *
 * @template {UCAN.Capability} C
 * @param {UCAN.UCAN<C>} data
 * @returns {UCAN.ByteView<UCAN.UCAN<C>>}
 */
export const encode = data =>
  data.type === "IPLD"
    ? CBOR.encode({
        header: {
          version: data.header.version,
          algorithm: data.header.algorithm,
        },
        body: {
          issuer: data.body.issuer,
          audience: data.body.audience,
          capabilities: data.body.capabilities.map(Parser.asCapability),
          expiration: data.body.expiration,
          proofs: data.body.proofs,
          // leave out optionals unless they are set
          ...(data.body.facts.length > 0 && { facts: data.body.facts }),
          ...(data.body.nonce && { nonce: data.body.nonce }),
          ...(data.body.notBefore && { notBefore: data.body.notBefore }),
        },
        signature: data.signature,
      })
    : UTF8.encode(data.jwt)

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
    return view(data)
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
    CID.createV1(ucan.type === "IPLD" ? code : RAW.code, digest)
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
 * @param {UCAN.JWT<UCAN.Data<C>>} input
 * @returns {UCAN.View<C>}
 */
export const parse = input => {
  const ucan = Parser.parse(input)

  // If formatting UCAN produces same jwt string we can use IPLD representation
  // otherwise we need to fallback to raw representation. This decision will
  // affect how we `encode` the UCAN.
  return Formatter.format(ucan) === input ? view(ucan) : jwt(ucan, input)
}

/**
 * Takes UCAN object and formats it into JWT string.
 *
 * @template {UCAN.Capability} C
 * @param {UCAN.UCAN<C>} ucan
 * @returns {UCAN.JWT<UCAN.Data<C>>}
 */
export const format = ucan => {
  if (ucan.type === "IPLD") {
    return Formatter.format(ucan)
  } else {
    return ucan.jwt
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

  return view({ header, body, signature })
}
