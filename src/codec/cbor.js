import * as UCAN from "../ucan.js"
import * as CBOR from "@ipld/dag-cbor"
import * as Parser from "../parser.js"
import * as View from "../view.js"
import * as DID from "../did.js"
import { CID } from "multiformats/cid"

export const name = "dag-ucan"
export const code = CBOR.code

/**
 * Encodes given UCAN (in either IPLD or JWT representation) and encodes it into
 * corresponding bytes representation. UCAN in IPLD representation is encoded as
 * DAG-CBOR which JWT representation is encoded as raw bytes of JWT string.
 *
 * @template {UCAN.Capability} C
 * @param {UCAN.Model<C>} ucan
 * @returns {UCAN.ByteView<UCAN.Model<C>>}
 */
export const encode = ucan => {
  const { facts, nonce, notBefore, ...rest } = match(ucan)
  return CBOR.encode({
    ...rest,
    // leave out optionals unless they are set
    ...(facts.length > 0 && { facts }),
    ...(ucan.nonce && { nonce }),
    ...(ucan.notBefore && { notBefore: ucan.notBefore }),
    signature: Parser.parseBytes(ucan.signature, "signature"),
  })
}

/**
 * Decodes UCAN in primary CBOR representation. It does not validate UCAN, it's
 * signature or proof chain. This is to say decoded UCAN may be invalid.
 *
 * @template {UCAN.Capability} C
 * @param {UCAN.ByteView<UCAN.Model<C>>} bytes
 * @returns {UCAN.View<C>}
 */
export const decode = bytes => View.cbor(match(CBOR.decode(bytes)))

/**
 * @template {UCAN.Capability} C
 * @param {{[key in PropertyKey]: unknown}|UCAN.Model<C>} data
 * @returns {UCAN.Model<C>}
 */
export const match = data => ({
  version: Parser.parseVersion(data.version, "version"),
  issuer: parseDID(data.issuer, "issuer"),
  audience: parseDID(data.audience, "audience"),
  capabilities: /** @type {C[]} */ (
    Parser.parseCapabilities(data.capabilities, "capabilities")
  ),
  expiration: Parser.parseInt(data.expiration, "expiration"),
  proofs: Parser.parseOptionalArray(data.proofs, parseProof, "proofs") || [],
  signature: Parser.parseBytes(data.signature, "signature"),
  nonce: Parser.parseOptionalString(data.nonce, "nonce"),
  facts: Parser.parseOptionalArray(data.facts, Parser.parseFact, "facts") || [],
  notBefore: Parser.parseOptionalInt(data.notBefore, "notBefore"),
})

/**
 * @template {UCAN.Capability} C
 * @param {unknown} cid
 * @param {string} context
 */
const parseProof = (cid, context) =>
  /** @type {UCAN.Proof<C>} */ (CID.asCID(cid)) ||
  Parser.ParseError.throw(
    `Expected ${context} to be CID, instead got ${JSON.stringify(cid)}`
  )

/**
 *
 * @param {unknown} input
 * @param {string} context
 */
const parseDID = (input, context) =>
  input instanceof Uint8Array
    ? DID.decode(input)
    : Parser.ParseError.throw(
        `Expected ${context} to be Uint8Array, instead got ${JSON.stringify(
          input
        )}`
      )
