import * as UCAN from "../ucan.js"
import * as CBOR from "@ipld/dag-cbor"
import * as Parser from "../parser.js"
import * as Signature from "../signature.js"
import * as DID from "../did.js"
import { CID } from "multiformats/cid"

export const name = "dag-ucan"
export const code = CBOR.code

/**
 * Encodes given UCAN (in either IPLD or JWT representation) and encodes it into
 * corresponding bytes representation. UCAN in IPLD representation is encoded as
 * DAG-CBOR which JWT representation is encoded as raw bytes of JWT string.
 *
 * @template {UCAN.Capabilities} C
 * @param {UCAN.Model<C>} model
 * @returns {UCAN.ByteView<UCAN.Model<C>>}
 */
export const encode = model => {
  const { fct, nnc, nbf, ...rest } = match(model)
  return CBOR.encode({
    ...rest,
    // leave out optionals unless they are set
    ...(fct.length > 0 && { fct }),
    ...(model.nnc && { nnc }),
    ...(model.nbf && { nbf: model.nbf }),
    s: Signature.encode(model.s),
  })
}

/**
 * Decodes UCAN in primary CBOR representation. It does not validate UCAN, it's
 * signature or proof chain. This is to say decoded UCAN may be invalid.
 *
 * @template {UCAN.Capabilities} C
 * @param {UCAN.ByteView<UCAN.Model<C>>} bytes
 * @returns {UCAN.Model<C>}
 */
export const decode = bytes => {
  const model = CBOR.decode(bytes)
  return {
    ...match(model),
    s: Signature.decode(model.s),
  }
}

/**
 * @template {UCAN.Capabilities} C
 * @param {{[key in PropertyKey]: unknown}|UCAN.Model<C>} data
 * @returns {UCAN.Data<C>}
 */
export const match = data => ({
  v: Parser.parseVersion(data.v, "version"),
  iss: parseDID(data.iss, "issuer"),
  aud: parseDID(data.aud, "audience"),
  att: /** @type {C} */ (Parser.parseCapabilities(data.att, "capabilities")),
  exp: Parser.parseExpiry(
    data.exp === Infinity ? null : data.exp,
    "expiration"
  ),
  prf: Parser.parseOptionalArray(data.prf, parseProof, "proofs") || [],
  nnc: Parser.parseOptionalString(data.nnc, "nonce"),
  fct: Parser.parseOptionalArray(data.fct, Parser.parseFact, "facts") || [],
  nbf: Parser.parseOptionalInt(data.nbf, "notBefore"),
})

/**
 * @template {UCAN.Capabilities} C
 * @param {unknown} cid
 * @param {string} context
 */
const parseProof = (cid, context) =>
  /** @type {UCAN.Link<C>} */ (CID.asCID(cid)) ||
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
