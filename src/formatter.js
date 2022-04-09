import * as UCAN from "./ucan.js"
import * as json from "@ipld/dag-json"
import { base64urlpad } from "multiformats/bases/base64"

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.Data<C>} data
 */
export const format = ({ header, body, signature }) =>
  `${formatHeader(header)}.${formatBody(body)}.${formatSignature(signature)}`

/**
 * @template {UCAN.Capability} C
 * @param {object} payload
 * @param {UCAN.Header} payload.header
 * @param {UCAN.Body<C>} payload.body
 */
export const formatPayload = ({ header, body }) =>
  `${formatHeader(header)}.${formatBody(body)}`

/**
 * @param {UCAN.Header} header
 */
export const formatHeader = header =>
  base64urlpad.baseEncode(encodeHeader(header))

/**
 * @param {UCAN.Body} body
 */
export const formatBody = body => base64urlpad.baseEncode(encodeBody(body))

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.Signature<[UCAN.Header, UCAN.Body<C>]>} signature
 */
export const formatSignature = signature => base64urlpad.baseEncode(signature)

/**
 * @param {UCAN.Header} header
 */
export const encodeHeader = header =>
  json.encode({
    alg: encodeAgorithm(header.algorithm),
    ucv: header.version,
    typ: "JWT",
  })

/**
 * @param {UCAN.Body} body
 */
export const encodeBody = body =>
  json.encode({
    iss: body.issuer,
    aud: body.audience,
    att: body.capabilities,
    exp: body.expiration,
    prf: body.proofs.map(encodeProof),
    ...(body.facts.length > 0 && { fct: body.facts }),
    ...(body.nonce && { nnc: body.nonce }),
    ...(body.notBefore && { nbf: body.notBefore }),
  })

/**
 * @param {UCAN.Proof} proof
 * @returns {string}
 */
export const encodeProof = proof => proof.toString()

/**
 * @template {number} Code
 * @param {Code} code
 */
export const encodeAgorithm = code => {
  switch (code) {
    case 0xed:
      return "EdDSA"
    case 0x1205:
      return "RS256"
    /* c8 ignore next 2 */
    default:
      throw new RangeError(`Unknown KeyType "${code}"`)
  }
}
