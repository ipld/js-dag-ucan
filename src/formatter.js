import * as UCAN from "./ucan.js"
import * as DID from "./did.js"
import * as json from "@ipld/dag-json"
import { base64urlpad } from "multiformats/bases/base64"
import { algorithm, ED25519, RSA } from "./did.js"

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.Model<C>} model
 * @returns {UCAN.JWT<C>}
 */
export const format = model =>
  `${formatHeader(model)}.${formatBody(model)}.${formatSignature(
    model.signature
  )}`

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.Input<C>} model
 * @returns {`${UCAN.Header}.${UCAN.Body}`}
 */
export const formatPayload = model =>
  `${formatHeader(model)}.${formatBody(model)}`

/**
 * @param {UCAN.Input} model
 * @returns {`${UCAN.Header}`}
 */
export const formatHeader = model =>
  base64urlpad.baseEncode(encodeHeader(model))

/**
 * @param {UCAN.Input} model
 * @returns {`${UCAN.Body}`}
 */
export const formatBody = model => base64urlpad.baseEncode(encodeBody(model))

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.Signature<C>} signature
 * @returns {UCAN.ToString<UCAN.Signature<C>>}
 */
export const formatSignature = signature => base64urlpad.baseEncode(signature)

/**
 * @param {UCAN.Input} model
 */
export const encodeHeader = model =>
  json.encode({
    alg: encodeAgorithm(model),
    ucv: model.version,
    typ: "JWT",
  })

/**
 * @param {UCAN.Input} body
 */
export const encodeBody = body =>
  json.encode({
    iss: DID.format(body.issuer),
    aud: DID.format(body.audience),
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
 * @param {UCAN.Input} model
 */
export const encodeAgorithm = model => {
  switch (algorithm(model.issuer)) {
    case ED25519:
      return "EdDSA"
    case RSA:
      return "RS256"
    /* c8 ignore next 2 */
    default:
      throw new RangeError(`Unknown KeyType "${algorithm(model.issuer)}"`)
  }
}
