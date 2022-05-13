import * as UCAN from "./ucan.js"
import * as DID from "./did.js"
import * as json from "@ipld/dag-json"
import { base64url } from "multiformats/bases/base64"
import { algorithm, ED25519, RSA } from "./did.js"

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.Model<C>} model
 * @returns {UCAN.JWT<C>}
 */
export const format = model =>
  `${formatHeader(model)}.${formatPayload(model)}.${formatSignature(
    model.signature
  )}`

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.Data<C>} model
 * @returns {UCAN.SignPayload<C>}
 */
export const formatSignPayload = model =>
  `${formatHeader(model)}.${formatPayload(model)}`

/**
 * @param {UCAN.Data} data
 * @returns {UCAN.ToString<UCAN.ByteView<UCAN.Header>>}
 */
export const formatHeader = data => base64url.baseEncode(encodeHeader(data))

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.Data<C>} data
 * @returns {UCAN.ToString<UCAN.ByteView<UCAN.Payload<C>>>}
 */
export const formatPayload = data => base64url.baseEncode(encodePayload(data))

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.Signature<UCAN.SignPayload<C>>} signature
 * @returns {UCAN.ToString<UCAN.Signature<C>>}
 */
export const formatSignature = signature => base64url.baseEncode(signature)

/**
 * @param {UCAN.Data} data
 * @returns {UCAN.ByteView<UCAN.Header>}
 */
export const encodeHeader = data =>
  json.encode({
    alg: encodeAgorithm(data),
    ucv: data.version,
    typ: "JWT",
  })

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.Data<C>} data
 * @returns {UCAN.ByteView<UCAN.Payload<C>>}
 */
export const encodePayload = data =>
  json.encode({
    iss: DID.format(data.issuer),
    aud: DID.format(data.audience),
    att: data.capabilities,
    exp: data.expiration,
    prf: data.proofs.map(encodeProof),
    ...(data.facts.length > 0 && { fct: data.facts }),
    ...(data.nonce && { nnc: data.nonce }),
    ...(data.notBefore && { nbf: data.notBefore }),
  })

/**
 * @param {UCAN.Proof} proof
 * @returns {string}
 */
export const encodeProof = proof => proof.toString()

/**
 * @param {object} data
 * @param {UCAN.ByteView<UCAN.DID>} data.issuer
 */
export const encodeAgorithm = data => {
  switch (algorithm(data.issuer)) {
    case ED25519:
      return "EdDSA"
    case RSA:
      return "RS256"
    /* c8 ignore next 2 */
    default:
      throw new RangeError(`Unknown KeyType "${algorithm(data.issuer)}"`)
  }
}
