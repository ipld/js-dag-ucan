import * as UCAN from "./ucan.js"
import * as DID from "./did.js"
import * as json from "@ipld/dag-json"
import { base64url } from "multiformats/bases/base64"
import * as Signature from "./signature.js"

/**
 * @template {UCAN.Capabilities} C
 * @param {UCAN.Model<C>} model
 * @returns {UCAN.JWT<C>}
 */
export const format = model => {
  const header = formatHeader(model.v, model.s.algorithm)
  const payload = formatPayload(model)
  const signature = formatSignature(model.s)
  return /** @type {UCAN.JWT<C>} */ (`${header}.${payload}.${signature}`)
}

/**
 * @template {UCAN.Capabilities} C
 * @param {UCAN.Payload<C>} payload
 * @param {UCAN.Version} version
 * @param {string} alg
 */
export const formatSignPayload = (payload, version, alg) =>
  `${formatHeader(version, alg)}.${formatPayload(payload)}`

/**
 * @param {UCAN.Version} version
 * @param {string} alg
 */
export const formatHeader = (version, alg) =>
  base64url.baseEncode(encodeHeader(version, alg))

/**
 * @template {UCAN.Capabilities} C
 * @param {UCAN.Payload<C>} data
 */
export const formatPayload = data => base64url.baseEncode(encodePayload(data))

/**
 * @param {UCAN.Signature<string>} signature
 */
export const formatSignature = signature => base64url.baseEncode(signature.raw)

/**
 * @param {UCAN.Version} v
 * @param {string} alg
 * @returns {UCAN.ByteView<UCAN.JWTHeader>}
 */
const encodeHeader = (v, alg) =>
  json.encode({
    alg,
    ucv: v,
    typ: "JWT",
  })

/**
 * @template {UCAN.Capabilities} C
 * @param {UCAN.Payload<C>} data
 * @returns {UCAN.ByteView<UCAN.JWTPayload<C>>}
 */
const encodePayload = data =>
  json.encode({
    iss: DID.format(data.iss),
    aud: DID.format(data.aud),
    att: data.att,
    exp: data.exp,
    prf: data.prf.map(encodeProof),
    // leave out optionals and empty fields
    ...(data.fct.length > 0 && { fct: data.fct }),
    ...(data.nnc && { nnc: data.nnc }),
    ...(data.nbf && { nbf: data.nbf }),
  })

/**
 * @param {UCAN.Link} proof
 * @returns {UCAN.ToString<UCAN.Link>}
 */
const encodeProof = proof =>
  /** @type {UCAN.ToString<UCAN.Link>} */ (proof.toString())
