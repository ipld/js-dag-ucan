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
export const format = model =>
  `${formatHeader(model, model.s.algorithm)}.${formatPayload(
    model
  )}.${formatSignature(model.s)}`

/**
 * @template {UCAN.Capabilities} C
 * @param {UCAN.Data<C>} model
 * @param {string} alg
 */
export const formatSignPayload = (model, alg) =>
  `${formatHeader(model, alg)}.${formatPayload(model)}`

/**
 * @param {UCAN.Data} data
 * @param {string} alg
 */
export const formatHeader = (data, alg) =>
  base64url.baseEncode(encodeHeader(data, alg))

/**
 * @template {UCAN.Capabilities} C
 * @param {UCAN.Data<C>} data
 */
export const formatPayload = data => base64url.baseEncode(encodePayload(data))

/**
 * @param {UCAN.Signature<string>} signature
 */
export const formatSignature = signature => base64url.baseEncode(signature.raw)

/**
 * @param {UCAN.Data} data
 * @param {string} alg
 * @returns {UCAN.ByteView<UCAN.Header>}
 */
export const encodeHeader = (data, alg) =>
  json.encode({
    alg,
    ucv: data.v,
    typ: "JWT",
  })

/**
 * @template {UCAN.Capabilities} C
 * @param {UCAN.Data<C>} data
 * @returns {UCAN.ByteView<UCAN.Payload<C>>}
 */
export const encodePayload = data =>
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
 */
export const encodeProof = proof => proof.toString()
