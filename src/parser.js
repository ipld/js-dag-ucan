import * as UCAN from "./ucan.js"
import * as json from "@ipld/dag-json"
import * as Schema from "./schema.js"
import { base64url } from "multiformats/bases/base64"
import { createNamed as createSignature } from "./signature.js"

/**
 * Parse JWT formatted UCAN. Note than no validation takes place here.
 *
 * @template {UCAN.Capabilities} C
 * @param {UCAN.JWT<C>|string} jwt
 * @returns {UCAN.Model<C>}
 */
export const parse = jwt => {
  const segments = jwt.split(".")
  const [header, payload, signature] =
    segments.length === 3
      ? segments
      : Schema.throw(
          `Can't parse UCAN: ${jwt}: Expected JWT format: 3 dot-separated base64url-encoded values.`
        )

  const { ucv, alg } = parseHeader(header)

  return {
    ...parsePayload(payload),
    v: ucv,
    s: createSignature(alg, base64url.baseDecode(signature)),
  }
}

/**
 * @param {string} header
 */
export const parseHeader = header => {
  const { ucv, alg, typ } = json.decode(base64url.baseDecode(header))

  return {
    typ: Schema.readLiteral(typ, "JWT", "typ"),
    ucv: Schema.readVersion(ucv, "ucv"),
    alg: Schema.readString(alg, "alg"),
  }
}

/**
 * @template {UCAN.Capabilities} C
 * @param {string} source
 * @returns {UCAN.Payload<C>}
 */
export const parsePayload = source => {
  /** @type {Record<string, unknown>} */
  const payload = json.decode(base64url.baseDecode(source))
  return Schema.readJWTPayload(payload)
}
