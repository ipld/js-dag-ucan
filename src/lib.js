import * as UCAN from "./ucan.js"
import * as json from "multiformats/codecs/json"
import * as CBOR from "@ipld/dag-cbor"
import * as UTF8 from "./utf8.js"
import { base64urlpad } from "multiformats/bases/base64"
import { view } from "./view.js"

export * from "./ucan.js"
export const VERSION = "0.8.1"
export const TYPE = "JWT"

// TODO: Send PR to multicodec table
export const code = 0x78c0

/**
 * Encodes
 *
 * @template {UCAN.Capability} C
 * @param {UCAN.IR<C>} data
 * @returns {UCAN.ByteView<UCAN.UCAN<C>>}
 */
export const encode = ({ header, body, signature }) =>
  CBOR.encode({ header, body, signature })

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.ByteView<UCAN.UCAN<C>>} bytes
 * @returns {UCAN.UCAN<C>}
 */
export const decode = bytes => view(CBOR.decode(bytes))

/**
 * Formats UCAN (IR) into a JWT token.
 *
 * @template {UCAN.Capability} C
 * @param {UCAN.IR<C>} data
 * @returns {UCAN.JWT<UCAN.UCAN<C>>}
 */
export const format = ({ header, body, signature }) =>
  `${base64urlpad.baseEncode(header)}.${base64urlpad.baseEncode(
    body
  )}.${base64urlpad.baseEncode(signature)}`

/**
 * Parse JWT formatted UCAN. Note than no validation takes place here.
 *
 * @template {UCAN.Capability} C
 * @param {UCAN.JWT<UCAN.UCAN<C>>} jwt
 * @returns {UCAN.UCAN<C>}
 */
export const parse = jwt => {
  const [header, body, signature] = jwt.split(".")

  if (header == null || body == null || signature == null) {
    throw new Error(
      `Can't parse UCAN: ${jwt}: Expected JWT format: 3 dot-separated base64url-encoded values.`
    )
  }

  return view({
    header: base64urlpad.baseDecode(header),
    body: base64urlpad.baseDecode(body),
    signature: base64urlpad.baseDecode(signature),
  })
}

/**
 * @template {number} A
 * @template {UCAN.Capability} C
 * @param {UCAN.UCANOptions<C, A>} options
 * @returns {Promise<UCAN.UCAN<C>>}
 */
export const issue = async ({
  issuer,
  audience,
  capabilities,
  lifetimeInSeconds = 30,
  expiration,
  notBefore,
  facts,
  proofs = [],
  nonce,
}) => {
  const header = encodeHeader({ algorithm: issuer.algorithm })

  // Validate
  if (!audience.startsWith("did:")) {
    throw new TypeError("The audience must be a DID")
  }

  // Timestamps
  const currentTimeInSeconds = Math.floor(Date.now() / 1000)
  const exp = expiration || currentTimeInSeconds + lifetimeInSeconds

  /** @type {UCAN.Signature<UCAN.Body<C>>} */
  const body = encodeBody({
    issuer: issuer.did(),
    audience,
    // TODO: Properly encode links
    capabilities,
    facts,
    expiration: exp,
    notBefore,
    proofs,
    nonce,
  })

  /** @type {UCAN.Signature<UCAN.UCAN<C>>} */
  const signature = await issuer.sign(encodePayload(header, body))

  return view({ header, body, signature })
}

/**
 * @param {UCAN.Body} body
 * @returns {UCAN.ByteView<UCAN.Body>}
 */
const encodeBody = body =>
  json.encode({
    iss: body.issuer,
    aud: body.audience,
    att: body.capabilities,
    exp: body.expiration,
    fct: body.facts,
    nbf: body.notBefore,
    nnc: body.nonce,
    prf: body.proofs.map(String),
  })

/**
 * Encodes UCAN header
 *
 * @template {number} A
 * @param {object} options
 * @param {A} options.algorithm
 * @param {string} [options.version]
 * @returns {UCAN.ByteView<UCAN.Header>}
 */
const encodeHeader = ({ algorithm, version = VERSION }) =>
  json.encode({
    alg: encodeAgorithm(algorithm),
    typ: TYPE,
    ucv: version,
  })

/**
 *
 * @param {UCAN.ByteView<UCAN.Header>} header
 * @param {UCAN.ByteView<UCAN.Body>} body
 */
const encodePayload = (header, body) =>
  UTF8.encode(
    `${base64urlpad.baseEncode(header)}.${base64urlpad.baseEncode(body)}`
  )

/**
 * @template {number} Code
 * @param {Code} code
 */
const encodeAgorithm = code => {
  switch (code) {
    case 0xed:
      return "EdDSA"
    case 0x1205:
      return "RS256"
    default:
      throw new RangeError(`Unknown KeyType "${code}"`)
  }
}
