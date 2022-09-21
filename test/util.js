import * as UCAN from "../src/lib.js"
import * as TSUCAN from "./ts-ucan.cjs"
import { assert } from "chai"
import { base64url } from "multiformats/bases/base64"
import { varint } from "multiformats"
import * as json from "@ipld/dag-json"
import * as UTF8 from "../src/utf8.js"
import * as ED25519 from "@noble/ed25519"
import * as API from "../src/ucan.js"
import * as DID from "../src/did.js"
import * as Signature from "../src/signature.js"

/**
 * @param {UCAN.View} ucan
 */
export const toTSUCAN = ucan => {
  const jwt = UCAN.format(ucan)
  return TSUCAN.parse(jwt)
}

/**
 * @param {UCAN.View} ucan
 */
export const assertCompatible = ucan =>
  TSUCAN.validate(UCAN.format(ucan), {
    checkIsExpired: true,
    checkIssuer: true,
    checkSignature: true,
  })

/**
 * @template {UCAN.Capabilities} T
 * @param {UCAN.View<T>} actual
 * @param {Partial<UCAN.View<T>>} expect
 */
export const assertUCAN = (actual, expect) => {
  assertUCANIncludes(actual, expect)
  assertUCANIncludes(UCAN.parse(UCAN.format(actual)), expect)

  assertUCANIncludes(UCAN.decode(UCAN.encode(actual)), expect)
}
/**
 * @param {UCAN.View} actual
 * @param {Partial<UCAN.View>} expect
 */
export const assertUCANIncludes = (actual, expect) => {
  for (const [key, value] of Object.entries(expect)) {
    const name = /** @type {keyof UCAN.View} */ (key)
    assert.deepEqual(actual[name], value, key)
  }
}

/**
 * @param {UCAN.View} actual
 */
export const assertFormatLoop = actual => {
  assert.deepEqual(UCAN.parse(UCAN.format(actual)), actual)
}

/**
 * @param {UCAN.View} actual
 */
export const assertCodecLoop = actual => {
  const t = UCAN.encode(actual)
  assert.deepEqual(UCAN.decode(t), actual)
}

/**
 * @param {string} secret
 * @returns {UCAN.Signer}
 */
export const createEdIssuer = secret => new EdDSA(secret)

class EdDSA {
  /**
   * @param {string} secret
   */
  constructor(secret) {
    this.keypair = TSUCAN.EdKeypair.fromSecretKey(secret)
  }
  get signatureAlgorithm() {
    return "EdDSA"
  }
  get signatureCode() {
    return 0xd0ed
  }

  get keyType() {
    return this.keypair.keyType
  }
  get publicKey() {
    return this.keypair.publicKey
  }
  /**
   *
   * @param {Uint8Array} payload
   */
  async sign(payload) {
    const bytes = await this.keypair.sign(payload)
    return Signature.create(this.signatureCode, bytes)
  }
  did() {
    return /** @type {`did:key:${string}`} */ (this.keypair.did())
  }
}

export const createRSAIssuer = async () =>
  new RSA(await TSUCAN.RsaKeypair.create())

class RSA {
  /**
   * @param {TSUCAN.RsaKeypair} keypair
   */
  constructor(keypair) {
    this.keypair = keypair
  }
  did() {
    return /** @type {`did:key:${string}`}*/ (this.keypair.did())
  }
  get signatureAlgorithm() {
    return "RS256"
  }
  get signatureCode() {
    return 0xd01205
  }
  /**
   * @param {Uint8Array} payload
   */
  async sign(payload) {
    const bytes = await this.keypair.sign(payload)
    return Signature.create(this.signatureCode, bytes)
  }
}
/**
 * @param {Uint8Array} bytes
 * @returns {API.Verifier}
 */
export const decodeAuthority = bytes => {
  const [algorithm, length] = varint.decode(bytes)
  const key = bytes.subarray(length)
  /**
   *
   * @param {Uint8Array} payload
   * @param {API.Signature} signature
   * @returns
   */
  const verify = (payload, signature) =>
    ED25519.verify(signature.raw, payload, key)

  return {
    did: () => DID.format(DID.decode(bytes)),
    verify,
  }
}

/**
 *
 * @typedef {{
 * issuer: TSUCAN.EdKeypair
 * audience: UCAN.Principal
 * proofs?: string[]
 * }} BuildOptions
 *
 * @param {BuildOptions} options
 */
export const buildUCAN = async ({ issuer, audience, proofs }) =>
  TSUCAN.build({
    issuer,
    audience: audience.did(),
    capabilities: [
      {
        with: {
          scheme: "wnfs",
          hierPart: "//boris.fission.name/public/photos/",
        },
        can: { namespace: "crud", segments: ["DELETE"] },
      },
      {
        with: {
          scheme: "wnfs",
          hierPart:
            "//boris.fission.name/private/84MZ7aqwKn7sNiMGsSbaxsEa6EPnQLoKYbXByxNBrCEr",
        },
        can: { namespace: "wnfs", segments: ["APPEND"] },
      },
      {
        with: { scheme: "mailto", hierPart: "boris@fission.codes" },
        can: { namespace: "msg", segments: ["SEND"] },
      },
    ],
    proofs,
  })

/**
 * @param {BuildOptions} options
 */
export const buildJWT = async options => TSUCAN.encode(await buildUCAN(options))

/**
 * @param {UCAN.Signer} issuer
 * @param {{header?:object, body:object}} token
 */
export const formatUnsafe = async (issuer, token) => {
  const header = base64url.baseEncode(
    json.encode({
      typ: "JWT",
      alg: "EdDSA",
      ucv: "0.9.0",
      ...token.header,
    })
  )
  const body = base64url.baseEncode(
    json.encode({
      iss: issuer.did(),
      aud: issuer.did(),
      exp: Math.floor(Date.now() / 1000) + 30,
      prf: [],
      att: [],

      ...token.body,
    })
  )
  const signature = await issuer.sign(UTF8.encode(`${header}.${body}`))
  return `${header}.${body}.${base64url.baseEncode(signature.raw)}`
}
