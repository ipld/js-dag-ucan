import * as UCAN from "../src/lib.js"
import * as TSUCAN from "./ts-ucan.cjs"
import { assert } from "chai"
import { base64urlpad } from "multiformats/bases/base64"
import * as json from "@ipld/dag-json"
import * as UTF8 from "../src/utf8.js"

/**
 * @param {UCAN.UCAN} ucan
 */
export const toTSUCAN = ucan => {
  const jwt = UCAN.format(ucan)
  return TSUCAN.parse(jwt)
}

/**
 * @param {UCAN.UCAN} ucan
 */
export const assertCompatible = ucan =>
  TSUCAN.validate(UCAN.format(ucan), {
    checkIsExpired: true,
    checkIssuer: true,
    checkSignature: true,
  })

/**
 * @param {UCAN.View} actual
 * @param {Partial<UCAN.View>} expect
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
  assert.deepEqual(UCAN.decode(UCAN.encode(actual)), actual)
}

/**
 * @param {string} secret
 */
export const createEdIssuer = secret =>
  /** @type {UCAN.Issuer & TSUCAN.EdKeypair} */
  (
    Object.assign(TSUCAN.EdKeypair.fromSecretKey(secret), {
      algorithm: 0xed,
    })
  )

export const createRSAIssuer = async () =>
  /** @type {UCAN.Issuer & TSUCAN.RsaKeypair} */
  (
    Object.assign(await TSUCAN.RsaKeypair.create(), {
      algorithm: 0x1205,
    })
  )

/**
 *
 * @typedef {{
 * issuer: TSUCAN.EdKeypair
 * audience: UCAN.Agent
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
 * @param {UCAN.Issuer} issuer
 * @param {{header?:object, body:object}} token
 */
export const formatUnsafe = async (issuer, token) => {
  const header = base64urlpad.baseEncode(
    json.encode({
      typ: "JWT",
      alg: "EdDSA",
      ucv: "0.8.1",
      ...token.header,
    })
  )
  const body = base64urlpad.baseEncode(
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
  return `${header}.${body}.${base64urlpad.baseEncode(signature)}`
}
