import * as UCAN from "../ucan.js"
import * as RAW from "multiformats/codecs/raw"
import * as View from "../view.js"
import * as UTF8 from "../utf8.js"
import * as Parser from "../parser.js"

export const name = "dag-ucan"
export const code = RAW.code

/**
 * Takes UCAN in RAW JWT representation and encodes it into binary
 * format.
 *
 * @template {UCAN.Capability} C
 * @param {UCAN.RAW<C>} ucan
 * @returns {UCAN.ByteView<UCAN.RAW<C>>}
 */
export const encode = ucan =>
  new Uint8Array(ucan.buffer, ucan.byteOffset, ucan.byteLength)

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.ByteView<UCAN.RAW<C>>|UCAN.RAW<C>} bytes
 * @returns {UCAN.JWTView<C>}
 */
export const decode = bytes =>
  View.jwt(
    Parser.parse(UTF8.decode(/** @type {UCAN.RAW<C>} */ (bytes))),
    /** @type {UCAN.RAW<C>} */ (bytes)
  )
