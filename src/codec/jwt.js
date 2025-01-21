import * as UCAN from "../ucan.js"
import * as UTF8 from "../utf8.js"
import { parse } from "../parser.js"
import { code } from "multiformats/codecs/raw"
import { View } from "../view.js"

export { code }
export const name = "dag-ucan"

/**
 * Creates a UCAN view from the underlying data model. Please note that this
 * function does no verification of the model and it is callers responsibility
 * to ensure that:
 *
 * 1. Data model is correct contains all the field etc...
 * 2. Payload of the signature will match paylodad when model is serialized
 *    with DAG-JSON.
 *
 * In other words you should never use this function unless you've parsed or
 * decoded a valid UCAN and want to wrap it into a view.
 *
 * @template {UCAN.Capabilities} C
 * @param {UCAN.FromJWT<C>} model
 * @returns {UCAN.View<C>}
 */
export const from = model => new JWTView(model)

/**
 * @template {UCAN.Capabilities} C
 * @param {UCAN.ByteView<UCAN.FromJWT<C>>} bytes
 * @returns {UCAN.View<C>}
 */
export const decode = bytes => {
  const jwt = /** @type {UCAN.JWT<C>} */ (UTF8.decode(bytes))

  return new JWTView({ ...parse(jwt), jwt })
}

/**
 * @template {UCAN.Capabilities} C
 * @param {UCAN.FromJWT<C>} model
 * @returns {UCAN.ByteView<UCAN.UCAN<C>>}
 */
export const encode = ({ jwt }) => UTF8.encode(jwt)

/**
 * @template {UCAN.Capabilities} C
 * @param {UCAN.FromJWT<C>} model
 * @returns {UCAN.JWT<C>}
 */
export const format = ({ jwt }) => jwt

/**
 * @template {UCAN.Capabilities} C
 * @extends {View<C>}
 */
class JWTView extends View {
  /**
   * @param {UCAN.FromJWT<C>} model
   */
  constructor(model) {
    super(model)
    this.model = model
  }
  /** @type {UCAN.MulticodecCode<typeof code, "Raw">} */
  get code() {
    return code
  }
  format() {
    return format(this.model)
  }
  encode() {
    return encode(this.model)
  }
}
