import * as UCAN from "./ucan.js"
import * as DID from "./did.js"
import { code as RAW_CODE } from "multiformats/codecs/raw"
import { code as CBOR_CODE } from "@ipld/dag-cbor"

/**
 * @template {UCAN.Capabilities} C
 * @template {UCAN.Code} Code
 */
class View {
  /**
   * @param {UCAN.Model<C>} model
   * @param {Code} code
   */
  constructor(model, code) {
    /** @readonly */
    this.model = model
    this.code = code
  }

  get version() {
    return this.model.v
  }

  get issuer() {
    return DID.from(this.model.iss)
  }

  get audience() {
    return DID.from(this.model.aud)
  }

  /**
   * @returns {C}
   */
  get capabilities() {
    return this.model.att
  }

  /**
   * @returns {number}
   */
  get expiration() {
    const { exp } = this.model
    return exp === null ? Infinity : exp
  }

  /**
   * @returns {undefined|number}
   */
  get notBefore() {
    return this.model.nbf
  }

  /**
   * @returns {undefined|string}
   */

  get nonce() {
    return this.model.nnc
  }

  /**
   * @returns {UCAN.Fact[]}
   */
  get facts() {
    return this.model.fct
  }

  /**
   * @returns {UCAN.Link[]}
   */

  get proofs() {
    return this.model.prf
  }

  get signature() {
    return this.model.s
  }
}

/**
 * @template {UCAN.Capabilities} C
 * @extends {View<C, typeof RAW_CODE>}
 * @implements {UCAN.JWTView<C>}
 */
export class JWTView extends View {
  /**
   * @param {UCAN.Model<C>} model
   * @param {UCAN.ByteView<UCAN.JWT<C>>} bytes
   */

  constructor(model, bytes) {
    super(model, RAW_CODE)
    this.bytes = bytes
  }
}

/**
 * @template {UCAN.Capabilities} C
 * @param {UCAN.Model<C>} model
 * @returns {UCAN.CBORView<C>}
 */
export const cbor = model => new View(model, CBOR_CODE)

/**
 * @template {UCAN.Capabilities} C
 * @param {UCAN.Model<C>} model
 * @param {UCAN.ByteView<UCAN.JWT<C>>} bytes
 * @returns {UCAN.JWTView<C>}
 */
export const jwt = (model, bytes) => new JWTView(model, bytes)
