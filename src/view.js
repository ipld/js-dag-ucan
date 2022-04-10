import * as UCAN from "./ucan.js"
import { code as CBOR_CODE } from "@ipld/dag-cbor"
import { code as RAW_CODE } from "multiformats/codecs/raw"

/**
 * @template {UCAN.Capability} C
 * @template {typeof CBOR_CODE|typeof RAW_CODE} Code
 * @extends {View<C>}
 */
class View {
  /**
   * @param {Code} code
   * @param {UCAN.Data<C>} data
   */
  constructor(code, { header, body, signature }) {
    /** @readonly */
    this.code = code
    /** @readonly */
    this.header = header
    /** @readonly */
    this.body = body
    /** @readonly */
    this.signature = signature
  }

  get version() {
    return this.header.version
  }
  get algorithm() {
    return this.header.algorithm
  }

  get issuer() {
    return this.body.issuer
  }

  /**
   * @returns {UCAN.DID}
   */
  get audience() {
    return this.body.audience
  }

  /**
   * @returns {C[]}
   */
  get capabilities() {
    return this.body.capabilities
  }

  /**
   * @returns {number}
   */
  get expiration() {
    return this.body.expiration
  }

  /**
   * @returns {undefined|number}
   */
  get notBefore() {
    return this.body.notBefore
  }

  /**
   * @returns {undefined|string}
   */

  get nonce() {
    return this.body.nonce
  }

  /**
   * @returns {UCAN.Fact[]}
   */
  get facts() {
    return this.body.facts
  }

  /**
   * @returns {UCAN.Proof[]}
   */

  get proofs() {
    return this.body.proofs
  }
}

/**
 * @template {UCAN.Capability} C
 * @extends {View<C, typeof RAW_CODE>}
 */
class RAWView extends View {
  /**
   *
   * @param {UCAN.Data<C>} data
   * @param {UCAN.JWT<UCAN.RAW<C>>} jwt
   */
  constructor(data, jwt) {
    super(RAW_CODE, data)
    this.jwt = jwt
  }
}

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.Data<C>} data
 * @returns {UCAN.View<C>}
 */
export const cbor = data => new View(CBOR_CODE, data)

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.Data<C>} data
 * @param {UCAN.JWT<UCAN.RAW<C>>} jwt
 * @returns {UCAN.View<C>}
 */
export const jwt = (data, jwt) => new RAWView(data, jwt)
