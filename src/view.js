import * as UCAN from "./ucan.js"

/**
 * @template {UCAN.Capability} C
 * @template {"IPLD"|"JWT"} Type
 * @extends {View<C>}
 */
class View {
  /**
   * @param {Type} type
   * @param {UCAN.Data<C>} data
   */
  constructor(type, { header, body, signature }) {
    /** @readonly */
    this.type = type
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
 * @extends {View<C, "JWT">}
 */
class JWTView extends View {
  /**
   *
   * @param {UCAN.Data<C>} data
   * @param {*} jwt
   */
  constructor(data, jwt) {
    super("JWT", data)
    this.jwt = jwt
  }
}

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.Data<C>} data
 * @returns {UCAN.View<C>}
 */
export const view = data => new View("IPLD", data)

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.Data<C>} data
 * @param {UCAN.JWT<UCAN.Data<C>>} jwt
 * @returns {UCAN.View<C>}
 */
export const jwt = (data, jwt) => new JWTView(data, jwt)
