import * as UCAN from "./ucan.js"
import * as RAW from "multiformats/codecs/raw"
import * as DID from "./did.js"

/**
 * @template {UCAN.Capability} C
 * @implements {UCAN.View<C>}
 */
class View {
  /**
   * @param {UCAN.Model<C>} model
   */
  constructor(model) {
    /** @readonly */
    this.model = model
  }

  get version() {
    return this.model.version
  }

  get issuer() {
    return DID.from(this.model.issuer)
  }

  get audience() {
    return DID.from(this.model.audience)
  }

  /**
   * @returns {C[]}
   */
  get capabilities() {
    return this.model.capabilities
  }

  /**
   * @returns {number}
   */
  get expiration() {
    return this.model.expiration
  }

  /**
   * @returns {undefined|number}
   */
  get notBefore() {
    return this.model.notBefore
  }

  /**
   * @returns {undefined|string}
   */

  get nonce() {
    return this.model.nonce
  }

  /**
   * @returns {UCAN.Fact[]}
   */
  get facts() {
    return this.model.facts
  }

  /**
   * @returns {UCAN.Proof[]}
   */

  get proofs() {
    return this.model.proofs
  }

  get signature() {
    return this.model.signature
  }
}

/**
 * @template {UCAN.Capability} C
 * @implements {UCAN.JWTView<C>}
 */
class JWTView extends Uint8Array {
  /**
   * @param {UCAN.Model<C>} model
   * @param {object} bytes
   * @param {ArrayBuffer} bytes.buffer
   * @param {number} [bytes.byteOffset]
   * @param {number} [bytes.byteLength]
   */
  constructor(
    model,
    { buffer, byteOffset = 0, byteLength = buffer.byteLength }
  ) {
    super(buffer, byteOffset, byteLength)
    this.model = model
  }

  get version() {
    return this.model.version
  }

  get issuer() {
    return DID.from(this.model.issuer)
  }

  get audience() {
    return DID.from(this.model.audience)
  }

  /**
   * @returns {C[]}
   */
  get capabilities() {
    return this.model.capabilities
  }

  /**
   * @returns {number}
   */
  get expiration() {
    return this.model.expiration
  }

  /**
   * @returns {undefined|number}
   */
  get notBefore() {
    return this.model.notBefore
  }

  /**
   * @returns {undefined|string}
   */

  get nonce() {
    return this.model.nonce
  }

  /**
   * @returns {UCAN.Fact[]}
   */
  get facts() {
    return this.model.facts
  }

  /**
   * @returns {UCAN.Proof[]}
   */

  get proofs() {
    return this.model.proofs
  }

  get signature() {
    return this.model.signature
  }
}

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.Model<C>} data
 * @returns {UCAN.View<C>}
 */
export const cbor = data => new View(data)

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.Model<C>} model
 * @param {UCAN.RAW<C>} bytes
 * @returns {UCAN.JWTView<C>}
 */
export const jwt = (model, bytes) => new JWTView(model, bytes)
