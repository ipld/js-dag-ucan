import * as UCAN from "./ucan.js"
import * as json from "multiformats/codecs/json"
import { CID } from "multiformats/cid"

/**
 * @template {UCAN.Capability} C
 * @param {UCAN.IR<C>} data
 * @returns {UCAN.UCAN<C>}
 */

export const view = data => new UCANView(data)

/**
 * @template {UCAN.Capability} C
 * @implements {UCAN.IR<C>}
 * @implements {UCAN.View<C>}
 */
class UCANView {
  /**
   * @param {UCAN.IR<C>} data
   */
  constructor({ header, body, signature }) {
    this.header = header
    this.body = body
    this.signature = signature
  }

  get version() {
    const { version } = decodeHeader(this.header)
    Object.defineProperties(this, {
      version: { value: version },
    })

    return version
  }

  /**
   * @returns {UCAN.DID}
   */
  get issuer() {
    return decode(this).issuer
  }

  /**
   * @returns {UCAN.DID}
   */
  get audience() {
    return decode(this).audience
  }

  /**
   * @returns {C[]}
   */
  get capabilities() {
    return decode(this).capabilities
  }

  /**
   * @returns {number}
   */
  get expiration() {
    return decode(this).expiration
  }

  /**
   * @returns {undefined|number}
   */
  get notBefore() {
    return decode(this).notBefore
  }

  /**
   * @returns {undefined|string}
   */

  get nonce() {
    return decode(this).nonce
  }

  /**
   * @returns {UCAN.Fact[]}
   */
  get facts() {
    return decode(this).facts || []
  }

  /**
   * @returns {UCAN.Link<UCAN.UCAN, 1, UCAN.code>[]}
   */

  get proofs() {
    return decode(this).proofs
  }
}

/**
 * @template {UCAN.Capability} C
 * @param {UCANView<C>} self
 * @returns {UCAN.View<C>}
 */
const decode = self => {
  const {
    issuer,
    audience,
    capabilities,
    expiration,
    facts,
    notBefore,
    nonce,
    proofs,
  } = decodeBody(self.body)

  return Object.defineProperties(self, {
    issuer: { value: issuer },
    audience: { value: audience },
    capabilities: { value: capabilities },
    expiration: { value: expiration },
    facts: { value: facts },
    notBefore: { value: notBefore },
    nonce: { value: nonce },
    proofs: { value: proofs },
  })
}

/**
 * @param {UCAN.ByteView<UCAN.Header>} bytes
 * @returns {UCAN.Header}
 */
const decodeHeader = bytes => {
  const { alg, ucv } = json.decode(bytes)
  return { algorithm: alg, version: ucv }
}

/**
 * @param {UCAN.ByteView<UCAN.Body>} bytes
 * @returns {UCAN.Body}
 */
const decodeBody = bytes => {
  const { iss, aud, att, exp, fct, nbpf, nnc, prf } = json.decode(bytes)

  return {
    issuer: iss,
    audience: aud,
    capabilities: att,
    expiration: exp,
    facts: fct,
    notBefore: nbpf,
    nonce: nnc,
    proofs: prf.map(CID.parse),
  }
}
