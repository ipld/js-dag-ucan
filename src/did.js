import * as UCAN from "./ucan.js"
import { base58btc } from "multiformats/bases/base58"
import { varint } from "multiformats"

const DID_KEY_PREFIX = `did:key:`
export const ED25519 = 0xed
export const RSA = 0x1205

/**
 * @param {Uint8Array} key
 * @returns {Code}
 */
export const algorithm = key => {
  const [code] = varint.decode(key)
  switch (code) {
    case ED25519:
    case RSA:
      return code
    default:
      throw new RangeError(
        `Unsupported key algorithm with multicode 0x${code.toString(16)}.`
      )
  }
}

/**
 * @typedef {typeof ED25519|typeof RSA} Code
 */

/**
 * @param {UCAN.DID} did
 * @returns {UCAN.DIDView}
 */
export const parse = did => {
  if (!did.startsWith(DID_KEY_PREFIX)) {
    throw new RangeError(`Invalid DID "${did}", must start with 'did:key:'`)
  }
  return decode(base58btc.decode(did.slice(DID_KEY_PREFIX.length)))
}

/**
 * @param {UCAN.ByteView<UCAN.DID>} key
 * @returns {UCAN.DID}
 */
export const format = key =>
  /** @type {UCAN.DID} */ (`${DID_KEY_PREFIX}${base58btc.encode(encode(key))}`)

/**
 * @param {Uint8Array} bytes
 * @returns {UCAN.DIDView}
 */
export const decode = bytes => {
  const _ = algorithm(bytes)
  return new DID(bytes.buffer, bytes.byteOffset, bytes.byteLength)
}

/**
 * @param {Uint8Array} bytes
 * @returns {UCAN.ByteView<UCAN.DID>}
 */
export const encode = bytes => {
  const _ = algorithm(bytes)
  return bytes
}

/**
 * @param {UCAN.ByteView<UCAN.DID>|UCAN.DID} input
 * @returns {UCAN.DIDView}
 */
export const from = input => {
  if (input instanceof DID) {
    return input
  } else if (input instanceof Uint8Array) {
    return decode(input)
  } else {
    return parse(input)
  }
}

class DID extends Uint8Array {
  did() {
    return format(this)
  }
}
