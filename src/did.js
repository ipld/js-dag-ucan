import * as UCAN from "./ucan.js"
import { base58btc } from "multiformats/bases/base58"
import { varint } from "multiformats"
import * as UTF8 from "./utf8.js"

const DID_PREFIX = "did:"
const DID_PREFIX_SIZE = DID_PREFIX.length
const DID_KEY_PREFIX = `did:key:`
const DID_KEY_PREFIX_SIZE = DID_KEY_PREFIX.length

export const ED25519 = 0xed
export const RSA = 0x1205
export const P256 = 0x1200
export const P384 = 0x1201
export const P521 = 0x1202
export const SECP256K1 = 0xe7
export const BLS12381G1 = 0xea
export const BLS12381G2 = 0xeb
export const DID_CORE = 0x0d1d
const METHOD_OFFSET = varint.encodingLength(DID_CORE)

/**
 * @typedef {typeof ED25519|typeof RSA|typeof P256|typeof P384|typeof P521|typeof DID_CORE} Code
 */

/**
 * Parses a DID string into a DID buffer view
 *
 * @template {UCAN.DID} ID
 * @param {ID|UCAN.ToString<unknown>} did
 * @returns {UCAN.PrincipalView<ID>}
 */
export const parse = did => {
  if (!did.startsWith(DID_PREFIX)) {
    throw new RangeError(`Invalid DID "${did}", must start with 'did:'`)
  } else if (did.startsWith(DID_KEY_PREFIX)) {
    const key = base58btc.decode(did.slice(DID_KEY_PREFIX_SIZE))
    return decode(key)
  } else {
    const suffix = UTF8.encode(did.slice(DID_PREFIX_SIZE))
    const bytes = new Uint8Array(suffix.byteLength + METHOD_OFFSET)
    varint.encodeTo(DID_CORE, bytes)
    bytes.set(suffix, METHOD_OFFSET)
    return new DID(bytes)
  }
}

/**
 * @template {UCAN.DID} ID
 * @param {UCAN.Principal<ID>} id
 * @returns {ID}
 */
export const format = id => id.did()

/**
 * @template {UCAN.DID} ID
 * @param {UCAN.PrincipalView<ID>|UCAN.ByteView<UCAN.Principal<ID>>|UCAN.Principal<ID>|ID|UCAN.ToJSONString<unknown>} principal
 * @returns {UCAN.PrincipalView<ID>}
 */
export const from = principal => {
  if (principal instanceof DID) {
    return principal
  } else if (principal instanceof Uint8Array) {
    return decode(principal)
  } else if (typeof principal === "string") {
    return parse(principal)
  } else {
    return parse(principal.did())
  }
}

/**
 * @template {UCAN.DID} ID
 * @param {UCAN.ByteView<UCAN.Principal<ID>>} bytes
 * @returns {UCAN.PrincipalView<ID>}
 */
export const decode = bytes => {
  const [code] = varint.decode(bytes)
  const { buffer, byteOffset, byteLength } = bytes
  switch (code) {
    case P256:
      if (bytes.length > 35) {
        throw new RangeError(`Only p256-pub compressed is supported.`)
      }
    case ED25519:
    case RSA:
    case P384:
    case P521:
    case BLS12381G1:
    case BLS12381G2:
    case SECP256K1:
      return /** @type {UCAN.PrincipalView<any>} */ (
        new DIDKey(buffer, byteOffset, byteLength)
      )
    case DID_CORE:
      return new DID(buffer, byteOffset, byteLength)
    default:
      throw new RangeError(
        `Unsupported DID encoding, unknown multicode 0x${code.toString(16)}.`
      )
  }
}

/**
 * @template {UCAN.DID} ID
 * @param {UCAN.Principal<ID>} principal
 * @returns {UCAN.PrincipalView<ID>}
 */
export const encode = principal => parse(principal.did())

/**
 * @template {UCAN.DID} ID
 * @implements {UCAN.PrincipalView<ID>}
 * @extends {Uint8Array}
 */
class DID extends Uint8Array {
  /**
   * @returns {ID}
   */
  did() {
    const bytes = new Uint8Array(this.buffer, this.byteOffset + METHOD_OFFSET)
    return /** @type {ID} */ (`did:${UTF8.decode(bytes)}`)
  }

  toJSON() {
    return this.did()
  }
}

/**
 * @implements {UCAN.PrincipalView<UCAN.DID<"key">>}
 * @extends {DID<UCAN.DID<"key">>}
 */
class DIDKey extends DID {
  /**
   * @return {`did:key:${string}`}
   */
  did() {
    return `did:key:${base58btc.encode(this)}`
  }
}
