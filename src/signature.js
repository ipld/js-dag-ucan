import * as UCAN from "./ucan.js"
import { varint } from "multiformats"
import { base64url, base64 } from "multiformats/bases/base64"
import * as UTF8 from "./utf8.js"

export const NON_STANDARD = 0xd000
export const ES256K = 0xd0e7
export const BLS12381G1 = 0xd0ea
export const BLS12381G2 = 0xd0eb
export const EdDSA = 0xd0ed
export const ES256 = 0xd01200
export const ES384 = 0xd01201
export const ES512 = 0xd01202
export const RS256 = 0xd01205
export const EIP191 = 0xd191

/**
 * @param {number} code
 * @returns {string}
 */
const codeName = code => {
  switch (code) {
    case ES256K:
      return "ES256K"
    case BLS12381G1:
      return "BLS12381G1"
    case BLS12381G2:
      return "BLS12381G2"
    case EdDSA:
      return "EdDSA"
    case ES256:
      return "ES256"
    case ES384:
      return "ES384"
    case ES512:
      return "ES512"
    case RS256:
      return "RS256"
    case EIP191:
      return "EIP191"
    default:
      throw new RangeError(
        `Unknown signature algorithm code 0x${code.toString(16)}`
      )
  }
}

/**
 *
 * @param {string} name
 */
export const nameCode = name => {
  switch (name) {
    case "ES256K":
      return ES256K
    case "BLS12381G1":
      return BLS12381G1
    case "BLS12381G2":
      return BLS12381G2
    case "EdDSA":
      return EdDSA
    case "ES256":
      return ES256
    case "ES384":
      return ES384
    case "ES512":
      return ES512
    case "RS256":
      return RS256
    case "EIP191":
      return EIP191
    default:
      return NON_STANDARD
  }
}

/**
 * @template {unknown} T
 * @template {number} A
 * @implements {UCAN.SignatureView<T, A>}
 */
export class Signature extends Uint8Array {
  get code() {
    const [code] = varint.decode(this)
    Object.defineProperties(this, { code: { value: code } })
    return /** @type {A} */ (code)
  }

  get size() {
    const value = size(this)
    Object.defineProperties(this, { size: { value } })
    return value
  }
  get algorithm() {
    const value = algorithm(this)
    Object.defineProperties(this, { algorithm: { value } })
    return value
  }

  get raw() {
    const { buffer, byteOffset, size, code } = this
    const codeSize = varint.encodingLength(code)
    const rawSize = varint.encodingLength(size)
    const value = new Uint8Array(buffer, byteOffset + codeSize + rawSize, size)
    Object.defineProperties(this, { raw: { value } })
    return value
  }

  /**
   * Verify that this signature was created by the given key.
   *
   * @param {UCAN.Crypto.Verifier<A>} signer
   * @param {UCAN.ByteView<T>} payload
   */
  async verify(signer, payload) {
    try {
      if ((await signer.verify(payload, this)) === true) {
        return { ok: {} }
      } else {
        throw new Error("Invalid signature")
      }
    } catch (cause) {
      return { error: /** @type {Error} */ (cause) }
    }
  }

  toJSON() {
    return toJSON(this)
  }
}

/**
 * @param {UCAN.Signature} signature
 */
const algorithm = signature => {
  const { code, raw, buffer, byteOffset } = signature
  if (code === NON_STANDARD) {
    const offset =
      raw.byteLength +
      varint.encodingLength(code) +
      varint.encodingLength(raw.byteLength)
    const bytes = new Uint8Array(buffer, byteOffset + offset)
    return UTF8.decode(bytes)
  } else {
    return codeName(code)
  }
}

/**
 * @param {UCAN.Signature} signature
 */
const size = signature => {
  const offset = varint.encodingLength(signature.code)
  const [size] = varint.decode(
    new Uint8Array(signature.buffer, signature.byteOffset + offset)
  )
  return size
}

/**
 * @template {unknown} T
 * @template {number} A
 * @param {A} code
 * @param {Uint8Array} raw
 * @returns {UCAN.SignatureView<T, A>}
 */
export const create = (code, raw) => {
  const _ = codeName(code)
  const codeSize = varint.encodingLength(code)
  const rawSize = varint.encodingLength(raw.byteLength)

  /** @type {Signature<T, A>} */
  const signature = new Signature(codeSize + rawSize + raw.byteLength)
  varint.encodeTo(code, signature)
  varint.encodeTo(raw.byteLength, signature, codeSize)
  signature.set(raw, codeSize + rawSize)
  Object.defineProperties(signature, {
    code: { value: code },
    size: { value: raw.byteLength },
  })
  return signature
}

/**
 * @template {unknown} T
 * @param {string} name
 * @param {Uint8Array} raw
 * @return {UCAN.SignatureView<T>}
 */
export const createNamed = (name, raw) => {
  const code = nameCode(name)
  return code === NON_STANDARD
    ? createNonStandard(name, raw)
    : create(code, raw)
}

/**
 * @template {unknown} T
 * @param {string} name
 * @param {Uint8Array} raw
 * @return {UCAN.SignatureView<T, typeof NON_STANDARD>}
 */
export const createNonStandard = (name, raw) => {
  const code = NON_STANDARD
  const codeSize = varint.encodingLength(code)
  const rawSize = varint.encodingLength(raw.byteLength)
  const nameBytes = UTF8.encode(name)
  /** @type {Signature<T, typeof NON_STANDARD>} */
  const signature = new Signature(
    codeSize + rawSize + raw.byteLength + nameBytes.byteLength
  )
  varint.encodeTo(code, signature)
  varint.encodeTo(raw.byteLength, signature, codeSize)
  signature.set(raw, codeSize + rawSize)
  signature.set(nameBytes, codeSize + rawSize + raw.byteLength)

  return signature
}

/**
 * @template {unknown} T
 * @template {number} A
 * @param {UCAN.ByteView<UCAN.Signature<T, A>>} bytes
 * @returns {UCAN.SignatureView<T, A>}
 */
export const view = bytes =>
  new Signature(bytes.buffer, bytes.byteOffset, bytes.byteLength)

/**
 * @template {unknown} T
 * @template {number} A
 * @param {UCAN.ByteView<UCAN.Signature<T, A>>} bytes
 * @returns {UCAN.SignatureView<T, A>}
 */
export const decode = bytes => {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError(
      `Can only decode Uint8Array into a Signature, instead got ${JSON.stringify(
        bytes
      )}`
    )
  }

  /** @type {UCAN.SignatureView<T, A>} */
  const signature = view(bytes)
  const { code, algorithm, raw } = signature
  return signature
}

/**
 * @template {unknown} T
 * @template {number} A
 * @param {UCAN.Signature<T, A>} signature
 * @returns {UCAN.ByteView<UCAN.Signature<T, A>>}
 */
export const encode = signature => decode(signature)

/**
 * @template {unknown} T
 * @template {number} A
 * @template {string} [Prefix="u"]
 * @param {UCAN.Signature<T, A>} signature
 * @param {UCAN.MultibaseEncoder<Prefix>} [base]
 * @returns {UCAN.ToString<UCAN.Signature<T, A>>}
 */
export const format = (signature, base) => (base || base64url).encode(signature)

/**
 * @template {unknown} T
 * @template {number} A
 * @template {string} [Prefix="u"]
 * @param {UCAN.ToString<UCAN.Signature<T, A>>} signature
 * @param {UCAN.MultibaseDecoder<Prefix>} [base]
 * @returns {UCAN.SignatureView<T, A>}
 */
export const parse = (signature, base) =>
  /** @type {UCAN.SignatureView<T, A>} */ (
    decode((base || base64url).decode(signature))
  )

/**
 * @template {UCAN.Signature} Signature
 * @param {Signature} signature
 * @returns {UCAN.SignatureJSON<Signature>}
 */
export const toJSON = signature => ({
  "/": { bytes: base64.baseEncode(signature) },
})

/**
 * @template {unknown} T
 * @template {UCAN.SigAlg} A
 * @param {UCAN.SignatureJSON<UCAN.Signature<T, A>>} json
 * @returns {UCAN.SignatureView<T, A>}
 */
export const fromJSON = json => decode(base64.baseDecode(json["/"].bytes))
