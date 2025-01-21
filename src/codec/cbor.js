import * as UCAN from "../ucan.js"
import * as CBOR from "@ipld/dag-cbor"
import { readPayload, readVersion, readSignature } from "../schema.js"
import { format } from "../formatter.js"
import * as Signature from "../signature.js"
import { View } from "../view.js"

export const name = "dag-ucan"
export const code = CBOR.code

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
 * @param {UCAN.FromModel<C>} model
 * @returns {UCAN.View<C>}
 */
export const from = model => new CBORView(model)

/**
 * Encodes given UCAN (in either IPLD or JWT representation) and encodes it into
 * corresponding bytes representation. UCAN in IPLD representation is encoded as
 * DAG-CBOR which JWT representation is encoded as raw bytes of JWT string.
 *
 * @template {UCAN.Capabilities} C
 * @param {UCAN.Model<C>} model
 * @returns {UCAN.ByteView<UCAN.Model<C>>}
 */
export const encode = model => {
  const { fct, nnc, nbf, ...payload } = readPayload(model)

  return /** @type {Uint8Array} */ (
    CBOR.encode({
      // leave out optionals unless they are set
      ...(fct.length > 0 && { fct }),
      ...(nnc != null && { nnc }),
      ...(nbf && { nbf }),
      ...payload,
      // add version and signature
      v: readVersion(model.v, "v"),
      s: encodeSignature(model.s, "s"),
    })
  )
}

/**
 * @param {UCAN.Signature} signature
 * @param {string} context
 */
const encodeSignature = (signature, context) => {
  try {
    return Signature.encode(signature)
  } catch (cause) {
    throw new Error(
      `Expected signature ${context}, instead got ${JSON.stringify(signature)}`,
      // @ts-expect-error - types don't know about second arg
      { cause }
    )
  }
}

/**
 * Decodes UCAN in primary CBOR representation. It does not validate UCAN, it's
 * signature or proof chain. This is to say decoded UCAN may be invalid.
 *
 * @template {UCAN.Capabilities} C
 * @param {UCAN.ByteView<UCAN.Model<C>>} bytes
 * @returns {UCAN.View<C>}
 */
export const decode = bytes => {
  const model = CBOR.decode(bytes)
  return new CBORView({
    ...readPayload(model),
    v: readVersion(model.v, "v"),
    s: readSignature(model.s),
  })
}

export { format }

/**
 * @template {UCAN.Capabilities} C
 * @extends {View<C>}
 */
class CBORView extends View {
  /** @type {UCAN.MulticodecCode<typeof code, "CBOR">} */
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
