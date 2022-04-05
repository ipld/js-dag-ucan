export const encoder = new TextEncoder()
export const decoder = new TextDecoder()

/**
 * @template {string} Text
 * @param {Text} text
 * @returns {import('./ucan').ByteView<Text>}
 */
export const encode = text => encoder.encode(text)

/**
 * @template {string} Text
 * @param {import('./ucan').ByteView<Text>} bytes
 * @returns {Text}
 */
export const decode = bytes => /** @type {Text} */ (decoder.decode(bytes))
