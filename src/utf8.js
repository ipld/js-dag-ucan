export const encoder = new TextEncoder()
export const decoder = new TextDecoder()

/**
 * @template T
 * @param {import('./ucan').ToString<T>} text
 * @returns {import('./ucan').ByteView<T>}
 */
export const encode = text => encoder.encode(text)

/**
 * @template T
 * @param {import('./ucan').ByteView<T>} bytes
 * @returns {import('./ucan').ToString<T>}
 */
export const decode = bytes => decoder.decode(bytes)
