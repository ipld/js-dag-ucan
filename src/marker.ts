/**
 * A byte-encoded representation of some type of `Data`.
 *
 * A `ByteView` is essentially a `Uint8Array` that's been "tagged" with
 * a `Data` type parameter indicating the type of encoded data.
 *
 * For example, a `ByteView<DID>` is a `Uint8Array` containing a binary
 * representation of a {@link DID}.
 */
export interface ByteView<Data> extends Uint8Array, Phantom<Data> {}

/**
 * Utility type that retains type information about data of type `In`, encoded
 * as type `Out`.
 *
 * For concrete examples see {@link ToString} and {@link ToJSONString}.
 */
export type Encoded<In, Out> = Out & Phantom<In>

/**
 * Data of some type `In`, encoded as a string.
 */
export type ToString<In, Out extends string = string> = Encoded<In, Out>

/**
 * Data of some type `In`, encoded as a JSON string.
 */
export type ToJSONString<In, Out extends string = string> = Encoded<In, Out>

/**
 * A byte-encoded representation of some type of `Data`.
 *
 * A `ByteView` is essentially a `Uint8Array` that's been "tagged" with
 * a `Data` type parameter indicating the type of encoded data.
 *
 * For example, a `ByteView<DID>` is a `Uint8Array` containing a binary
 * representation of a {@link DID}.
 */
export interface ByteView<Data> extends Uint8Array, Phantom<Data> {}

/**
 * A utility type to retain an unused type parameter `T`.
 * Similar to [phantom type parameters in Rust](https://doc.rust-lang.org/rust-by-example/generics/phantom.html).
 *
 * Capturing unused type parameters allows us to define "nominal types," which
 * TypeScript does not natively support. Nominal types in turn allow us to capture
 * semantics not represented in the actual type structure, without requring us to define
 * new classes or pay additional runtime costs.
 *
 * For a concrete example, see {@link ByteView}, which extends the `Uint8Array` type to capture
 * type information about the structure of the data encoded into the array.
 */
export interface Phantom<T> {
  // This field can not be represented because field name is non-existings
  // unique symbol. But given that field is optional any object will valid
  // type contstraint.
  [Marker]?: T
}

declare const Marker: unique symbol
