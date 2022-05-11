/**
 * Represents an entity that can verify signatures produced by a given signing algorithm `A`.
 * 
 * @template A - the [multicodec code](https://github.com/multiformats/multicodec/blob/master/table.csv) 
 * for a cryptographic signing algorithm
 */
export interface Verifier<A extends number = number> {
  /**
   * Takes byte encoded payload and verifies that it is signed by corresponding
   * signer.
   */
  verify<T>(payload: ByteView<T>, signature: Signature<T, A>): Await<boolean>
}

/**
 * Represents an entity that can sign a payload using the signing algorithm `A`. 
 * 
 * @template A - the [multicodec code](https://github.com/multiformats/multicodec/blob/master/table.csv) 
 * for a cryptographic signing algorithm
 */
export interface Signer<A extends number = number> {
  /**
   * Takes byte encoded payload and produces a verifiable signature.
   */
  sign<T>(payload: ByteView<T>): Await<Signature<T, A>>
}

/**
 * Represents a cryptographic signature of (the byte-encoding of) some data of type `T`.
 * 
 * @template T - represents the structure of the data that was byte-encoded before signing
 * @template A - the [multicodec code](https://github.com/multiformats/multicodec/blob/master/table.csv) 
 * for a cryptographic signing algorithm
 */
export interface Signature<T = unknown, A extends number = number>
  extends ByteView<T> {
  algorithm?: A
}

/**
 * Just like {@link Verifier}, except definitely async.
 */
export interface AsyncVerifier<A extends number> {
  verify<T>(
    payload: ByteView<T>,
    signature: Signature<T, A>
  ): PromiseLike<boolean>
}

/**
 * Just like {@link Verifier}, but definitely sync.
 */
export interface SyncVerifier<A extends number> {
  verify<T>(payload: ByteView<T>, signature: Signature<T, A>): boolean
}

/**
 * Just like {@link Signer}, but definitely sync.
 */
export interface SyncSigner<A extends number = number> {
  sign<T>(payload: ByteView<T>): Signature<T, A>
}

/**
 * Just like {@link Signer}, but definitely async.
 */
export interface AsyncSigner<A extends number = number> {
  sign<T>(payload: ByteView<T>): PromiseLike<Signature<T, A>>
}

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
 * Something you can `await` and get a `T` out of. Either a `T` already, or a Promise for a `T`.
 */
export type Await<T> = T | PromiseLike<T>

/**
 * A utility type to retain an unused type parameter `T`.
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
  [PhantomKey]?: T
}

declare const PhantomKey: unique symbol
