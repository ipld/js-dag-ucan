import type { ByteView } from "./marker.js"

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
 * Something you can `await` and get a `T` out of. Either a `T` already, or a Promise for a `T`.
 */
export type Await<T> = T | PromiseLike<T>
