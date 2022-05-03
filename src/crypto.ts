export interface AsyncVerifier<A extends number> {
  readonly algorithm: A
  verify<S extends Signer<A>, T>(
    payload: ByteView<T>,
    signature: Signature<T, S>
  ): PromiseLike<boolean>
}

export interface SyncVerifier<A extends number> {
  readonly algorithm: A
  verify<S extends Signer<A>, T>(
    payload: ByteView<T>,
    signature: Signature<T, S>
  ): boolean
}

export interface Verifier<A extends number = number> {
  readonly algorithm: A
  verify<S extends Signer<A>, T>(
    payload: ByteView<T>,
    signature: Signature<T, S>
  ): Await<boolean>
}

export interface SyncSigner<A extends number = number> {
  readonly algorithm: A
  sign<T>(payload: ByteView<T>): Signature<T, this>
}

export interface AsyncSigner<A extends number = number> {
  readonly algorithm: A
  sign<T>(payload: ByteView<T>): PromiseLike<Signature<T, this>>
}

export interface Signer<A extends number = number> {
  readonly algorithm: A
  sign<T>(payload: ByteView<T>): Await<Signature<T, this>>
}

/**
 * Represents `T` signed by `S`.
 */
export interface Signature<T = unknown, S extends Signer = Signer>
  extends Phantom<T>,
    Uint8Array {}

/**
 * Represents byte encoded representation of the `Data`. It uses type parameter
 * to capture the structure of the data it encodes.
 */
export interface ByteView<Data> extends Uint8Array, Phantom<Data> {}

export type Await<T> = T | PromiseLike<T>

/**
 * This is an utility type to retain unused type parameter `T`. It can be used
 * as nominal type e.g. to capture semantics not represented in actual type strucutre.
 */
export interface Phantom<T> {
  // This field can not be represented because field name is non-existings
  // unique symbol. But given that field is optional any object will valid
  // type contstraint.
  [PhantomKey]?: T
}

declare const PhantomKey: unique symbol
