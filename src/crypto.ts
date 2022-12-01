import type { ByteView, MulticodecCode } from "./ucan.js"

/**
 * Multicodec code corresponding to the byteprefix of the [VarSig]. It is
 * used to encode which signature algorithm was used to produce signature.
 *
 * [VarSig]:https://github.com/ucan-wg/ucan-ipld/#25-signature
 */
export type SigAlg = MulticodecCode

/**
 * Represents an entity that can verify signatures produced by a given signing
 * algorithm `Alg`.
 */
export interface Verifier<Alg extends SigAlg = SigAlg> {
  /**
   * @template T - Source data before it was byte encoding into payload.
   *
   * Takes byte encoded payload and verifies that it is signed by corresponding
   * signer.
   */
  verify<T>(payload: ByteView<T>, signature: Signature<T, Alg>): Await<boolean>
}

/**
 * Represents an entity that can sign a payload using the signing algorithm
 * `Alg`.
 */
export interface Signer<Alg extends SigAlg = SigAlg> {
  /**
   * @template T - Source data before it was byte encoding into payload.
   *
   * Takes byte encoded payload and produces a verifiable signature.
   */
  sign<T>(payload: ByteView<T>): Await<Signature<T, Alg>>
}

/**
 * Represents a cryptographic signature of (the byte-encoded) data of type `T`.
 *
 * @template T - Represents the structure of the data that was byte-encoded before signing.
 * @template Alg - Multicodec code corresponding to cryptographic signing algorithm used
 */
export interface Signature<T = unknown, Alg extends SigAlg = SigAlg>
  extends ByteView<Signature<T, Alg>> {
  code: Alg
  algorithm: string
  /**
   * Raw signature (without a signature algorithm info)
   */
  raw: Uint8Array
}

/**
 * Just like {@link Verifier}, except definitely async.
 */
export interface AsyncVerifier<Alg extends SigAlg> {
  verify<T>(
    payload: ByteView<T>,
    signature: Signature<T, Alg>
  ): PromiseLike<boolean>
}

/**
 * Just like {@link Verifier}, but definitely sync.
 */
export interface SyncVerifier<Alg extends SigAlg> {
  verify<T>(payload: ByteView<T>, signature: Signature<T, Alg>): boolean
}

/**
 * Just like {@link Signer}, but definitely sync.
 */
export interface SyncSigner<Alg extends SigAlg = SigAlg> {
  sign<T>(payload: ByteView<T>): Signature<T, Alg>
}

/**
 * Just like {@link Signer}, but definitely async.
 */
export interface AsyncSigner<Alg extends SigAlg = SigAlg> {
  sign<T>(payload: ByteView<T>): PromiseLike<Signature<T, Alg>>
}

/**
 * Something you can `await` and get a `T` out of. Either a `T` already, or a Promise for a `T`.
 */
export type Await<T> = T | PromiseLike<T>
