/* eslint-env mocha */
import * as UCAN from "../src/lib.js"
import * as DID from "../src/did.js"
import { assert } from "chai"
import { alice, bob, mallory, JWT_UCAN, JWT_UCAN_SIG } from "./fixtures.js"
import * as Signature from "../src/signature.js"
import { varint } from "multiformats"
import * as UTF8 from "../src/utf8.js"
import { base64url, base64 } from "multiformats/bases/base64"

describe("Signature", () => {
  const dataset = [
    {
      title: "non standard signature",
      algorithm: "GOZ256",
      code: Signature.NON_STANDARD,
    },
    {
      algorithm: "EdDSA",
      code: Signature.EdDSA,
    },
    {
      algorithm: "ES256K",
      code: Signature.ES256K,
    },
    {
      algorithm: "BLS12381G1",
      code: Signature.BLS12381G1,
    },
    {
      algorithm: "BLS12381G2",
      code: Signature.BLS12381G2,
    },
    {
      algorithm: "ES256",
      code: Signature.ES256,
    },
    {
      algorithm: "ES384",
      code: Signature.ES384,
    },
    {
      algorithm: "ES512",
      code: Signature.ES512,
    },
    {
      algorithm: "RS256",
      code: Signature.RS256,
    },
    {
      algorithm: "EIP191",
      code: Signature.EIP191,
    },
  ]
  for (const { code, algorithm, title = algorithm } of dataset) {
    it(title, () => {
      const raw = UTF8.encode(title)
      const sig = Signature.createNamed(algorithm, raw)
      assert.deepEqual(
        sig.byteLength,
        varint.encodingLength(code) +
          varint.encodingLength(raw.byteLength) +
          raw.byteLength +
          (code === Signature.NON_STANDARD
            ? UTF8.encode(algorithm).byteLength
            : 0)
      )

      assert.deepEqual(sig.code, code)
      assert.deepEqual(sig.algorithm, algorithm)
      assert.deepEqual(sig.raw, raw)
      assert.deepEqual(
        JSON.stringify(sig),
        JSON.stringify({ "/": { bytes: base64.baseEncode(sig) } })
      )
    })

    it(`roundtrip ${title}`, () => {
      const raw = UTF8.encode(`parse<->format ${title}`)
      const sig = Signature.createNamed(algorithm, raw)

      assert.deepEqual(sig, Signature.parse(Signature.format(sig)))
      assert.deepEqual(sig, Signature.fromJSON(Signature.toJSON(sig)))
    })
  }

  it("fails to decode sigs with unknown code", () => {
    /** @type {Uint8Array} */
    const raw = UTF8.encode(`give me some bytes`)
    const code = 0x0d1300
    const sizeOffset = varint.encodingLength(code)
    const rawOffset = sizeOffset + varint.encodingLength(raw.byteLength)
    const bytes = new Uint8Array(rawOffset + raw.byteLength)
    varint.encodeTo(0x0d1300, bytes)
    varint.encodeTo(raw.byteLength, bytes, sizeOffset)
    bytes.set(raw, rawOffset)
    assert.throws(
      () => Signature.decode(bytes),
      /Unknown signature algorithm code/
    )
  })

  it(".verify can be used to verify signature", async () => {
    const payload = UTF8.encode(`give me some bytes`)
    const signature = await alice.sign(payload)

    const result = await signature.verify(alice, payload)
    assert.deepEqual(result, { ok: {} }, "succeeds if payload is the same")

    assert.deepEqual(
      `${(await signature.verify(alice, payload.slice(0, -1))).error?.message}`,
      "Invalid signature",
      "fails if payload is different"
    )

    assert.deepEqual(
      (await signature.verify(bob, payload)).error?.message,
      "Invalid signature",
      "fails if signer is different"
    )
  })
})
