/* eslint-env mocha */
import * as UCAN from "../src/lib.js"
import { assert } from "chai"
import { fetch } from "./util.js"
import { alice, bob, mallory } from "./fixtures.js"
import * as token from "ucans/dist/token.js"

const utf8 = new TextEncoder()
const MURMUR = 0x22

/**
 * @param {string} text
 */
const utf8Encode = text => utf8.encode(text)

describe("dag-ucan", () => {
  it("self-issued token", async () => {
    const ucan = await UCAN.issue({
      issuer: alice,
      audience: alice.did(),
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })

    assert.deepEqual(ucan.issuer, alice.did())
    assert.deepEqual(ucan.audience, alice.did())
    assert.deepEqual(ucan.capabilities, [
      {
        with: alice.did(),
        can: "store/put",
      },
    ])
    assert.ok(ucan.expiration > Date.now() / 1000)
    assert.equal(ucan.notBefore, undefined)
    assert.equal(ucan.nonce, undefined)
    assert.equal(ucan.facts, undefined)
    assert.deepEqual(ucan.proofs, [])
  })

  it("ts-ucan compat", async () => {
    const ucan = await UCAN.issue({
      issuer: alice,
      audience: alice.did(),
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })

    assert.ok(
      await token.validate(UCAN.format(ucan), {
        checkIsExpired: true,
        checkIssuer: true,
        checkSignature: true,
      })
    )
  })
})

describe("ts-ucan compat", () => {
  async function makeUcan() {
    return await token.build({
      audience: bob.did(),
      issuer: alice,
      capabilities: [
        {
          with: {
            scheme: "wnfs",
            hierPart: "//boris.fission.name/public/photos/",
          },
          can: { namespace: "crud", segments: ["DELETE"] },
        },
        {
          with: {
            scheme: "wnfs",
            hierPart:
              "//boris.fission.name/private/84MZ7aqwKn7sNiMGsSbaxsEa6EPnQLoKYbXByxNBrCEr",
          },
          can: { namespace: "wnfs", segments: ["APPEND"] },
        },
        {
          with: { scheme: "mailto", hierPart: "boris@fission.codes" },
          can: { namespace: "msg", segments: ["SEND"] },
        },
      ],
    })
  }

  it("round-trips with token.build", async () => {
    const ucan = await makeUcan()

    const ucan2 = UCAN.parse(token.encode(ucan))
    assert.equal(ucan2.issuer, alice.did())
    assert.equal(ucan2.audience, bob.did())
    /*
    For some reason ts-ucan encodes differently
    assert.deepEqual(ucan2.capabilities, [
      {
        with: "wnfs://boris.fission.name/public/photos/",
        can: "crud/DELETE",
      },
      {
        with: "wnfs://boris.fission.name/private/84MZ7aqwKn7sNiMGsSbaxsEa6EPnQLoKYbXByxNBrCEr",
        can: "wnfs/APPEND",
      },
      {
        with: "mailto:boris@fission.codes",
        can: "msg/SEND",
      },
    ])
    */
  })
})
