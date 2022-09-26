/* eslint-env mocha */
import * as UCAN from "../src/lib.js"
import * as DID from "../src/did.js"
import { assert } from "chai"
import { alice, bob, mallory, JWT_UCAN, JWT_UCAN_SIG } from "./fixtures.js"

describe("DID", () => {
  it("DID.parse non did", () => {
    assert.throws(
      () =>
        DID.parse("d1d:key:z6Mkk89bC3JrVqKie71YEcc5M1SMVxuCgNx6zLZ8SYJsxALi"),
      /Invalid DID "d1d:key:.*", must start with 'did:/
    )
  })

  it("DID.from duck", () => {
    const ali = DID.from({
      did() {
        return alice.did()
      },
    })

    assert.equal(ali.did(), alice.did())
  })

  it("DID.encode <-> DID.decode", () => {
    assert.equal(DID.decode(DID.encode(alice)).did(), alice.did())
  })
})
