/* eslint-env mocha */
import * as UCAN from "../src/lib.js"
import * as DID from "../src/did.js"
import { assert } from "chai"
import { alice, bob, mallory, JWT_UCAN, JWT_UCAN_SIG } from "./fixtures.js"

describe("DID", () => {
  it("can infer decode type", () => {
    /**
     * @template {UCAN.Capabilities} C
     * @param {UCAN.Block<C>} block
     * @returns {UCAN.View<C>}
     */
    const decode = ({ bytes }) => {
      const data = UCAN.decode(bytes)
      return data
    }
  })
})
