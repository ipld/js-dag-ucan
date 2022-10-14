/* eslint-env mocha */
import * as UCAN from "../src/lib.js"
import * as DID from "../src/did.js"
import { assert } from "chai"
import { alice, bob, mallory, JWT_UCAN, JWT_UCAN_SIG } from "./fixtures.js"

describe("inference", () => {
  it("can infer type from block", () =>
    /**
     * @template {UCAN.Capabilities} C
     * @param {UCAN.Block<C>} block
     * @returns {UCAN.View<C>}
     */
    ({ bytes }) => {
      const data = UCAN.decode(bytes)
      return data
    })

  it("can carry type from write -> decode -> format -> parse", () =>
    /**
     * @template {UCAN.Capabilities} C
     * @param {UCAN.View<C>} ucan
     * @returns {Promise<UCAN.View<C>>}
     */
    async ucan => {
      const block = await UCAN.write(ucan)

      return UCAN.parse(UCAN.format(UCAN.decode(block.bytes)))
    })

  it("can parse arbitrary strings", () =>
    /**
     * @returns {UCAN.View}
     */
    () => {
      return UCAN.parse("hello world")
    })

  it("can decode arbitrary bytes", () =>
    /**
     * @returns {UCAN.View}
     */
    () => {
      return UCAN.decode(new Uint8Array())
    })

  it("can format compatible stuff", () => () => {
    const ucan = UCAN.parse("")
    // @ts-expect-error
    UCAN.format({})

    UCAN.format(ucan.model)
    UCAN.format(ucan)
  })
})
