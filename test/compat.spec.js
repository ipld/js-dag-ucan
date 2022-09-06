import valid from "./fixtures/0.8.1/valid.js"
import * as UCAN from "../src/lib.js"
import { asCapability } from "../src/parser.js"
import { assert } from "chai"
import { assertUCAN } from "./util.js"
import * as DID from "../src/did.js"

const skip = new Set(["Delegated UCAN can delegate"])
describe("0.8.1", () => {
  for (const {
    comment,
    token,
    assertions: { header, payload },
  } of valid) {
    const test = skip.has(comment) ? it.skip : it
    test(comment, () => {
      const ucan = UCAN.parse(token)
      assertUCAN(ucan, {
        version: /** @type {UCAN.Version} */ (header.ucv),
        issuer: DID.parse(/** @type {UCAN.DIDString} */ (payload.iss)),
        audience: DID.parse(/** @type {UCAN.DIDString} */ (payload.aud)),
        capabilities: payload.att.map(asCapability),
      })

      const proofs = ucan.proofs.map(cid => UCAN.decode(cid.multihash.digest))

      assert.deepEqual(proofs.map(UCAN.format), payload.prf)

      assert.equal(UCAN.format(ucan), token)
    })
  }
})
