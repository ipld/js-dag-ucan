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

  it("JSON.stringify", () => {
    assert.deepEqual(JSON.stringify(DID.parse(alice.did())), `"${alice.did()}"`)
  })

  // @see https://w3c-ccg.github.io/did-method-key/#test-vectors
  const fixtures = [
    'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp',
    'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG',
    'did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf',
    // @see https://w3c-ccg.github.io/did-method-key/#secp256k1
    'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme',
    'did:key:zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2',
    'did:key:zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N',
    // @see https://w3c-ccg.github.io/did-method-key/#bls-12381
    'did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY',
    'did:key:zUC7KKoJk5ttwuuc8pmQDiUmtckEPTwcaFVZe4DSFV7fURuoRnD17D3xkBK3A9tZqdADkTTMKSwNkhjo9Hs6HfgNUXo48TNRaxU6XPLSPdRgMc15jCD5DfN34ixjoVemY62JxnW',
    // @see https://w3c-ccg.github.io/did-method-key/#p-256
    'did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169',
    'did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv',
    // @see https://w3c-ccg.github.io/did-method-key/#p-384
    'did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9',
    'did:key:z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54',
    // @see https://w3c-ccg.github.io/did-method-key/#p-521
    'did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7'
    'did:key:z2J9gcGdb2nEyMDmzQYv2QZQcM1vXktvy1Pw4MduSWxGabLZ9XESSWLQgbuPhwnXN7zP7HpTzWqrMTzaY5zWe6hpzJ2jnw4f',
    // @see https://w3c-ccg.github.io/did-method-key/#rsa
    'did:key:z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i'
  ]
  
  it("did fixtures", () => {
    for (const did of fixtures) {
      assert.equal(DID.format(DID.parse(id)).did(), id)
    }
  })
})
