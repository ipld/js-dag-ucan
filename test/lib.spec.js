/* eslint-env mocha */
import * as UCAN from "../src/lib.js"
import { assert } from "chai"
import { alice, bob, mallory } from "./fixtures.js"
import * as TSUCAN from "./ts-ucan.cjs"
import * as RAW from "multiformats/codecs/raw"
import * as UTF8 from "../src/utf8.js"
import { identity } from "multiformats/hashes/identity"
import {
  createRSAIssuer,
  assertCompatible,
  assertUCAN,
  buildJWT,
  formatUnsafe,
} from "./util.js"

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

    assertUCAN(ucan, {
      code: UCAN.cbor,
      version: UCAN.VERSION,
      algorithm: alice.algorithm,
      issuer: alice.did(),
      audience: alice.did(),
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
      notBefore: undefined,
      nonce: undefined,
      facts: [],
      proofs: [],
    })

    assert.ok(ucan.expiration > Date.now() / 1000)
  })

  it("dervie token", async () => {
    const root = await UCAN.issue({
      issuer: alice,
      audience: bob.did(),
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })
    const proof = await UCAN.link(root)
    assert.equal(proof.code, UCAN.code)

    const leaf = await UCAN.issue({
      issuer: bob,
      audience: mallory.did(),
      capabilities: root.capabilities,
      expiration: root.expiration,
      proofs: [proof],
    })

    assertUCAN(leaf, {
      code: UCAN.cbor,
      version: UCAN.VERSION,
      algorithm: alice.algorithm,
      issuer: bob.did(),
      audience: mallory.did(),
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
      notBefore: undefined,
      nonce: undefined,
      facts: [],
      proofs: [proof],
    })
  })

  it("rsa did", async () => {
    const bot = await createRSAIssuer()

    const root = await UCAN.issue({
      issuer: alice,
      audience: bot.did(),
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })
    const proof = await UCAN.link(root)

    const leaf = await UCAN.issue({
      issuer: bot,
      audience: bob.did(),
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
      proofs: [proof],
    })

    assertUCAN(leaf, {
      code: UCAN.cbor,
      version: UCAN.VERSION,
      algorithm: bot.algorithm,
      issuer: bot.did(),
      audience: bob.did(),
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
      notBefore: undefined,
      nonce: undefined,
      facts: [],
      proofs: [proof],
    })

    await assertCompatible(leaf)
  })

  it("with nonce", async () => {
    const root = await UCAN.issue({
      issuer: alice,
      audience: bob.did(),
      nonce: "hello",
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })

    await assertCompatible(root)
    assertUCAN(root, {
      code: UCAN.cbor,
      version: UCAN.VERSION,
      algorithm: alice.algorithm,
      issuer: alice.did(),
      audience: bob.did(),
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
      notBefore: undefined,
      nonce: "hello",
      facts: [],
      proofs: [],
    })
  })

  it("with facts", async () => {
    const root = await UCAN.issue({
      issuer: alice,
      audience: bob.did(),
      facts: [
        {
          hello: "world",
        },
      ],
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })

    await assertCompatible(root)
    assertUCAN(root, {
      code: UCAN.cbor,
      version: UCAN.VERSION,
      algorithm: alice.algorithm,
      issuer: alice.did(),
      audience: bob.did(),
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
      facts: [
        {
          hello: "world",
        },
      ],
      notBefore: undefined,
      nonce: undefined,
      proofs: [],
    })
  })

  it("with notBefore", async () => {
    const now = Math.floor(Date.now() / 1000)
    const root = await UCAN.issue({
      issuer: alice,
      audience: bob.did(),
      facts: [],
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
      notBefore: now + 10,
      expiration: now + 120,
    })

    assertUCAN(root, {
      code: UCAN.cbor,
      version: UCAN.VERSION,
      algorithm: alice.algorithm,
      issuer: alice.did(),
      audience: bob.did(),
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
      facts: [],
      notBefore: now + 10,
      expiration: now + 120,
      nonce: undefined,
      proofs: [],
    })
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
      await TSUCAN.validate(UCAN.format(ucan), {
        checkIsExpired: true,
        checkIssuer: true,
        checkSignature: true,
      })
    )
  })
})

describe("errors", () => {
  it("throws on bad audience", async () => {
    try {
      const root = await UCAN.issue({
        issuer: alice,
        // @ts-expect-error
        audience: "bob",
        nonce: "hello",
        capabilities: [
          {
            with: alice.did(),
            can: "store/put",
          },
        ],
      })
      assert.fail("Should have thrown on bad did")
    } catch (error) {
      assert.match(String(error), /The audience must be a DID/)
    }
  })

  /** @type {Record<string, [UCAN.Capability, ?RegExp]>} */
  const invilidCapabilities = {
    'must have "can"': [
      // @ts-expect-error
      { with: alice.did() },
      /Capability has invalid 'can: undefined', value must be a string/,
    ],
    "must have path segment": [
      // @ts-expect-error
      { with: alice.did(), can: "send" },
      /Capability has invalid 'can: "send"', value must have at least one path segment/,
    ],
    "must have segment after path": [
      { with: alice.did(), can: "send/" },
      /Capability has invalid 'can: "send\/"', value must have at least one path segment/,
    ],
    "must have segment before path": [
      { with: alice.did(), can: "/send" },
      /Capability has invalid 'can: "\/send"', value must have at least one path segment/,
    ],
    "with my:* it must have can: *": [
      {
        with: "my:*",
        can: "msg/send",
      },
      /Capability has invalid 'can: "msg\/send"', for all 'my:\*' or 'as:<did>:\*' it must be '\*'/,
    ],
    "with as:<did>:* must have can: *": [
      {
        // @ts-ignore
        with: `as:${alice.did()}:*`,
        can: "msg/send",
      },
      /Capability has invalid 'can: "msg\/send"', for all 'my:\*' or 'as:<did>:\*' it must be '\*'/,
    ],

    "with must be string": [
      // @ts-expect-error
      {
        can: "msg/send",
      },
      /Capability has invalid 'with: undefined', value must be a string/,
    ],

    "with must have something prior to :": [
      {
        can: "msg/send",
        with: ":hello",
      },
      /Capability has invalid 'with: ":hello"', value must be a valid URI string/,
    ],

    "with as:<did>:* may have can: *": [
      {
        // @ts-ignore
        with: `as:${alice.did()}:*`,
        can: "*",
      },
      null,
    ],

    "with my:* it may have can: *": [
      {
        with: "my:*",
        can: "*",
      },
      null,
    ],
  }

  for (const [title, [capability, expect]] of Object.entries(
    invilidCapabilities
  )) {
    it(title, async () => {
      try {
        await UCAN.issue({
          issuer: alice,
          audience: bob.did(),
          capabilities: [capability],
        })

        if (expect) {
          assert.fail("Should throw error on invalid capability")
        }
      } catch (error) {
        if (expect) {
          assert.match(String(error), expect)
        } else {
          throw error
        }
      }
    })
  }

  it("decode throws on invalid code", async () => {
    const ucan = await UCAN.issue({
      issuer: alice,
      audience: bob.did(),
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })

    assert.throws(
      () =>
        UCAN.encode({
          ...ucan,
          // @ts-expect-error
          code: 0x0129,
        }),
      /Provided UCAN has unsupported code/
    )
  })

  it("format throws on invalid code", async () => {
    const ucan = await UCAN.issue({
      issuer: alice,
      audience: bob.did(),
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })

    assert.throws(
      () =>
        UCAN.format({
          ...ucan,
          // @ts-expect-error
          code: 0x0129,
        }),
      /Provided UCAN has unsupported code/
    )
  })
})

describe("parse", () => {
  it("errors on invalid jwt", async () => {
    const jwt = await buildJWT({ issuer: alice, audience: bob })
    assert.throws(
      () => UCAN.parse(jwt.slice(jwt.indexOf(".") + 1)),
      /Expected JWT format: 3 dot-separated/
    )
  })

  it("hash conistent ucan is parsed into IPLD representation", async () => {
    const jwt = await formatUnsafe(alice, {
      body: {
        att: [
          {
            can: "send/message",
            with: "mailto:*",
          },
        ],
      },
    })
    const ucan = UCAN.parse(jwt)
    assertUCAN(ucan, {
      code: UCAN.cbor,
      version: UCAN.VERSION,
      algorithm: alice.algorithm,
      issuer: alice.did(),
      audience: alice.did(),
      capabilities: [
        {
          can: "send/message",
          with: "mailto:*",
        },
      ],
      facts: [],
      notBefore: undefined,
      nonce: undefined,
      proofs: [],
    })
  })

  it("errors on invalid nnc", async () => {
    const jwt = await formatUnsafe(alice, {
      body: {
        nnc: 5,
        att: [
          {
            can: "send/message",
            with: "mailto:*",
          },
        ],
      },
    })

    assert.throws(() => UCAN.parse(jwt), /nnc has invalid value 5/)
  })

  it("errors on invalid nbf", async () => {
    const jwt = await formatUnsafe(alice, {
      body: {
        nbf: "tomorrow",
        att: [
          {
            can: "send/message",
            with: "mailto:*",
          },
        ],
      },
    })

    assert.throws(() => UCAN.parse(jwt), /nbf has invalid value "tomorrow"/)
  })

  it("errors on invalid alg", async () => {
    const jwt = await formatUnsafe(alice, {
      header: {
        alg: alice.keyType,
      },
      body: {
        att: [
          {
            can: "send/message",
            with: "mailto:*",
          },
        ],
      },
    })

    assert.throws(
      () => UCAN.parse(jwt),
      /Header has invalid algorithm 'alg: "ed25519"'/
    )
  })

  it("errors on invalid typ", async () => {
    const jwt = await formatUnsafe(alice, {
      header: {
        typ: "IPLD",
      },
      body: {
        att: [
          {
            can: "send/message",
            with: "mailto:*",
          },
        ],
      },
    })

    assert.throws(
      () => UCAN.parse(jwt),
      /Header has invalid type 'typ: "IPLD"'/
    )
  })

  it("errors on invalid ucv", async () => {
    const jwt = await formatUnsafe(alice, {
      header: {
        ucv: "9.0",
      },
      body: {
        att: [
          {
            can: "send/message",
            with: "mailto:*",
          },
        ],
      },
    })

    assert.throws(
      () => UCAN.parse(jwt),
      /Header has invalid version 'ucv: "9.0"'/
    )
  })

  it("errors on invalid att", async () => {
    const jwt = await formatUnsafe(alice, {
      body: {
        att: {
          can: "send/message",
          with: "mailto:*",
        },
      },
    })

    assert.throws(() => UCAN.parse(jwt), /att must be an array/)
  })

  it("errors on invalid fct", async () => {
    const jwt = await formatUnsafe(alice, {
      body: {
        att: [
          {
            can: "send/message",
            with: "mailto:*",
          },
        ],
        fct: [1],
      },
    })

    assert.throws(() => UCAN.parse(jwt), /fct elements must be of type object/)
  })

  it("errors on invalid aud", async () => {
    const jwt = await formatUnsafe(alice, {
      body: {
        aud: "bob",
        att: [
          {
            can: "send/message",
            with: "mailto:*",
          },
        ],
        fct: [1],
      },
    })

    assert.throws(() => UCAN.parse(jwt), /DID has invalid representation 'bob'/)
  })

  it("errors on invalid prf (must be array of string)", async () => {
    const jwt = await formatUnsafe(alice, {
      body: {
        att: [
          {
            can: "send/message",
            with: "mailto:*",
          },
        ],
        prf: [1],
      },
    })

    assert.throws(
      () => UCAN.parse(jwt),
      /prf has invalid value 1, must be a string/
    )
  })

  it("errors on invalid prf", async () => {
    const jwt = await formatUnsafe(alice, {
      body: {
        att: [
          {
            can: "send/message",
            with: "mailto:*",
          },
        ],
        prf: {},
      },
    })

    assert.throws(
      () => UCAN.parse(jwt),
      /prf has invalid value {}, must be a string/
    )
  })
})

describe("ts-ucan compat", () => {
  it("round-trips with token.build", async () => {
    const jwt = await buildJWT({ issuer: alice, audience: bob })
    const ucan = UCAN.parse(jwt)
    assertUCAN(ucan, {
      code: UCAN.raw,
      version: UCAN.VERSION,
      issuer: alice.did(),
      audience: bob.did(),
      facts: [],
      proofs: [],
      notBefore: undefined,
      nonce: undefined,
      capabilities: [
        {
          with: "wnfs://boris.fission.name/public/photos/",
          can: "crud/delete",
        },
        {
          with: "wnfs://boris.fission.name/private/84MZ7aqwKn7sNiMGsSbaxsEa6EPnQLoKYbXByxNBrCEr",
          can: "wnfs/append",
        },
        { with: "mailto:boris@fission.codes", can: "msg/send" },
      ],
    })

    assert.equal(UCAN.format(ucan), jwt)

    const cid = await UCAN.link(ucan)
    assert.equal(cid.code, RAW.code)
  })

  it("can have inline proofs", async () => {
    const root = await buildJWT({
      issuer: alice,
      audience: bob,
    })

    const leaf = await buildJWT({
      issuer: bob,
      audience: mallory,
      proofs: [root],
    })

    const ucan = UCAN.parse(leaf)
    assertUCAN(ucan, {
      code: UCAN.raw,
      version: UCAN.VERSION,
      issuer: bob.did(),
      audience: mallory.did(),
      facts: [],
      notBefore: undefined,
      nonce: undefined,
      capabilities: [
        {
          with: "wnfs://boris.fission.name/public/photos/",
          can: "crud/delete",
        },
        {
          with: "wnfs://boris.fission.name/private/84MZ7aqwKn7sNiMGsSbaxsEa6EPnQLoKYbXByxNBrCEr",
          can: "wnfs/append",
        },
        { with: "mailto:boris@fission.codes", can: "msg/send" },
      ],
    })

    const [proof] = ucan.proofs

    assert.equal(proof.code, RAW.code)
    assert.equal(proof.multihash.code, identity.code)

    assert.equal(UTF8.decode(proof.multihash.digest), root)
  })
})
