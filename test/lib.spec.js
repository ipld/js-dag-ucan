/* eslint-env mocha */
import * as UCAN from "../src/lib.js"
import { assert } from "chai"
import { alice, bob, mallory, JWT_UCAN, JWT_UCAN_SIG } from "./fixtures.js"
import * as TSUCAN from "./ts-ucan.cjs"
import * as RAW from "../src/codec/raw.js"
import * as CBOR from "../src/codec/cbor.js"
import * as UTF8 from "../src/utf8.js"
import * as DID from "../src/did.js"
import { identity } from "multiformats/hashes/identity"
import {
  Verifier,
  createRSAIssuer,
  assertCompatible,
  assertUCAN,
  buildJWT,
  formatUnsafe,
} from "./util.js"
import { sha256 } from "multiformats/hashes/sha2"

describe("dag-ucan", () => {
  it("self-issued token", async () => {
    const ucan = await UCAN.issue({
      issuer: alice,
      audience: alice,
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })

    assertUCAN(ucan, {
      version: UCAN.VERSION,
      issuer: DID.parse(alice.did()),
      audience: DID.parse(alice.did()),
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

    assert.ok(ucan.expiration > UCAN.now())
  })

  it("dervie token", async () => {
    const root = await UCAN.issue({
      issuer: alice,
      audience: bob,
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })
    const proof = await UCAN.link(root)
    assert.equal(proof.code, CBOR.code)

    const leaf = await UCAN.issue({
      issuer: bob,
      audience: mallory,
      capabilities: root.capabilities,
      expiration: root.expiration,
      proofs: [proof],
    })

    assertUCAN(leaf, {
      version: UCAN.VERSION,
      issuer: DID.parse(bob.did()),
      audience: DID.parse(mallory.did()),
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
      audience: bot,
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
      audience: bob,
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
      proofs: [proof],
    })

    assertUCAN(leaf, {
      version: UCAN.VERSION,
      issuer: DID.parse(bot.did()),
      audience: DID.parse(bob.did()),
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
      audience: bob,
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
      version: UCAN.VERSION,
      issuer: DID.parse(alice.did()),
      audience: DID.parse(bob.did()),
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
      audience: bob,
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
      version: UCAN.VERSION,
      issuer: DID.parse(alice.did()),
      audience: DID.parse(bob.did()),
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
    const now = UCAN.now()
    const root = await UCAN.issue({
      issuer: alice,
      audience: bob,
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
      version: UCAN.VERSION,
      issuer: DID.parse(alice.did()),
      audience: DID.parse(bob.did()),
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
      audience: alice,
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
      await UCAN.issue({
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
      assert.match(
        String(error),
        /The audience.did\(\) must be a function that returns DID/
      )
    }
  })

  it("throws on bad did", async () => {
    try {
      await UCAN.issue({
        issuer: alice,
        audience: { did: () => "did:dns:ucan.storage" },
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
      assert.match(
        String(error),
        /Invalid DID "did:dns:ucan\.storage", must start with 'did:key:'/
      )
    }
  })

  it("throws on unsupported algorithms", async () => {
    try {
      await UCAN.issue({
        issuer: alice,
        audience: {
          did: () =>
            "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
        },
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
      assert.match(
        String(error),
        /Unsupported key algorithm with multicode 0x1200/
      )
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

    "with can't be did": [
      // @ts-expect-error
      { with: alice, can: "send/message" },
      /Capability has invalid 'with: {.*}', value must be a string/,
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
          audience: bob,
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

  it("proofs must be CIDs", () => {
    assert.throws(() => {
      UCAN.encode({
        version: "0.8.1",
        issuer: DID.parse(alice.did()),
        audience: DID.parse(bob.did()),
        expiration: Date.now(),
        capabilities: [
          {
            with: "my:*",
            can: "*",
          },
        ],
        signature: new Uint8Array(),
        proofs: [
          // @ts-expect-error
          "bafkreihgufl2d3wwp4kjo75na265sywwi3yqcx2xpk3rif4tlo62nscg4m",
        ],
        facts: [],
      })
    }, /Expected proofs\[0\] to be CID, instead got "bafkr/)
  })

  it("proofs must be CIDs", () => {
    assert.throws(() => {
      UCAN.encode({
        version: "0.8.1",
        issuer: DID.parse(alice.did()),
        // @ts-expect-error
        audience: bob.did(),
        expiration: Date.now(),
        capabilities: [
          {
            with: "my:*",
            can: "*",
          },
        ],
        signature: new Uint8Array(),
        facts: [],
      })
    }, /Expected audience to be Uint8Array, instead got "did:key/)
  })

  it("expiration must be int", async () => {
    try {
      await UCAN.issue({
        expiration: 8.7,
        issuer: alice,
        audience: bob,
        capabilities: [
          {
            with: alice.did(),
            can: "store/add",
          },
        ],
      })
    } catch (error) {
      assert.match(
        String(error),
        /Expected integer but instead got 'expiration: 8.7'/
      )
    }
  })

  it("signature must be Uint8Array", () => {
    assert.throws(() => {
      UCAN.encode({
        version: "0.8.1",
        issuer: DID.parse(alice.did()),
        audience: DID.parse(bob.did()),
        expiration: Date.now(),
        capabilities: [
          {
            with: "my:*",
            can: "*",
          },
        ],
        // @ts-expect-error
        signature: "hello world",
        facts: [],
        proofs: [],
      })
    }, /signature must be Uint8Array, instead got "hello world"/)
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

    const v2 = await UCAN.issue({
      issuer: alice,
      audience: alice,
      expiration: ucan.expiration,
      capabilities: [...ucan.capabilities],
    })

    assert.equal(ucan instanceof Uint8Array, false)
    assertUCAN(ucan, {
      version: UCAN.VERSION,
      issuer: DID.parse(alice.did()),
      audience: DID.parse(alice.did()),
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
      signature: v2.signature,
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

    assert.throws(() => UCAN.parse(jwt), /Invalid version 'ucv: "9.0"'/)
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

    assert.throws(() => UCAN.parse(jwt), /fct\[0\] must be of type object/)
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

    assert.throws(
      () => UCAN.parse(jwt),
      /DID has invalid representation 'aud: "bob"'/
    )
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
      /prf\[0\] has invalid value 1, must be a string/
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

describe("encode <-> decode", () => {
  it("issued ucan is equal to decoded ucan", async () => {
    const expected = await UCAN.issue({
      issuer: alice,
      audience: bob,
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })

    const actual = UCAN.decode(UCAN.encode(expected))
    assert.deepEqual(expected, actual)
  })

  it("can leave out optionals", async () => {
    const v1 = await UCAN.issue({
      issuer: alice,
      audience: bob,
      capabilities: [
        {
          with: "my:*",
          can: "*",
        },
      ],
    })

    // @ts-expect-error - leaving out proofs and facts
    const v2 = UCAN.encode({
      version: v1.version,
      issuer: v1.issuer,
      audience: v1.audience,
      expiration: v1.expiration,
      capabilities: [...v1.capabilities],
      signature: v1.signature,
    })

    assert.deepEqual(v2, UCAN.encode(v1))
  })
})

describe("ts-ucan compat", () => {
  it("round-trips with token.build", async () => {
    const jwt = await buildJWT({ issuer: alice, audience: bob })
    const ucan = UCAN.parse(jwt)

    assertUCAN(ucan, {
      version: UCAN.VERSION,
      issuer: DID.parse(alice.did()),
      audience: DID.parse(bob.did()),
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
      version: UCAN.VERSION,
      issuer: DID.parse(bob.did()),
      audience: DID.parse(mallory.did()),
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

describe("api compatibility", () => {
  it("multiformats compatibility", async () => {
    const Block = await import("multiformats/block")
    const ucan = await UCAN.issue({
      issuer: alice,
      audience: DID.parse(bob.did()),
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })

    const block = await Block.encode({
      value: ucan,
      codec: UCAN,
      hasher: sha256,
    })

    const { cid, bytes } = await UCAN.write(ucan)
    assert.deepEqual(block.cid, cid)
    assert.deepEqual(block.bytes, bytes)
    assert.deepEqual(block.value, ucan)
  })
})

describe("jwt representation", () => {
  it("can parse non cbor UCANs", async () => {
    const jwt = UCAN.parse(JWT_UCAN)
    assert.ok(jwt instanceof Uint8Array)

    assertUCAN(jwt, {
      issuer: DID.parse(alice.did()),
      audience: DID.parse(bob.did()),
      expiration: 1650500849,
      nonce: undefined,
      notBefore: undefined,
      facts: [],
      proofs: [],
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
      signature: JWT_UCAN_SIG,
    })
  })

  it("can encode non cbor UCANs", () => {
    const jwt = UCAN.parse(JWT_UCAN)
    assert.ok(jwt instanceof Uint8Array)

    const bytes = UCAN.encode(jwt)
    const jwt2 = assert.equal(JWT_UCAN, UCAN.format(UCAN.decode(bytes)))
  })

  it("can still decode into jwt representation", async () => {
    const ucan = await UCAN.issue({
      issuer: alice,
      audience: bob,
      capabilities: [
        {
          can: "access/identify",
          with: "did:key:*",
          as: "mailto:*",
        },
      ],
    })

    const token = UCAN.format(ucan)
    const cbor = UCAN.parse(token)
    const jwt = RAW.decode(UTF8.encode(token))

    assert.equal(cbor instanceof Uint8Array, false)
    assertUCAN(cbor, {
      issuer: DID.from(alice.did()),
      audience: DID.from(bob.did()),
      capabilities: [
        {
          can: "access/identify",
          with: "did:key:*",
          as: "mailto:*",
        },
      ],
      expiration: ucan.expiration,
      signature: ucan.signature,
    })

    assert.equal(jwt instanceof Uint8Array, true)
    assertUCAN(jwt, {
      issuer: DID.parse(alice.did()),
      audience: DID.parse(bob.did()),
      capabilities: [
        {
          can: "access/identify",
          with: "did:key:*",
          as: "mailto:*",
        },
      ],
      expiration: ucan.expiration,
      signature: ucan.signature,
    })
  })
})

describe("did", () => {
  it("parse", () => {
    const did = DID.parse(alice.did())
    assert.equal(did.did(), alice.did())
  })

  it("decode", () => {
    const bytes = new Uint8Array(DID.parse(alice.did()))
    assert.equal(DID.decode(bytes).did(), alice.did())
  })

  it("from string", () => {
    const did = DID.from(alice.did())
    assert.equal(did.did(), alice.did())
  })

  it("from bytes", () => {
    const bytes = new Uint8Array(DID.parse(alice.did()))
    const did = DID.from(bytes)
    assert.equal(did.did(), alice.did())
  })

  it("from did", () => {
    const did = DID.parse(alice.did())
    assert.equal(DID.from(did), did)
  })
})

describe("verify", () => {
  it("expired", async () => {
    const ucan = await UCAN.issue({
      issuer: alice,
      audience: alice,
      expiration: UCAN.now() - 10, // expires 10 seconds ago
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })

    assert.equal(UCAN.isExpired(ucan), true)
    assert.equal(UCAN.isTooEarly(ucan), false)
  })

  it("too early", async () => {
    const ucan = await UCAN.issue({
      issuer: alice,
      audience: alice,
      notBefore: UCAN.now() + 10, // valid in 10 seconds
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })

    assert.equal(UCAN.isExpired(ucan), false)
    assert.equal(UCAN.isTooEarly(ucan), true)
  })

  it("invalid time range", async () => {
    const ucan = await UCAN.issue({
      issuer: alice,
      audience: alice,
      expiration: UCAN.now() - 10,
      notBefore: UCAN.now() + 10,
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })

    assert.equal(UCAN.isExpired(ucan), true)
    assert.equal(UCAN.isTooEarly(ucan), true)
  })

  it("verify signatures", async () => {
    const ucan = await UCAN.issue({
      issuer: alice,
      audience: alice,
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })

    assert.equal(await UCAN.verifySignature(ucan, Verifier(ucan.issuer)), true)
  })

  it("invalid signature", async () => {
    const ucan = await UCAN.issue({
      issuer: alice,
      audience: alice,
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })

    const fake = await UCAN.issue({
      issuer: alice,
      audience: alice,
      capabilities: [
        {
          with: alice.did(),
          can: "store/fake",
        },
      ],
    })

    Object.defineProperties(ucan, {
      signature: { value: fake.signature },
    })

    assert.equal(await UCAN.verifySignature(ucan, Verifier(ucan.issuer)), false)
  })

  it("invalid signer", async () => {
    const ucan = await UCAN.issue({
      issuer: alice,
      audience: alice,
      capabilities: [
        {
          with: alice.did(),
          can: "store/put",
        },
      ],
    })

    assert.equal(
      await UCAN.verifySignature(ucan, Verifier(DID.parse(bob.did()))),
      false
    )
  })
})
