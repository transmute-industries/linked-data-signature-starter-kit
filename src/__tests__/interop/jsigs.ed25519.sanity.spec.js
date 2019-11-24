const jsigs = require("jsonld-signatures");
const { Ed25519KeyPair } = require("crypto-ld");
const { Ed25519Signature2018 } = jsigs.suites;
const { AuthenticationProofPurpose } = jsigs.purposes;

const {
  didKeyDoc,
  didKeypair,
  authenticateMeActionDoc,
  documentLoader
} = require("../__fixtures__");

describe("ed25519.sanity", () => {
  it("sign verify", async () => {
    const signed = await jsigs.sign(authenticateMeActionDoc, {
      documentLoader,
      suite: new Ed25519Signature2018({
        verificationMethod: didKeyDoc.publicKey[0].id,
        key: new Ed25519KeyPair(didKeypair)
      }),
      purpose: new AuthenticationProofPurpose({
        challenge: "abc",
        domain: "example.com"
      }),
      compactProof: false
    });

    const result = await jsigs.verify(signed, {
      documentLoader,
      suite: new Ed25519Signature2018({
        key: new Ed25519KeyPair(didKeyDoc.publicKey[0])
      }),

      purpose: new AuthenticationProofPurpose({
        controller: didKeyDoc,
        challenge: "abc",
        domain: "example.com"
      })
    });
    expect(result.verified).toBe(true);
  });
});
