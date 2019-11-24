const jsigs = require("jsonld-signatures");
const { Ed25519KeyPair } = require("crypto-ld");
const { Ed25519Signature2018 } = jsigs.suites;
const { AuthenticationProofPurpose } = jsigs.purposes;

const {
  didKeyDoc,
  didKeyDoc2,
  didKeypair,
  authenticateMeActionDoc,
  documentLoader
} = require("../__fixtures__");

const {
  MyLinkedDataKeyClass2019,
  MyLinkedDataSignature2019
} = require("../../index");

describe.skip("ed25519.interop", () => {
  it("jsig sign / custom verify", async () => {
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

    // console.log(signed);

    const myldKey = new MyLinkedDataKeyClass2019({
      id: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
      controller: "did:example:123",
      type: "Ed25519VerificationKey2018",
      privateKeyJwk: {
        crv: "Ed25519",
        x: "D-5zI9uCYOAk_bN_QWD2XAQ_gIyHUh-6OY7nVk-Rg0g",
        d: "zA65gfNF5g2CLKQnl8uRbGI2IRjJIE7PTZki7Qin9bw",
        kty: "OKP",
        kid: "my-kid"
      },
      publicKeyJwk: {
        crv: "Ed25519",
        x: "D-5zI9uCYOAk_bN_QWD2XAQ_gIyHUh-6OY7nVk-Rg0g",
        kty: "OKP",
        kid: "my-kid"
      }
    });

    // need to do key conversion...

    const res = await jsigs.verify(signed, {
      suite: new MyLinkedDataSignature2019({
        LDKeyClass: MyLinkedDataKeyClass2019,
        linkedDataSigantureType: "Ed25519Signature2018",
        linkedDataSignatureVerificationKeyType: "Ed25519VerificationKey2018",
        alg: "EdDSA",
        key: myldKey
      }),
      purpose: new AuthenticationProofPurpose({
        controller: didKeyDoc2,
        challenge: "abc",
        domain: "example.com"
      }),
      documentLoader: documentLoader,
      compactProof: false
    });

    console.log(res);
  });
});
