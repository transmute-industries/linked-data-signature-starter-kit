const jsigs = require("jsonld-signatures");
const { AuthenticationProofPurpose } = jsigs.purposes;

const {
  didKeyDoc2,
  authenticateMeActionDoc,
  documentLoader
} = require("../__fixtures__");

const {
  MyLinkedDataKeyClass2019,
  MyLinkedDataSignature2019
} = require("../../index");

describe("ed25519.custom", () => {
  it("MyLinkedDataSignature2019 sign and verify", async () => {
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

    const signed = await jsigs.sign(authenticateMeActionDoc, {
      documentLoader,
      suite: new MyLinkedDataSignature2019({
        LDKeyClass: MyLinkedDataKeyClass2019,
        linkedDataSigantureType: "Ed25519Signature2018",
        linkedDataSignatureVerificationKeyType: "Ed25519VerificationKey2018",
        alg: "EdDSA",
        key: myldKey
      }),
      purpose: new AuthenticationProofPurpose({
        challenge: "abc",
        domain: "example.com"
      }),
      compactProof: false
    });

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
