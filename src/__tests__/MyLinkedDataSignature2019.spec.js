const {
  MyLinkedDataKeyClass2019,
  MyLinkedDataSignature2019
} = require("../index");

const {
  publicKeyJwk,
  privateKeyJwk,
  documentLoader,
  doc
} = require("./__fixtures__");

const jsigs = require("jsonld-signatures");
const { AssertionProofPurpose } = jsigs.purposes;

describe("MyLinkedDataSignature2019", () => {
  it("constructor works", async () => {
    const s = new MyLinkedDataSignature2019({
      type: "MyLinkedDataSignature2019",
      requiredKeyType: "MyJwsVerificationKey2019"
    });
    expect(s.type).toBe("MyLinkedDataSignature2019");
    expect(s.requiredKeyType).toBe("MyJwsVerificationKey2019");
  });

  it("MyLinkedDataSignature2019", async () => {
    const key = new MyLinkedDataKeyClass2019({
      publicKeyJwk,
      privateKeyJwk,
      id: "did:example:123#" + publicKeyJwk.kid,
      controller: "did:example:123"
    });

    const signed = await jsigs.sign(doc, {
      suite: new MyLinkedDataSignature2019({
        LDKeyClass: MyLinkedDataKeyClass2019,
        type: "MyLinkedDataSignature2019",
        requiredKeyType: "MyJwsVerificationKey2019",
        alg: "ES256K",
        key,
        verificationMethod: "did:example:123#" + publicKeyJwk.kid
      }),
      purpose: new AssertionProofPurpose(),
      documentLoader: documentLoader,
      compactProof: false
    });

    expect(signed.proof).toBeDefined();

    const res = await jsigs.verify(signed, {
      suite: new MyLinkedDataSignature2019({
        LDKeyClass: MyLinkedDataKeyClass2019,
        type: "MyLinkedDataSignature2019",
        requiredKeyType: "MyJwsVerificationKey2019",
        alg: "ES256K",
        key,
        verificationMethod: "did:example:123#" + publicKeyJwk.kid,
        proof: "MyLinkedDataSignature2019"
      }),
      purpose: new AssertionProofPurpose(),
      documentLoader: documentLoader,
      compactProof: false
    });

    const { verified } = res;
    expect(verified).toBe(true);
  });
});
