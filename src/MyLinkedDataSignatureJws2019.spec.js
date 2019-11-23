const MyLinkedDataSignatureJws2019 = require("./MyLinkedDataSignatureJws2019");

const LDKeyClassJose = require("./LDKeyClassJose");

const customDocumentLoader = require("./customDocumentLoader");

const jsigs = require("jsonld-signatures");
const { AssertionProofPurpose } = jsigs.purposes;

const privateKeyJwk = {
  crv: "secp256k1",
  d: "rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw",
  kid: "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
  kty: "EC",
  x: "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
  y: "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA"
};

const publicKeyJwk = {
  crv: "secp256k1",
  kid: "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
  kty: "EC",
  x: "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
  y: "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA"
};

const doc = {
  "@context": [
    "https://example.com/my-context/v2",
    {
      schema: "http://schema.org/",
      name: "schema:name",
      homepage: "schema:url",
      image: "schema:image"
    }
  ],
  name: "Manu Sporny",
  homepage: "https://manu.sporny.org/",
  image: "https://manu.sporny.org/images/manu.png"
};

describe("MyLinkedDataSignatureJws2019", () => {
  it("constructor works", async () => {
    const s = new MyLinkedDataSignatureJws2019();
    expect(s.type).toBe("MyLinkedDataSignatureJws2019");
    expect(s.requiredKeyType).toBe("MyJwsVerificationKey2019");
  });

  it("MyLinkedDataSignatureJws2019", async () => {
    const key = new LDKeyClassJose({
      publicKeyJwk,
      privateKeyJwk,
      id: "did:example:123#" + publicKeyJwk.kid,
      controller: "did:example:123"
    });

    const controller = {
      "@context": jsigs.SECURITY_CONTEXT_URL,
      type: "MyJwsVerificationKey2019",
      id: "did:example:123#" + publicKeyJwk.kid,
      controller: "did:example:123",
      publicKeyJwk
    };

    const signed = await jsigs.sign(doc, {
      suite: new MyLinkedDataSignatureJws2019({
        key,
        verificationMethod: "did:example:123#" + publicKeyJwk.kid
        // proof: "MyLinkedDataSignatureJws2019"
      }),
      purpose: new AssertionProofPurpose(),
      documentLoader: customDocumentLoader,
      compactProof: false
    });

    // console.log(signed);

    const res = await jsigs.verify(signed, {
      suite: new MyLinkedDataSignatureJws2019({
        key,
        verificationMethod: "did:example:123#" + publicKeyJwk.kid,
        proof: "MyLinkedDataSignatureJws2019"
      }),
      purpose: new AssertionProofPurpose(),
      documentLoader: customDocumentLoader,
      compactProof: false
    });

    // console.log(res);

    const { verified, error } = res;

    console.log(error);

    expect(verified).toBe(true);
  });
});
