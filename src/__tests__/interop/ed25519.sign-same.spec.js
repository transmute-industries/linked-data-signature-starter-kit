const jsigs = require("jsonld-signatures");
const base64url = require("base64url");
const { Ed25519KeyPair } = require("crypto-ld");
const { Ed25519Signature2018 } = jsigs.suites;
const { AuthenticationProofPurpose } = jsigs.purposes;

const { authenticateMeActionDoc, documentLoader } = require("../__fixtures__");

var BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
var bs58 = require("base-x")(BASE58);

const {
  MyLinkedDataKeyClass2019,
  MyLinkedDataSignature2019
} = require("../../index");

describe("ed25519.sign-same", () => {
  it("signatures match", async () => {
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

    const publicKeyBuffer = base64url.toBuffer(myldKey.publicKey.x);
    const publicKeyBase58 = bs58.encode(publicKeyBuffer);

    const privateKeyBase58 = bs58.encode(
      Buffer.concat([
        base64url.toBuffer(myldKey.privateKey.d),
        base64url.toBuffer(myldKey.privateKey.x)
      ])
    );

    const signed = await jsigs.sign(
      { ...authenticateMeActionDoc },
      {
        documentLoader,
        suite: new Ed25519Signature2018({
          verificationMethod: myldKey.id,
          key: new Ed25519KeyPair({
            id: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
            controller: "did:example:123",
            type: "Ed25519VerificationKey2018",
            publicKeyBase58,
            privateKeyBase58
          }),
          date: "2019-11-24T04:34:48Z"
        }),
        purpose: new AuthenticationProofPurpose({
          challenge: "abc",
          domain: "example.com"
        }),
        compactProof: false
      }
    );

    const signed2 = await jsigs.sign(
      { ...authenticateMeActionDoc },
      {
        documentLoader,
        suite: new MyLinkedDataSignature2019({
          date: "2019-11-24T04:34:48Z",
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
      }
    );

    expect(signed.proof.jws).toBe(signed2.proof.jws);
  });
});
