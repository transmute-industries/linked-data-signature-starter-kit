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

const {
  publicKeyPemToPubliKeyJwk,
  privateKeyPemToPrivateKeyJwk,

  publicKeyBase58ToPublicKeyJwk,
  privateKeyBase58ToPrivateKeyJwk,

  publicKeyJwkToPublicKeyBase58,
  privateKeyJwkToPrivateKeyBase58,

  publicKeyBase58ToPublicKeyPem,
  privateKeyBase58ToPrivateKeyPem,

  publicKeyPemToPublicKeyBase58,
  privateKeyPemToPrivateKeyBase58
} = require("./utils");

describe("ed25519.sign-same", () => {
  it("signatures match", async () => {
    const publicKeyPem =
      "-----BEGIN PUBLIC KEY-----\n" +
      "MCowBQYDK2VwAyEAh83ufcOAO9zVigHCgOOTp8waN/ycH4xnPRvn45yu6gw=\n" +
      "-----END PUBLIC KEY-----\n";
    const privateKeyPem =
      "-----BEGIN PRIVATE KEY-----\n" +
      "MC4CAQAwBQYDK2VwBCIEIDKq/xOBEOdQ8c1R4e+BxMuhdCSMpKg568IHiTsYi3k1\n" +
      "-----END PRIVATE KEY-----\n";

    const myldKey = new MyLinkedDataKeyClass2019({
      id: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
      controller: "did:example:123",
      type: "Ed25519VerificationKey2018",
      privateKeyJwk: privateKeyPemToPrivateKeyJwk({
        privateKeyPem,
        publicKeyPem
      }),
      publicKeyJwk: publicKeyPemToPubliKeyJwk(publicKeyPem)
    });

    const edKey = new Ed25519KeyPair({
      id: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
      controller: "did:example:123",
      type: "Ed25519VerificationKey2018",
      publicKeyBase58: publicKeyPemToPublicKeyBase58(publicKeyPem),
      privateKeyBase58: privateKeyPemToPrivateKeyBase58({
        publicKeyPem,
        privateKeyPem
      })
    });

    const signed = await jsigs.sign(
      { ...authenticateMeActionDoc },
      {
        documentLoader,
        suite: new Ed25519Signature2018({
          date: "2019-11-24T04:34:48Z",
          verificationMethod: myldKey.id,
          key: edKey
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
    expect(signed2.proof.jws).toBe(signed.proof.jws);
  });
});
