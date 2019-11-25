const crypto = require("crypto");
const base64url = require("base64url");
const jose = require("@panva/jose");

const {
  publicKeyPemToPubliKeyJwk,
  privateKeyPemToPrivateKeyJwk
} = require("./utils");

describe("ed25519.node12.crypto", () => {
  it("key conversion from pem works", async () => {
    // const keypair = crypto.generateKeyPairSync("ed25519", {
    //   publicKeyEncoding: { format: "pem", type: "spki" },
    //   privateKeyEncoding: { format: "pem", type: "pkcs8" }
    // });
    const publicKeyPem =
      "-----BEGIN PUBLIC KEY-----\n" +
      "MCowBQYDK2VwAyEAh83ufcOAO9zVigHCgOOTp8waN/ycH4xnPRvn45yu6gw=\n" +
      "-----END PUBLIC KEY-----\n";
    const privateKeyPem =
      "-----BEGIN PRIVATE KEY-----\n" +
      "MC4CAQAwBQYDK2VwBCIEIDKq/xOBEOdQ8c1R4e+BxMuhdCSMpKg568IHiTsYi3k1\n" +
      "-----END PRIVATE KEY-----\n";
    publicKey = crypto.createPublicKey(publicKeyPem, "pem", "spki");
    //   .export({ format: "der", type: "spki" });
    privateKey = crypto.createPrivateKey(privateKeyPem, "pem", "pkcs8");
    // .export({ format: "der", type: "pkcs8" })

    // console.log(privateKeyPemToPrivateKeyJwk({ publicKeyPem, privateKeyPem }));
    const header = {
      alg: "EdDSA",
      b64: true,
      crit: ["b64"]
    };
    const payload = {
      hello: 1
    };
    let encodedHeader = base64url.encode(JSON.stringify(header));
    let encodedPayload = base64url.encode(JSON.stringify(payload));
    const data = Buffer.from(encodedHeader + "." + encodedPayload);
    const sig = crypto.sign(null, data, privateKey);
    const encodedSig = base64url.encode(sig);
    const jws = `${encodedHeader}.${encodedPayload}.${encodedSig}`;
    expect(jws).toBe(
      "eyJhbGciOiJFZERTQSIsImI2NCI6dHJ1ZSwiY3JpdCI6WyJiNjQiXX0.eyJoZWxsbyI6MX0.d1SRP9BpMrflp4jx-T8JZnFpat47VDp3hU6EIt6tBrWwKBZpGkhETYaB3d1OZZFVJZy6KszwMi6DKDmzb3puDQ"
    );

    const result = jose.JWS.verify(
      jws,
      jose.JWK.asKey(publicKeyPemToPubliKeyJwk(publicKeyPem)),
      {
        crit: ["b64"]
      }
    );
    expect(result.hello).toBe(1);
  });
});
