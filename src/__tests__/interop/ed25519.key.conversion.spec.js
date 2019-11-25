const jose = require("@panva/jose");
const crypto = require("crypto");
const base64url = require("base64url");
const forge = require("node-forge");
const { Ed25519KeyPair } = require("crypto-ld");
const { keyToDidDoc } = require("did-method-key").driver();

var BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
var bs58 = require("base-x")(BASE58);

const {
  asn1,
  oids,
  ed25519: { privateKeyFromAsn1, publicKeyFromAsn1 },
  util: { ByteBuffer }
} = forge;

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

const { didKeypair } = require("../__fixtures__");

describe("ed25519.key.conversion", () => {
  it("base58 to jwk", async () => {
    const publicKeyJwk = publicKeyBase58ToPublicKeyJwk(
      didKeypair.publicKeyBase58
    );
    const privateKeyJwk = privateKeyBase58ToPrivateKeyJwk(
      didKeypair.privateKeyBase58
    );
    expect(publicKeyJwk).toEqual({
      crv: "Ed25519",
      x: "D-5zI9uCYOAk_bN_QWD2XAQ_gIyHUh-6OY7nVk-Rg0g",
      kty: "OKP",
      kid: "7lMt97NZhIN9UFr-5xRoJYFhW_Gujx_j4l4BJlItEY8"
    });

    expect(privateKeyJwk).toEqual({
      crv: "Ed25519",
      x: "D-5zI9uCYOAk_bN_QWD2XAQ_gIyHUh-6OY7nVk-Rg0g",
      d: "zA65gfNF5g2CLKQnl8uRbGI2IRjJIE7PTZki7Qin9bw",
      kty: "OKP",
      kid: "7lMt97NZhIN9UFr-5xRoJYFhW_Gujx_j4l4BJlItEY8"
    });
  });

  it("pem to jwk", async () => {
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

    const publicKeyJwk = publicKeyPemToPubliKeyJwk(publicKeyPem);

    const privateKeyJwk = privateKeyPemToPrivateKeyJwk({
      privateKeyPem,
      publicKeyPem
    });

    expect(publicKeyJwk).toEqual({
      crv: "Ed25519",
      x: "h83ufcOAO9zVigHCgOOTp8waN_ycH4xnPRvn45yu6gw",
      kty: "OKP",
      kid: "8R_gUPjBoJ_nf39_G7VLGWNuhL5etuW7zvS46kwYN6Q"
    });

    expect(privateKeyJwk).toEqual({
      crv: "Ed25519",
      x: "h83ufcOAO9zVigHCgOOTp8waN_ycH4xnPRvn45yu6gw",
      d: "Mqr_E4EQ51DxzVHh74HEy6F0JIykqDnrwgeJOxiLeTU",
      kty: "OKP",
      kid: "8R_gUPjBoJ_nf39_G7VLGWNuhL5etuW7zvS46kwYN6Q"
    });
  });

  it("jwk to base58", async () => {
    // const key = jose.JWK.generateSync("OKP", "Ed25519").toJWK(true);
    const privateKeyJwk = {
      crv: "Ed25519",
      x: "VQ99N9eEYrkt9d7Iw-sq9tAbB7H_vX82iCNU4uBDYwA",
      d: "Sexnoz1MarNT4lu88ufi_T4G57d4bekfg8m18uYHQ4g",
      kty: "OKP",
      kid: "YDTVGm77-bIReuTAVmFnAdkpMWpuvM74wG6vAhfBYmU"
    };

    const publicKeyBase58 = publicKeyJwkToPublicKeyBase58(privateKeyJwk);

    const privateKeyBase58 = privateKeyJwkToPrivateKeyBase58(privateKeyJwk);

    expect(publicKeyBase58).toBe(
      "6j3MURCDR8WoHgJ81U8mLME9H5uEcEx4yU74QrAgHbDq"
    );

    expect(privateKeyBase58).toBe(
      "2Uit2seAJ6Wn3Unynn6t8DpfREDpiMZrnakw2miWMVDQQY6iRA1LuG7c6HDdyLwUREKBy42rR4MUsb5KcJf33qwM"
    );
  });

  it("base58 to pem", async () => {
    const publicKeyPem = publicKeyBase58ToPublicKeyPem(
      didKeypair.publicKeyBase58
    );
    const privateKeyPem = privateKeyBase58ToPrivateKeyPem(
      didKeypair.privateKeyBase58
    );

    expect(publicKeyPem).toBe(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAD+5zI9uCYOAk/bN/QWD2XAQ/gIyHUh+6OY7nVk+Rg0g=
-----END PUBLIC KEY-----
`);

    expect(privateKeyPem).toBe(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMwOuYHzReYNgiykJ5fLkWxiNiEYySBOz02ZIu0Ip/W8
-----END PRIVATE KEY-----
`);
  });

  it("pem to base58", async () => {
    const publicKeyPem =
      "-----BEGIN PUBLIC KEY-----\n" +
      "MCowBQYDK2VwAyEAh83ufcOAO9zVigHCgOOTp8waN/ycH4xnPRvn45yu6gw=\n" +
      "-----END PUBLIC KEY-----\n";
    const privateKeyPem =
      "-----BEGIN PRIVATE KEY-----\n" +
      "MC4CAQAwBQYDK2VwBCIEIDKq/xOBEOdQ8c1R4e+BxMuhdCSMpKg568IHiTsYi3k1\n" +
      "-----END PRIVATE KEY-----\n";

    const publicKeyBase58 = publicKeyPemToPublicKeyBase58(publicKeyPem);
    const privateKeyBase58 = privateKeyPemToPrivateKeyBase58({
      privateKeyPem,
      publicKeyPem
    });
    expect(publicKeyBase58).toBe(
      "A98AdwjnAHkF2zk61mPYVx216LW58Lc6HiM8e4b4Cbpw"
    );
    expect(privateKeyBase58).toBe(
      "21knKoyCy3QqjGwkZS5RbqM5QuL3nanry2Pm367M5oMsMTTX6NeNAup2S4cKYYN27h9PHa3Aqdcaihw6jYzy8H4f"
    );
  });
});
