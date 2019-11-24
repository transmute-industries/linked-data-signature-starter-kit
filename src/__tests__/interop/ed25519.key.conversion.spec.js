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

const { didKeypair } = require("../__fixtures__");

describe("ed25519.key.conversion", () => {
  it("base58 to pem to jwk to did:key", async () => {
    const privateKeyDerEncode = ({ privateKeyBytes, seedBytes }) => {
      if (!(privateKeyBytes || seedBytes)) {
        throw new TypeError("`privateKeyBytes` or `seedBytes` is required.");
      }
      if (
        !privateKeyBytes &&
        !(Buffer.isBuffer(seedBytes) && seedBytes.length === 32)
      ) {
        throw new TypeError("`seedBytes` must be a 32 byte Buffer.");
      }
      if (
        !seedBytes &&
        !(Buffer.isBuffer(privateKeyBytes) && privateKeyBytes.length === 64)
      ) {
        throw new TypeError("`privateKeyBytes` must be a 64 byte Buffer.");
      }
      let p;
      if (seedBytes) {
        p = seedBytes;
      } else {
        // extract the first 32 bytes of the 64 byte private key representation
        p = Buffer.from(privateKeyBytes.buffer, privateKeyBytes.byteOffset, 32);
      }
      const keyBuffer = new ByteBuffer(p);

      const asn1Key = asn1.create(
        asn1.UNIVERSAL,
        asn1.Type.OCTETSTRING,
        false,
        keyBuffer.getBytes()
      );

      const a = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(
          asn1.Class.UNIVERSAL,
          asn1.Type.INTEGER,
          false,
          asn1.integerToDer(0).getBytes()
        ),
        // privateKeyAlgorithm
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          asn1.create(
            asn1.Class.UNIVERSAL,
            asn1.Type.OID,
            false,
            asn1.oidToDer(oids.EdDSA25519).getBytes()
          )
        ]),
        // private key
        asn1.create(
          asn1.Class.UNIVERSAL,
          asn1.Type.OCTETSTRING,
          false,
          asn1.toDer(asn1Key).getBytes()
        )
      ]);

      const privateKeyDer = asn1.toDer(a);
      return Buffer.from(privateKeyDer.getBytes(), "binary");
    };

    const publicKeyDerEncode = ({ publicKeyBytes }) => {
      if (!(Buffer.isBuffer(publicKeyBytes) && publicKeyBytes.length === 32)) {
        throw new TypeError("`publicKeyBytes` must be a 32 byte Buffer.");
      }
      // add a zero byte to the front of the publicKeyBytes, this results in
      // the bitstring being 256 bits vs. 170 bits (without padding)
      const zeroBuffer = Buffer.from(new Uint8Array([0]));
      const keyBuffer = new ByteBuffer(
        Buffer.concat([zeroBuffer, publicKeyBytes])
      );

      const a = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          asn1.create(
            asn1.Class.UNIVERSAL,
            asn1.Type.OID,
            false,
            asn1.oidToDer(oids.EdDSA25519).getBytes()
          )
        ]),
        // public key
        asn1.create(
          asn1.Class.UNIVERSAL,
          asn1.Type.BITSTRING,
          false,
          keyBuffer.getBytes()
        )
      ]);

      const publicKeyDer = asn1.toDer(a);
      return Buffer.from(publicKeyDer.getBytes(), "binary");
    };

    const publicKey = crypto.createPublicKey({
      key: publicKeyDerEncode({
        publicKeyBytes: bs58.decode(didKeypair.publicKeyBase58)
      }),
      format: "der",
      type: "spki"
    });

    const privateKey = crypto.createPrivateKey({
      key: privateKeyDerEncode({
        privateKeyBytes: bs58.decode(didKeypair.privateKeyBase58)
      }),
      format: "der",
      type: "pkcs8"
    });

    const publicKeyBytes = publicKeyFromAsn1(
      asn1.fromDer(
        new ByteBuffer(publicKey.export({ format: "der", type: "spki" }))
      )
    );
    const { privateKeyBytes } = privateKeyFromAsn1(
      asn1.fromDer(
        new ByteBuffer(privateKey.export({ format: "der", type: "pkcs8" }))
      )
    );

    const privateKeyJwk = {
      crv: "Ed25519",
      x: base64url.encode(publicKeyBytes),
      d: base64url.encode(privateKeyBytes),
      kty: "OKP",
      kid: "my-kid"
    };

    // console.log(privateKeyJwk);

    const publicKeyBuffer = base64url.toBuffer(privateKeyJwk.x);
    const publicKeyBase58 = bs58.encode(publicKeyBuffer);
    expect(publicKeyBase58).toBe(
      "25C16YaTbD96wAvdokKnTmD8ruWvYARDkc6nfNEA3L71"
    );

    const privateKeyBase58 = bs58.encode(
      Buffer.concat([
        base64url.toBuffer(privateKeyJwk.d),
        base64url.toBuffer(privateKeyJwk.x)
      ])
    );
    expect(privateKeyBase58).toBe(
      "55dKnusKVZjGK9rtTQgT3usTnALuChkzQpoksz4jES5G7AKMCpQCBt3azfko5oTMQD11gPxQ1bFRAYWSwcYSPdPV"
    );
    const edKey = new Ed25519KeyPair({
      publicKeyBase58,
      privateKeyBase58
    });
    const didDoc = keyToDidDoc(edKey);
    expect(didDoc.id).toBe(
      "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP"
    );
  });

  it("PEM to did:key", async () => {
    // const keypair = crypto.generateKeyPairSync("ed25519", {
    //   publicKeyEncoding: { format: "pem", type: "spki" },
    //   privateKeyEncoding: { format: "pem", type: "pkcs8" }
    // });
    const { publicKey, privateKey } = {
      publicKey:
        "-----BEGIN PUBLIC KEY-----\n" +
        "MCowBQYDK2VwAyEAh83ufcOAO9zVigHCgOOTp8waN/ycH4xnPRvn45yu6gw=\n" +
        "-----END PUBLIC KEY-----\n",
      privateKey:
        "-----BEGIN PRIVATE KEY-----\n" +
        "MC4CAQAwBQYDK2VwBCIEIDKq/xOBEOdQ8c1R4e+BxMuhdCSMpKg568IHiTsYi3k1\n" +
        "-----END PRIVATE KEY-----\n"
    };
    const publicKeyBytes = publicKeyFromAsn1(
      asn1.fromDer(
        new ByteBuffer(
          crypto
            .createPublicKey(publicKey, "pem", "spki")
            .export({ format: "der", type: "spki" })
        )
      )
    );
    const { privateKeyBytes } = privateKeyFromAsn1(
      asn1.fromDer(
        new ByteBuffer(
          crypto
            .createPrivateKey(privateKey, "pem", "pkcs8")
            .export({ format: "der", type: "pkcs8" })
        )
      )
    );

    const privateKeyJwk = {
      crv: "Ed25519",
      x: base64url.encode(publicKeyBytes),
      d: base64url.encode(privateKeyBytes),
      kty: "OKP",
      kid: "my-kid"
    };

    const publicKeyBuffer = base64url.toBuffer(privateKeyJwk.x);
    const publicKeyBase58 = bs58.encode(publicKeyBuffer);
    expect(publicKeyBase58).toBe(
      "A98AdwjnAHkF2zk61mPYVx216LW58Lc6HiM8e4b4Cbpw"
    );

    const privateKeyBase58 = bs58.encode(
      Buffer.concat([
        base64url.toBuffer(privateKeyJwk.d),
        base64url.toBuffer(privateKeyJwk.x)
      ])
    );
    expect(privateKeyBase58).toBe(
      "21knKoyCy3QqjGwkZS5RbqM5QuL3nanry2Pm367M5oMsMTTX6NeNAup2S4cKYYN27h9PHa3Aqdcaihw6jYzy8H4f"
    );
    const edKey = new Ed25519KeyPair({
      publicKeyBase58,
      privateKeyBase58
    });
    const didDoc = keyToDidDoc(edKey);
    expect(didDoc.id).toBe(
      "did:key:z6MkobPDEBzDVqEi9VanhLMPM3ZzuumvYDrSyjG4ULZ57pcK"
    );
  });

  it("JOSE to did:key", async () => {
    // const key = jose.JWK.generateSync("OKP", "Ed25519").toJWK(true);
    const privateKeyJwk = {
      crv: "Ed25519",
      x: "VQ99N9eEYrkt9d7Iw-sq9tAbB7H_vX82iCNU4uBDYwA",
      d: "Sexnoz1MarNT4lu88ufi_T4G57d4bekfg8m18uYHQ4g",
      kty: "OKP",
      kid: "YDTVGm77-bIReuTAVmFnAdkpMWpuvM74wG6vAhfBYmU"
    };
    const publicKeyBuffer = base64url.toBuffer(privateKeyJwk.x);
    const publicKeyBase58 = bs58.encode(publicKeyBuffer);
    expect(publicKeyBase58).toBe(
      "6j3MURCDR8WoHgJ81U8mLME9H5uEcEx4yU74QrAgHbDq"
    );

    const privateKeyBase58 = bs58.encode(
      Buffer.concat([
        base64url.toBuffer(privateKeyJwk.d),
        base64url.toBuffer(privateKeyJwk.x)
      ])
    );
    expect(privateKeyBase58).toBe(
      "2Uit2seAJ6Wn3Unynn6t8DpfREDpiMZrnakw2miWMVDQQY6iRA1LuG7c6HDdyLwUREKBy42rR4MUsb5KcJf33qwM"
    );
    const edKey = new Ed25519KeyPair({
      publicKeyBase58,
      privateKeyBase58
    });
    const didDoc = keyToDidDoc(edKey);
    expect(didDoc.id).toBe(
      "did:key:z6MkkBJQ4fSekg1GQB8ph36cBSn96fB628CRfV1zF88hCp1D"
    );
  });
});
