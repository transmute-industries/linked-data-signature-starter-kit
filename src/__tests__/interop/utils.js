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
  const keyBuffer = new ByteBuffer(Buffer.concat([zeroBuffer, publicKeyBytes]));

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

const publicKeyPemToPubliKeyJwk = publicKeyPem => {
  const publicKeyBytes = publicKeyFromAsn1(
    asn1.fromDer(
      new ByteBuffer(
        crypto
          .createPublicKey(publicKeyPem, "pem", "spki")
          .export({ format: "der", type: "spki" })
      )
    )
  );

  return jose.JWK.asKey({
    crv: "Ed25519",
    x: base64url.encode(publicKeyBytes),
    kty: "OKP"
  }).toJWK(false);
};

const privateKeyPemToPrivateKeyJwk = ({ privateKeyPem, publicKeyPem }) => {
  const privateKey = crypto.createPrivateKey(privateKeyPem, "pem", "pkcs8");

  const { privateKeyBytes } = privateKeyFromAsn1(
    asn1.fromDer(
      new ByteBuffer(privateKey.export({ format: "der", type: "pkcs8" }))
    )
  );

  const publicKeyBytes = publicKeyFromAsn1(
    asn1.fromDer(
      new ByteBuffer(
        crypto
          .createPublicKey(publicKeyPem, "pem", "spki")
          .export({ format: "der", type: "spki" })
      )
    )
  );

  return jose.JWK.asKey({
    crv: "Ed25519",
    x: base64url.encode(publicKeyBytes),
    d: base64url.encode(privateKeyBytes),
    kty: "OKP"
  }).toJWK(true);
};

const publicKeyBase58ToPublicKeyJwk = publicKeyBase58 => {
  const publicKeyBuf = bs58.decode(publicKeyBase58);
  return jose.JWK.asKey({
    crv: "Ed25519",
    x: base64url.encode(publicKeyBuf),
    kty: "OKP"
  }).toJWK(false);
};

const privateKeyBase58ToPrivateKeyJwk = privateKeyBase58 => {
  const privateKeyBuf = bs58.decode(privateKeyBase58);
  return jose.JWK.asKey({
    crv: "Ed25519",
    x: base64url.encode(privateKeyBuf.slice(32, 64)),
    d: base64url.encode(privateKeyBuf.slice(0, 32)),
    kty: "OKP"
  }).toJWK(true);
};

const publicKeyJwkToPublicKeyBase58 = publicKeyJwk => {
  const publicKeyBuffer = base64url.toBuffer(publicKeyJwk.x);
  const publicKeyBase58 = bs58.encode(publicKeyBuffer);
  return publicKeyBase58;
};

const privateKeyJwkToPrivateKeyBase58 = privateKeyJwk => {
  const privateKeyBase58 = bs58.encode(
    Buffer.concat([
      base64url.toBuffer(privateKeyJwk.d),
      base64url.toBuffer(privateKeyJwk.x)
    ])
  );
  return privateKeyBase58;
};

const publicKeyBase58ToPublicKeyPem = publicKeyBase58 => {
  return crypto
    .createPublicKey({
      key: publicKeyDerEncode({
        publicKeyBytes: bs58.decode(publicKeyBase58)
      }),
      format: "der",
      type: "spki"
    })
    .export({ format: "pem", type: "spki" });
};

const privateKeyBase58ToPrivateKeyPem = privateKeyBase58 => {
  const privateKeyBuf = bs58.decode(privateKeyBase58);
  return crypto
    .createPrivateKey({
      key: privateKeyDerEncode({
        privateKeyBytes: privateKeyBuf
      }),
      format: "der",
      type: "pkcs8"
    })
    .export({ format: "pem", type: "pkcs8" });
};

const publicKeyPemToPublicKeyBase58 = publicKeyPem => {
  const publicKeyBytes = publicKeyFromAsn1(
    asn1.fromDer(
      new ByteBuffer(
        crypto
          .createPublicKey(publicKeyPem, "pem", "spki")
          .export({ format: "der", type: "spki" })
      )
    )
  );
  return bs58.encode(publicKeyBytes);
};

const privateKeyPemToPrivateKeyBase58 = ({ privateKeyPem, publicKeyPem }) => {
  const privateKey = crypto.createPrivateKey(privateKeyPem, "pem", "pkcs8");
  const publicKey = crypto.createPublicKey(publicKeyPem, "pem", "spki");

  const { privateKeyBytes } = privateKeyFromAsn1(
    asn1.fromDer(
      new ByteBuffer(privateKey.export({ format: "der", type: "pkcs8" }))
    )
  );

  const publicKeyBytes = publicKeyFromAsn1(
    asn1.fromDer(
      new ByteBuffer(publicKey.export({ format: "der", type: "spki" }))
    )
  );

  return bs58.encode(Buffer.concat([privateKeyBytes, publicKeyBytes]));
};

module.exports = {
  publicKeyDerEncode,
  privateKeyDerEncode,

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
};
