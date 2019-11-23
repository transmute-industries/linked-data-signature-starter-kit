const crypto = require("crypto");
const jose = require("@panva/jose");
const linkedDataVerificationKeyType = "MyLinkedDataVerificationKey2019";

class LDKeyClassJose {
  /**
   * @param {KeyPairOptions} options - The options to use.
   * @param {string} options.id - The key ID.
   * @param {string} options.controller - The key controller.
   * @param {string} options.publicKeyJwk - The Base58 encoded Public Key.
   * @param {string} options.privateKeyJwk - The Base58 Private Key.
   */
  constructor(options = {}) {
    this.id = options.id;
    this.controller = options.controller;
    this.privateKeyJwk = options.privateKeyJwk;
    this.publicKeyJwk = options.publicKeyJwk;
  }

  /**
   * Returns the Base58 encoded public key.
   *
   * @returns {string} The Base58 encoded public key.
   */
  get publicKey() {
    return this.publicKeyJwk;
  }

  /**
   * Returns the Base58 encoded private key.
   *
   * @returns {string} The Base58 encoded private key.
   */
  get privateKey() {
    return this.privateKeyJwk;
  }

  /**
   * Generates a KeyPair with an optional deterministic seed.
   * @param {KeyPairOptions} [options={}] - The options to use.
   *
   * @returns {Promise<LDKeyClassJose>} Generates a key pair.
   */
  static async generate(kty, crv, options = {}) {
    let key = jose.JWK.generateSync(kty, crv);
    return new LDKeyClassJose({
      privateKeyJwk: key.toJWK(true),
      publicKeyJwk: key.toJWK(),
      ...options
    });
  }

  /**
   * Returns a signer object for use with jsonld-signatures.
   *
   * @returns {{sign: Function}} A signer for the json-ld block.
   */
  signer() {
    return joseSignerFactory(this);
  }

  /**
   * Returns a verifier object for use with jsonld-signatures.
   *
   * @returns {{verify: Function}} Used to verify jsonld-signatures.
   */
  verifier() {
    return joseVerifierFactory(this);
  }

  /**
   * Adds a public key base to a public key node.
   *
   * @param {Object} publicKeyNode - The public key node in a jsonld-signature.
   * @param {string} publicKeyNode.publicKeyJwk - Base58 Public Key for
   *   jsonld-signatures.
   *
   * @returns {Object} A PublicKeyNode in a block.
   */
  addEncodedPublicKey(publicKeyNode) {
    publicKeyNode.publicKeyJwk = this.publicKeyJwk;
    return publicKeyNode;
  }

  /**
   * Generates and returns a public key fingerprint.
   *
   * @param {string} publicKeyJwk - The base58 encoded public key material.
   *
   * @returns {string} The fingerprint.
   */
  static fingerprintFromPublicKey(/*{publicKeyJwk}*/) {
    // TODO: implement
    throw new Error("`fingerprintFromPublicKey` API is not implemented.");
  }

  /**
   * Generates and returns a public key fingerprint.
   *
   * @returns {string} The fingerprint.
   */
  fingerprint() {
    // TODO: implement
    throw new Error("`fingerprint` API is not implemented.");
  }

  /**
   * Tests whether the fingerprint was generated from a given key pair.
   *
   * @param {string} fingerprint - A Base58 public key.
   *
   * @returns {Object} An object indicating valid is true or false.
   */
  verifyFingerprint(/*fingerprint*/) {
    // TODO: implement
    throw new Error("`verifyFingerprint` API is not implemented.");
  }

  static async from(options) {
    return new LDKeyClassJose(options);
  }

  /**
   * Contains the public key for the KeyPair
   * and other information that json-ld Signatures can use to form a proof.
   * @param {Object} [options={}] - Needs either a controller or owner.
   * @param {string} [options.controller=this.controller]  - DID of the
   * person/entity controlling this key pair.
   *
   * @returns {Object} A public node with
   * information used in verification methods by signatures.
   */
  publicNode({ controller = this.controller } = {}) {
    const publicNode = {
      id: this.id,
      type: this.type
    };
    if (controller) {
      publicNode.controller = controller;
    }
    this.addEncodedPublicKey(publicNode); // Subclass-specific
    return publicNode;
  }
}

/**
 * @ignore
 * Returns an object with an async sign function.
 * The sign function is bound to the KeyPair
 * and then returned by the KeyPair's signer method.
 * @param {LDKeyClassJose} key - An LDKeyClassJose.
 *
 * @returns {{sign: Function}} An object with an async function sign
 * using the private key passed in.
 */
function joseSignerFactory(key) {
  if (!key.privateKeyJwk) {
    return {
      async sign() {
        throw new Error("No private key to sign with.");
      }
    };
  }

  return {
    async sign({ data }) {
      const attachedJws = jose.JWS.sign(
        Buffer.from(data),
        jose.JWK.asKey(key.privateKeyJwk),
        {
          kid: key.privateKeyJwk.kid,
          b64: false,
          crit: ["b64"]
        }
      );
      const [header, payload, signature] = attachedJws.split(".");
      return header + ".." + signature;
    }
  };
}

/**
 * @ignore
 * Returns an object with an async verify function.
 * The verify function is bound to the KeyPair
 * and then returned by the KeyPair's verifier method.
 * @param {LDKeyClassJose} key - An LDKeyClassJose.
 *
 * @returns {{verify: Function}} An async verifier specific
 * to the key passed in.
 */
function joseVerifierFactory(key) {
  return {
    async verify({ data, signature }) {
      let verified = false;
      const [encodedheader, encodedsignature] = signature.split("..");
      const jws =
        encodedheader + "." + data.toString("utf8") + "." + encodedsignature;
      try {
        jose.JWS.verify(jws, jose.JWK.asKey(key.publicKeyJwk), {
          crit: ["b64"]
        });
        verified = true;
      } catch (e) {
        console.error("An error occurred when verifying signature: ", e);
      }
      return verified;
    }
  };
}

module.exports = LDKeyClassJose;
